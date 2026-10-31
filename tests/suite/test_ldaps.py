"""ldaps:// connections and server certificate verification (ssl_check_cert).

The ldap container serves the directory over TLS with certificates from
tests/ldap/tls/generate.sh: a valid one on 636 (SAN DNS:ldap and both IP
addresses of the container) and, through TLS proxies, certificates the
module has to reject. Every test starts its own nginx: all ldaps servers
of one nginx share an SSL_CTX today, so one test's CA could leak into
another (kvspb#258).

A rejected server never becomes usable, so the request waits until
request_timeout and is closed without a response (nal-toj.18); a later
fix may answer 5xx instead. Either way it must not be let through.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest
import requests

from conftest import TIMEOUTS, ldap_server, protected_location
from ldapdata import (
    CN_ONLY_PORT,
    DNS_ONLY_PORT,
    LDAP_IPV4,
    LDAP_IPV6,
    TLS13_ONLY_PORT,
    TLS_DIR,
    UNTRUSTED_PORT,
    WRONG_HOST_PORT,
    creds,
    ldaps_url,
)

CA = TLS_DIR / "ca.crt"
OTHER_CA = TLS_DIR / "other-ca.crt"


def tls_server(name: str, url: str, check: str = "on", ca_file=CA) -> str:
    body = f"require valid_user;\nssl_check_cert {check};{TIMEOUTS}"
    if ca_file is not None:
        body += f"ssl_ca_file {ca_file};\n"
    return ldap_server(name, body, url=url)


def start(nginx, url: str, **kwargs):
    return nginx.start(http=tls_server("tls", url, **kwargs), server=protected_location("tls"))


def assert_denied(server) -> None:
    try:
        response = server.get(auth=creds("alice"))
    except requests.ConnectionError:
        return
    assert response.status_code != 200, "a request was let through over an untrusted TLS connection"


@pytest.mark.parametrize(
    "host",
    [
        pytest.param("ldap", id="host-name"),
        pytest.param(LDAP_IPV4, id="ipv4-address"),
        # Aliases that resolve to one address only and match no DNS SAN.
        pytest.param("ldap4", id="ipv4-san-of-host-name"),
        pytest.param("ldap6", id="ipv6-san-of-host-name"),
        pytest.param(
            LDAP_IPV6,
            id="ipv6-address",
            marks=pytest.mark.xfail(
                reason="an IPv6 address in brackets is rejected as an invalid port (nal-5br.15)"
            ),
        ),
    ],
)
def test_valid_certificate_is_accepted(nginx, host):
    server = start(nginx, ldaps_url(host))

    assert server.get(auth=creds("alice")).status_code == 200
    assert server.get(auth=("alice", "wrong")).status_code == 401


def test_host_name_matches_without_ip_sans(nginx):
    server = start(nginx, ldaps_url(port=DNS_ONLY_PORT))

    assert server.get(auth=creds("alice")).status_code == 200


def test_ip_address_does_not_match_a_dns_san(nginx):
    server = start(nginx, ldaps_url(LDAP_IPV4, port=DNS_ONLY_PORT))

    assert_denied(server)
    assert "does not match address" in server.log()


def test_ca_directory_is_trusted(nginx, tmp_path):
    # OpenSSL looks CAs up in a directory by subject hash: <hash>.0.
    subject_hash = subprocess.run(
        ["openssl", "x509", "-hash", "-noout", "-in", str(CA)], capture_output=True, text=True, check=True
    ).stdout.strip()
    shutil.copy(CA, tmp_path / f"{subject_hash}.0")
    body = f"require valid_user;\nssl_check_cert on;\nssl_ca_dir {tmp_path};{TIMEOUTS}"
    server = nginx.start(http=ldap_server("tls", body, url=ldaps_url()), server=protected_location("tls"))

    assert server.get(auth=creds("alice")).status_code == 200


def test_certificate_is_not_checked_when_ssl_check_cert_is_off(nginx):
    server = start(nginx, ldaps_url(port=UNTRUSTED_PORT), check="off", ca_file=None)

    assert server.get(auth=creds("alice")).status_code == 200


def test_untrusted_issuer_is_rejected(nginx):
    server = start(nginx, ldaps_url(port=UNTRUSTED_PORT))

    assert_denied(server)
    assert "presented invalid SSL certificate: error" in server.log()


def test_test_ca_is_not_trusted_without_ssl_ca_file(nginx):
    server = start(nginx, ldaps_url(), ca_file=None)

    assert_denied(server)
    assert "presented invalid SSL certificate: error" in server.log()


def test_certificate_for_another_host_is_rejected(nginx):
    server = start(nginx, ldaps_url(port=WRONG_HOST_PORT))

    assert_denied(server)
    assert "does not match address" in server.log()


def test_host_name_only_in_subject_cn_is_rejected(nginx):
    # RFC 9525: the subject CN is never used as a reference identifier.
    server = start(nginx, ldaps_url(port=CN_ONLY_PORT))

    assert_denied(server)
    assert "does not match address" in server.log()


def test_tls13_only_server_is_accepted(nginx):
    server = start(nginx, ldaps_url(port=TLS13_ONLY_PORT))

    assert server.get(auth=creds("alice")).status_code == 200


def test_ssl_ca_file_applies_to_its_own_server_only(nginx):
    # "other" trusts the other CA and reaches the proxy whose certificate it
    # issued; "main" trusts only the test CA and must not accept that proxy.
    http = tls_server("other", ldaps_url(port=UNTRUSTED_PORT), ca_file=OTHER_CA) + tls_server(
        "main", ldaps_url(port=UNTRUSTED_PORT)
    )
    server = nginx.start(
        http=http,
        server=protected_location("other", "/other/") + protected_location("main", "/main/"),
    )

    assert server.get("/other/", auth=creds("alice")).status_code == 200
    try:
        response = server.get("/main/", auth=creds("alice"))
    except requests.ConnectionError:
        return
    assert response.status_code != 200


@pytest.mark.parametrize(
    ("directive", "path"),
    [
        pytest.param("ssl_ca_file", "/nonexistent/ca.crt", id="missing-ca-file"),
        pytest.param("ssl_ca_file", TLS_DIR / "generate.sh", id="ca-file-without-certificates"),
    ],
)
def test_unusable_ca_location_is_a_configuration_error(nginx, directive, path):
    body = f"require valid_user;\nssl_check_cert on;\n{directive} {path};"
    result = nginx.check_config(
        http=ldap_server("tls", body, url=ldaps_url()), server=protected_location("tls")
    )

    assert result.returncode == 1, result.stderr
    assert f'cannot load CA certificates from "{path}"' in result.stderr
