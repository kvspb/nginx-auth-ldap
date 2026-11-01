"""StartTLS on ldap:// urls ("starttls on;", kvspb#44 #175).

The module sends the StartTLS extended operation (RFC 4511, section 4.14)
right after the TCP connect and runs the TLS handshake on the same
connection before the service bind. Nothing else crosses the wire in clear,
and a server that refuses StartTLS or does not complete the handshake is
never sent a bind: there is no fallback to plain LDAP.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest

from conftest import TIMEOUTS, ldap_server, protected_location, url_for
from fakeldap import BIND_REQUEST, EXTENDED_RESPONSE, NOT_LDAP, FakeLdapServer, message, result
from ldapdata import BIND_SECRET, LDAP_HOST, LDAP_IPV4, TLS_DIR, creds, password
from ldapproxy import LdapProxy

CA = TLS_DIR / "ca.crt"
OTHER_CA = TLS_DIR / "other-ca.crt"


def starttls_server(url: str, ca=CA, check: str = "on", extra: str = "") -> str:
    body = f"require valid_user;\nstarttls on;\nssl_check_cert {check};{TIMEOUTS}{extra}"
    if ca is not None:
        body += f"ssl_ca_file {ca};\n"
    return ldap_server("tls", body, url=url)


def start(nginx, url: str, **kwargs):
    return nginx.start(http=starttls_server(url, **kwargs), server=protected_location("tls"))


@pytest.fixture
def proxy() -> Iterator[LdapProxy]:
    # In front of slapd on 389, which offers StartTLS with the test PKI.
    with LdapProxy() as proxy:
        yield proxy


def test_starttls_authenticates(nginx):
    server = start(nginx, url_for(LDAP_HOST, 389))

    assert server.get(auth=creds("alice")).status_code == 200
    assert server.get(auth=("alice", "wrong")).status_code == 401


def test_nothing_secret_crosses_the_wire_in_clear(nginx, proxy):
    # The proxy is reached as 127.0.0.1, which the certificate does not
    # name: check the chain only, through ssl_check_cert off, since this
    # test is about what is sent, not about verification.
    server = start(nginx, url_for("127.0.0.1", proxy.port), check="off", ca=None)

    assert server.get(auth=creds("alice")).status_code == 200
    assert BIND_SECRET.encode() not in proxy.sent
    assert password("alice").encode() not in proxy.sent


def test_without_starttls_the_password_is_sent_in_clear(nginx, proxy):
    # Guards the test above: the proxy does see a plain bind.
    body = f"require valid_user;{TIMEOUTS}"
    url = url_for("127.0.0.1", proxy.port)
    server = nginx.start(http=ldap_server("plain", body, url=url), server=protected_location("plain"))

    assert server.get(auth=creds("alice")).status_code == 200
    assert password("alice").encode() in proxy.sent


def test_certificate_is_verified(nginx):
    server = start(nginx, url_for(LDAP_HOST, 389), ca=OTHER_CA)

    assert server.get(auth=creds("alice")).status_code == 503
    assert "presented invalid SSL certificate" in server.log()


def test_certificate_ip_san_is_verified(nginx):
    server = start(nginx, url_for(LDAP_IPV4, 389))

    assert server.get(auth=creds("alice")).status_code == 200


class RefusingStartTls(FakeLdapServer):
    """Answers the StartTLS request with an error (protocolError)."""


class AcceptingWithoutTls(FakeLdapServer):
    """Says yes to StartTLS, then never answers the TLS handshake: a man in
    the middle that strips TLS cannot get the bind out of the module."""

    def answer_extended(self, msgid: int) -> bytes | None:
        return message(msgid, result(EXTENDED_RESPONSE, 0))


@pytest.mark.parametrize("fake_class", [RefusingStartTls, AcceptingWithoutTls], ids=["refused", "stripped"])
def test_no_bind_without_tls(nginx, fake_class):
    fake = fake_class()
    try:
        server = start(nginx, fake.url())

        assert server.get(auth=creds("alice"), timeout=10).status_code == 503
        assert BIND_REQUEST not in fake.requests, f"bind sent without TLS: {fake.requests}"
        assert fake.requests, "the module never asked for StartTLS"
        if fake_class is AcceptingWithoutTls:
            assert NOT_LDAP in fake.requests, "no TLS handshake after StartTLS"
        # The failed connection is closed and opened again after
        # reconnect_timeout (1 s), not left hanging.
        deadline = time.monotonic() + 3
        while fake.connections < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert fake.connections >= 2
    finally:
        fake.close()


@pytest.mark.parametrize(
    ("body", "text"),
    [
        pytest.param("starttls maybe;", 'invalid value "maybe" for starttls', id="unknown-value"),
        pytest.param("starttls;", 'invalid number of arguments in "starttls"', id="no-value"),
    ],
)
def test_starttls_config_errors(nginx, body, text):
    result_ = nginx.check_config(
        http=ldap_server("tls", f"require valid_user;\n{body}"), server=protected_location("tls")
    )

    assert result_.returncode == 1, result_.stderr
    assert text in result_.stderr


def test_starttls_with_ldaps_is_a_config_error(nginx):
    url = f"ldaps://{LDAP_HOST}:636/ou=people,dc=example,dc=org?uid?sub?(objectClass=inetOrgPerson)"
    result_ = nginx.check_config(http=starttls_server(url), server=protected_location("tls"))

    assert result_.returncode == 1, result_.stderr
    assert '"starttls" needs an ldap:// url' in result_.stderr


def test_starttls_off_is_accepted(nginx):
    result_ = nginx.check_config(
        http=ldap_server("plain", "require valid_user;\nstarttls off;"), server=protected_location("plain")
    )

    assert result_.returncode == 0, result_.stderr
