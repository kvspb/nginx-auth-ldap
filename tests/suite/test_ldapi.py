"""ldapi:// urls: LDAP over a Unix socket (kvspb#229).

A slapd on the same host may listen only on a Unix socket. The url names
the path of the socket, percent-encoded, as in ldap.conf(5):
ldapi://%2Frun%2Fslapd%2Fldapi/dc=example,dc=org?uid?sub. The LDAP server
of the suite runs in another container, so a proxy on a Unix socket next to
nginx stands in for it.
"""

from __future__ import annotations

import time
from pathlib import Path
from urllib.parse import quote

import pytest

from conftest import TIMEOUTS, ldap_server, protected_location
from ldapdata import PEOPLE_DN, creds, group_dn
from ldapproxy import LdapProxy


def ldapi_url(path: Path | str, base: str = PEOPLE_DN) -> str:
    return f"ldapi://{quote(str(path), safe='')}/{base}?uid?sub?(objectClass=inetOrgPerson)"


@pytest.fixture
def socket_path(nginx) -> Path:
    path = nginx.prefix / "run" / "ldapi"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture
def proxy(socket_path):
    with LdapProxy(unix_path=socket_path) as ldap:
        yield ldap


def test_login_over_a_unix_socket(nginx, proxy, socket_path):
    body = f"""
group_attribute member;
group_attribute_is_dn on;
satisfy all;
require group "{group_dn("admins")}";
{TIMEOUTS}
"""
    server = nginx.start(
        http=ldap_server("local", body, url=ldapi_url(socket_path)), server=protected_location("local")
    )

    assert server.get(auth=creds("alice")).status_code == 200
    assert server.get(auth=("alice", "wrong")).status_code == 401
    assert server.get(auth=creds("bob")).status_code == 401  # not in admins
    assert proxy.connections >= 1
    # TCP keepalive (on by default) does not apply to a Unix socket.
    assert "setsockopt" not in server.log()


def test_reconnects_after_the_server_closed_the_socket(nginx, proxy, socket_path):
    server = nginx.start(
        http=ldap_server("local", f"require valid_user;{TIMEOUTS}", url=ldapi_url(socket_path)),
        server=protected_location("local"),
    )
    assert server.get(auth=creds("alice")).status_code == 200
    connections = proxy.connections

    proxy.drop()
    time.sleep(0.3)

    assert server.get(auth=creds("bob")).status_code == 200
    assert proxy.connections > connections


def test_socket_that_appears_later(nginx, socket_path):
    # No socket yet: the server cannot decide (503), and the module keeps
    # trying every reconnect_timeout until slapd is up.
    server = nginx.start(
        http=ldap_server("local", f"require valid_user;{TIMEOUTS}", url=ldapi_url(socket_path)),
        server=protected_location("local"),
    )
    assert server.get(auth=creds("alice")).status_code == 503
    assert f'Unable to connect to LDAP server "unix:{socket_path}"' in server.log()

    with LdapProxy(unix_path=socket_path):
        deadline = time.monotonic() + 5
        status = None
        while time.monotonic() < deadline:
            status = server.get(auth=creds("alice")).status_code
            if status == 200:
                break
            time.sleep(0.2)

    assert status == 200


@pytest.mark.parametrize(
    ("url", "body", "text"),
    [
        pytest.param(
            f"ldapi:///{PEOPLE_DN}?uid?sub",
            "",
            'ldapi:// url of ldap_server "users" needs the path of the socket',
            id="no-path",
        ),
        pytest.param(
            f"ldapi://ldapi/{PEOPLE_DN}?uid?sub",
            "",
            'ldapi:// url of ldap_server "users" needs the path of the socket',
            id="relative-path",
        ),
        pytest.param(
            ldapi_url("/run/" + "x" * 120),
            "",
            "too long path in the unix domain socket",
            id="path-too-long",
        ),
        pytest.param(
            ldapi_url("/run/slapd/ldapi"),
            "starttls on;",
            '"starttls" needs an ldap:// url',
            id="starttls",
        ),
    ],
)
def test_invalid_ldapi_url(nginx, url, body, text):
    result = nginx.check_config(http=ldap_server("users", body, url=url), server=protected_location("users"))

    assert result.returncode == 1, result.stderr
    assert text in result.stderr


def test_socket_path_with_special_characters(nginx):
    # Percent-encoded in the url; nginx -t does not need the socket.
    url = ldapi_url("/run/slapd dir/ldapi%1")
    result = nginx.check_config(http=ldap_server("users", url=url), server=protected_location("users"))

    assert result.returncode == 0, result.stderr
