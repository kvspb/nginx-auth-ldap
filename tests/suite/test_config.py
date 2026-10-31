"""Configuration parsing: invalid input is reported, never crashes nginx."""

import pytest

from conftest import ldap_server, protected_location
from ldapdata import LDAP_HOST, PEOPLE_DN

USERS = ldap_server("users")
LOCATION = protected_location("users")


@pytest.mark.parametrize(
    ("http", "server", "expected_rc", "expected_text"),
    [
        pytest.param(USERS, LOCATION, 0, None, id="valid"),
        pytest.param("", LOCATION, 1, "ldap_server", id="servers-used-before-defined"),
        pytest.param(
            USERS,
            protected_location("nosuch"),
            1,
            'Server "nosuch" has not been defined',
            id="unknown-server-name",
        ),
        pytest.param(
            ldap_server("users", url=f"ldap://{LDAP_HOST}/{PEOPLE_DN}"),
            LOCATION,
            1,
            "No user attribute specified",
            id="url-without-login-attribute",
        ),
        pytest.param(
            ldap_server("users", url=f"ldap:///{PEOPLE_DN}?uid"),
            LOCATION,
            1,
            "[emerg]",
            id="url-without-host",
            marks=pytest.mark.xfail(reason="ngx_strlen(lud_host) on a NULL host segfaults (#187)"),
        ),
        pytest.param(
            ldap_server("users", "require valid_user;\nno_such_directive on;"),
            LOCATION,
            1,
            None,
            id="unknown-directive-in-ldap-server",
            marks=pytest.mark.xfail(
                reason="unknown directives inside ldap_server are silently ignored (#69, #87)"
            ),
        ),
    ],
)
def test_nginx_t(nginx, http, server, expected_rc, expected_text):
    result = nginx.check_config(http=http, server=server)

    # A negative return code means nginx -t was killed by a signal.
    assert result.returncode == expected_rc, f"nginx -t exited with {result.returncode}:\n{result.stderr}"
    if expected_text is not None:
        assert expected_text in result.stderr
