"""Configuration parsing: invalid input is reported, never crashes nginx."""

import pytest

from conftest import ldap_server, protected_location
from ldapdata import LDAP_HOST, PEOPLE_DN

USERS = ldap_server("users")
LOCATION = protected_location("users")
QUERY = f"{PEOPLE_DN}?uid?sub?(objectClass=*)"

# Accepted silently or with a misleading result today; see nal-5br.7.
NOT_VALIDATED = pytest.mark.xfail(reason="invalid ldap_server values are not rejected (#69, #87, nal-5br.7)")


def server_case(
    case_id: str, text: str | None, body: str = "require valid_user;", url: str | None = None, marks=()
):
    """An ldap_server block that nginx -t must reject with ``text`` in its output."""
    block = ldap_server("users", body) if url is None else ldap_server("users", body, url=url)
    return pytest.param(block, LOCATION, 1, text, id=case_id, marks=marks)


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
        server_case(
            "unknown-directive-in-ldap-server",
            None,
            "require valid_user;\nno_such_directive on;",
            marks=NOT_VALIDATED,
        ),
        # url
        server_case(
            "url-with-other-scheme", 'URL doesnt begin with "ldap[s]://"', url=f"http://{LDAP_HOST}/{QUERY}"
        ),
        server_case(
            "url-with-cldap-scheme", 'URL doesnt begin with "ldap[s]://"', url=f"cldap://{LDAP_HOST}/{QUERY}"
        ),
        server_case(
            "url-with-bad-scope",
            "Invalid or missing scope string",
            url=f"ldap://{LDAP_HOST}/{PEOPLE_DN}?uid?bogus",
        ),
        server_case(
            "url-with-unresolvable-host",
            "host not found in LDAP hostname",
            url=f"ldap://no-such-host.invalid/{QUERY}",
        ),
        server_case(
            "url-with-bad-filter",
            None,
            url=f"ldap://{LDAP_HOST}/{PEOPLE_DN}?uid?sub?objectClass=*)(",
            marks=NOT_VALIDATED,
        ),
        server_case(
            "url-with-port-out-of-range", None, url=f"ldap://{LDAP_HOST}:99999/{QUERY}", marks=NOT_VALIDATED
        ),
        # require / satisfy
        server_case("require-unknown-kind", "require", "require nobody;", marks=NOT_VALIDATED),
        server_case(
            "require-valid-user-template-twice",
            "is duplicate",
            'require valid_user "uid=$remote_user,ou=a";\nrequire valid_user "uid=$remote_user,ou=b";',
        ),
        server_case(
            "satisfy-unknown-value",
            "Incorrect value for auth_ldap_satisfy",
            "require valid_user;\nsatisfy some;",
        ),
        # other options
        server_case(
            "referral-unknown-value", "Incorrect value for referral", "require valid_user;\nreferral maybe;"
        ),
        server_case(
            "connections-zero",
            "'connections' value has to be a number greater than 0",
            "require valid_user;\nconnections 0;",
        ),
        server_case(
            "connections-not-a-number",
            "'connections' value has to be a number greater than 0",
            "require valid_user;\nconnections abc;",
        ),
        server_case(
            "max-down-retries-not-a-number",
            "'max_down_retries' value must be an integer",
            "require valid_user;\nmax_down_retries abc;",
            marks=NOT_VALIDATED,
        ),
        server_case(
            "timeout-zero",
            "'request_timeout' value has to be a valid time unit greater than 0",
            "require valid_user;\nrequest_timeout 0;",
        ),
        server_case(
            "timeout-not-a-time",
            "'connect_timeout' value has to be a valid time unit greater than 0",
            "require valid_user;\nconnect_timeout abc;",
        ),
    ],
)
def test_nginx_t(nginx, http, server, expected_rc, expected_text):
    result = nginx.check_config(http=http, server=server)

    # A negative return code means nginx -t was killed by a signal.
    assert result.returncode == expected_rc, f"nginx -t exited with {result.returncode}:\n{result.stderr}"
    if expected_text is not None:
        assert expected_text in result.stderr
