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
            "No host specified",
            id="url-without-host",
        ),
        server_case("url-with-port-without-host", "No host specified", url=f"ldap://:389/{QUERY}"),
        server_case(
            "unknown-directive-in-ldap-server",
            'unknown directive "no_such_directive" in ldap_server',
            "require valid_user;\nno_such_directive on;",
        ),
        server_case(
            "group-attribute-is-dn-unknown-value",
            'invalid value "maybe" for group_attribute_is_dn, it must be "on" or "off"',
            "require valid_user;\ngroup_attribute_is_dn maybe;",
        ),
        server_case(
            "ssl-check-cert-unknown-value",
            'invalid value "maybe" for ssl_check_cert, it must be "on" or "off"',
            "require valid_user;\nssl_check_cert maybe;",
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


@pytest.mark.parametrize(
    "directive",
    [
        pytest.param('group_attribute "member";', id="group_attribute"),
        pytest.param("group_attribute_is_dn on;", id="group_attribute_is_dn-on"),
        pytest.param("group_attribute_is_dn off;", id="group_attribute_is_dn-off"),
        pytest.param("satisfy all;", id="satisfy"),
        pytest.param("referral off;", id="referral"),
        pytest.param("max_down_retries 2;", id="max_down_retries"),
        pytest.param("connections 2;", id="connections"),
        pytest.param("ssl_check_cert on;", id="ssl_check_cert-on"),
        pytest.param("ssl_check_cert off;", id="ssl_check_cert-off"),
        pytest.param("ssl_ca_dir /etc/ssl/certs;", id="ssl_ca_dir"),
        pytest.param("ssl_ca_file /etc/ssl/certs/ca-certificates.crt;", id="ssl_ca_file"),
        pytest.param("connect_timeout 5s;", id="connect_timeout"),
        pytest.param("reconnect_timeout 5s;", id="reconnect_timeout"),
        pytest.param("bind_timeout 5s;", id="bind_timeout"),
        pytest.param("request_timeout 5s;", id="request_timeout"),
    ],
)
def test_known_directive_is_accepted(nginx, directive):
    result = nginx.check_config(http=ldap_server("users", f"require valid_user;\n{directive}"), server=LOCATION)

    assert result.returncode == 0, result.stderr
