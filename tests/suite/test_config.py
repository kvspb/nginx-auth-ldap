"""Configuration parsing: invalid input is reported, never crashes nginx."""

import pytest

from conftest import ldap_server, protected_location
from ldapdata import LDAP_HOST, PEOPLE_DN

USERS = ldap_server("users")
LOCATION = protected_location("users")
QUERY = f"{PEOPLE_DN}?uid?sub?(objectClass=*)"
WITHOUT_URL = """
ldap_server users {
    require valid_user;
}
"""
NO_URL_TEXT = 'no "url" in ldap_server "users"'


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
        pytest.param(WITHOUT_URL, LOCATION, 1, NO_URL_TEXT, id="ldap-server-without-url"),
        pytest.param(WITHOUT_URL, "", 1, NO_URL_TEXT, id="unused-ldap-server-without-url"),
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
        *[
            server_case(
                case_id,
                f'Invalid filter "{bad_filter}" in auth_ldap_url',
                url=f"ldap://{LDAP_HOST}/{PEOPLE_DN}?uid?sub?{bad_filter}",
            )
            for case_id, bad_filter in [
                ("url-with-bad-filter", "objectClass=*)("),
                ("url-with-filter-without-parentheses", "objectClass=*"),
                ("url-with-unclosed-filter", "(objectClass=*"),
                ("url-with-two-filters", "(objectClass=*)(uid=*)"),
                ("url-with-empty-filter", "()"),
            ]
        ],
        pytest.param(
            ldap_server(
                "users", url=f"ldap://{LDAP_HOST}/{PEOPLE_DN}?uid?sub?(&(objectClass=*)(!(uid=nobody)))"
            ),
            LOCATION,
            0,
            None,
            id="url-with-nested-filter",
        ),
        server_case(
            "url-with-port-out-of-range",
            "Invalid port 99999 in auth_ldap_url",
            url=f"ldap://{LDAP_HOST}:99999/{QUERY}",
        ),
        server_case(
            "url-with-port-above-65535",
            "Invalid port 65536 in auth_ldap_url",
            url=f"ldap://{LDAP_HOST}:65536/{QUERY}",
        ),
        pytest.param(
            ldap_server("users", url=f"ldap://{LDAP_HOST}:65535/{QUERY}"),
            LOCATION,
            0,
            None,
            id="url-with-port-65535",
        ),
        pytest.param(
            ldap_server("users", url=f"ldap://{LDAP_HOST}:1/{QUERY}"), LOCATION, 0, None, id="url-with-port-1"
        ),
        server_case(
            "url-with-negative-port", "Invalid port -1 in auth_ldap_url", url=f"ldap://{LDAP_HOST}:-1/{QUERY}"
        ),
        # require / satisfy
        server_case(
            "require-unknown-kind",
            'invalid value "nobody" for require, it must be "valid_user", "user" or "group"',
            "require nobody;",
        ),
        server_case("require-without-kind", 'invalid number of arguments in "require"', "require;"),
        server_case(
            "require-user-without-value", 'invalid number of arguments in "require"', "require user;"
        ),
        server_case(
            "require-group-without-value", 'invalid number of arguments in "require"', "require group;"
        ),
        server_case(
            "require-user-with-two-values",
            'invalid number of arguments in "require"',
            'require user "a" "b";',
        ),
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
        ),
        server_case(
            "max-down-retries-negative",
            "'max_down_retries' value must be an integer",
            "require valid_user;\nmax_down_retries -1;",
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


def test_ldap_server_without_url_does_not_start(nginx):
    # It used to pass nginx -t and kill every worker with SIGFPE at start.
    with pytest.raises(RuntimeError, match="nginx exited with 1"):
        nginx.start(http=WITHOUT_URL, server=LOCATION)


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
    result = nginx.check_config(
        http=ldap_server("users", f"require valid_user;\n{directive}"), server=LOCATION
    )

    assert result.returncode == 0, result.stderr


SINGLE_VALUE_DIRECTIVES = [
    "url",
    "binddn",
    "binddn_passwd",
    "group_attribute",
    "group_attribute_is_dn",
    "satisfy",
    "referral",
    "max_down_retries",
    "connections",
    "ssl_check_cert",
    "ssl_ca_dir",
    "ssl_ca_file",
    "connect_timeout",
    "reconnect_timeout",
    "bind_timeout",
    "request_timeout",
    "include",
]


@pytest.mark.parametrize("args", ["", " on off"], ids=["no-value", "two-values"])
@pytest.mark.parametrize("name", SINGLE_VALUE_DIRECTIVES)
def test_single_value_directive_needs_exactly_one_value(nginx, name, args):
    result = nginx.check_config(
        http=ldap_server("users", f"require valid_user;\n{name}{args};"), server=LOCATION
    )

    assert result.returncode == 1, result.stderr
    assert f'invalid number of arguments in "{name}"' in result.stderr
