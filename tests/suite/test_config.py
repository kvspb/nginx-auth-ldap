"""Configuration parsing: invalid input is reported, never crashes nginx."""

import re
from pathlib import Path

import pytest

from conftest import ldap_server, protected_location
from harness import Nginx
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
            'No user attribute specified in url of ldap_server "users"',
            id="url-without-login-attribute",
        ),
        pytest.param(
            ldap_server("users", url=f"ldap:///{PEOPLE_DN}?uid"),
            LOCATION,
            1,
            'No host specified in url of ldap_server "users"',
            id="url-without-host",
        ),
        pytest.param(WITHOUT_URL, LOCATION, 1, NO_URL_TEXT, id="ldap-server-without-url"),
        pytest.param(WITHOUT_URL, "", 1, NO_URL_TEXT, id="unused-ldap-server-without-url"),
        server_case(
            "url-with-port-without-host",
            'No host specified in url of ldap_server "users"',
            url=f"ldap://:389/{QUERY}",
        ),
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
                f'Invalid filter "{bad_filter}" in url of ldap_server "users"',
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
            'Invalid port 99999 in url of ldap_server "users"',
            url=f"ldap://{LDAP_HOST}:99999/{QUERY}",
        ),
        server_case(
            "url-with-port-above-65535",
            'Invalid port 65536 in url of ldap_server "users"',
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
            "url-with-negative-port",
            'Invalid port -1 in url of ldap_server "users"',
            url=f"ldap://{LDAP_HOST}:-1/{QUERY}",
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
            'http_auth_ldap: "require valid_user" template is duplicate',
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
        # Names of the same length, which only the comparison tells apart.
        pytest.param(ldap_server("first") + USERS, LOCATION, 0, None, id="two-servers"),
        pytest.param(
            USERS + ldap_server("first") + ldap_server("users"),
            LOCATION,
            1,
            'duplicate ldap_server "users"',
            id="duplicate-of-the-first-server",
        ),
        pytest.param(
            ldap_server("first") + USERS + ldap_server("users"),
            LOCATION,
            1,
            'duplicate ldap_server "users"',
            id="duplicate-of-the-second-server",
        ),
        server_case(
            "second-url",
            '"url" is duplicate',
            f'require valid_user;\nurl "ldap://{LDAP_HOST}/{QUERY}";',
        ),
        pytest.param(
            USERS,
            'location / { auth_ldap "Restricted"; auth_ldap_servers; }',
            1,
            'invalid number of arguments in "auth_ldap_servers"',
            id="auth-ldap-servers-without-servers",
        ),
        pytest.param(
            USERS,
            'location / { auth_ldap "a"; auth_ldap "b"; auth_ldap_servers users; }',
            1,
            '"auth_ldap" directive is duplicate',
            id="auth-ldap-twice",
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


def test_nginx_t_prints_nothing_for_a_valid_configuration(nginx):
    # "parse_require", "Setting group" and "Setting satisfy all" were logged
    # at the notice level for every such line (audit F29).
    body = (
        "require valid_user;\nrequire user uid=alice;\ngroup_attribute member;\n"
        "require group cn=admins;\nsatisfy all;"
    )
    result = nginx.check_config(http=ldap_server("users", body), server=LOCATION)

    assert result.returncode == 0, result.stderr
    # nginx -t writes to the error_log of the configuration once it is read.
    assert "http_auth_ldap" not in result.stderr + nginx.log()


def worker_memory(nginx, size: int) -> int:
    """VmSize of the worker, in kB, with a cache of ``size`` entries."""
    http = f"auth_ldap_cache_enabled on;\nauth_ldap_cache_size {size};\n" + USERS
    server = nginx.start(http=http, server=LOCATION)
    (worker,) = server.worker_pids()
    status = Path(f"/proc/{worker}/status").read_text()
    server.stop()
    match = re.search(r"^VmSize:\s+(\d+) kB", status, re.MULTILINE)
    assert match is not None, status
    return int(match.group(1))


def test_large_cache_size_is_honoured(nginx):
    # The bucket table ended at 1109 buckets: any auth_ldap_cache_size above
    # 8872 entries was cut to that without a word (audit F30). Two million
    # entries of 40 bytes take about 78 MB; the cut cache took 0.3 MB. The
    # size is large, as an AddressSanitizer build serves a few MB from
    # address space it reserved before, which VmSize does not show again.
    grown = worker_memory(nginx, 2000000) - worker_memory(nginx, 100)

    assert 40000 < grown < 130000, f"the worker grew by {grown} kB"


@pytest.mark.skipif(
    "-fsanitize=address" not in Nginx._configure_args(), reason="needs an AddressSanitizer build (SANITIZE=1)"
)
def test_reload_frees_the_parsed_url(nginx):
    # ldap_url_parse() allocates the LDAPURLDesc with malloc(); it was never
    # freed, so every reload leaked one per ldap_server (audit F27). The
    # master destroys the old configuration at once on a reload, after which
    # LeakSanitizer sees the descriptor as lost when the master exits.
    nginx.env["ASAN_OPTIONS"] = f"detect_leaks=1:fast_unwind_on_malloc=0:log_path={nginx.prefix}/lsan"
    nginx.start(http=USERS, server=LOCATION)
    nginx.reload()
    assert nginx.quit(timeout=10)

    reports = "".join(path.read_text() for path in nginx.prefix.glob("lsan*"))
    assert "ldap_url_parse" not in reports, reports
