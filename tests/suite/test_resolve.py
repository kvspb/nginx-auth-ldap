"""resolve on: the host name of the url resolved at run time (kvspb#63).

The name was resolved once, when nginx read the configuration, so a changed
DNS record took effect only after a reload: nginx kept connecting to the old
servers for days. With "resolve on" in an ldap_server block, the name is
resolved through the "resolver" of the http block before every connection,
as the resolver caches it (the TTL or valid=). A fake DNS server answers
the resolver; LDAP proxies on 127.0.0.2 and 127.0.0.3 stand for the old
and the new address of the server.
"""

from __future__ import annotations

import time

import pytest

from conftest import TIMEOUTS, ldap_server, protected_location
from fakedns import FakeDns
from ldapdata import LDAP_IPV4, PEOPLE_DN, TLS_DIR, creds, ldaps_url
from ldapproxy import LdapProxy

NAME = "ldap.test"


def url(port: int, host: str = NAME) -> str:
    return f"ldap://{host}:{port}/{PEOPLE_DN}?uid?sub?(objectClass=inetOrgPerson)"


def resolver(dns: FakeDns, timeout: str = "1s") -> str:
    return f"resolver {dns.address} valid=1s ipv6=off;\nresolver_timeout {timeout};\n"


def resolving_server(name: str, port: int, body: str = "require valid_user;") -> str:
    return ldap_server(name, f"{body}\nresolve on;{TIMEOUTS}", url=url(port))


def wait_for(predicate, timeout: float = 5) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


@pytest.fixture
def dns():
    with FakeDns() as server:
        yield server


@pytest.fixture
def old():
    with LdapProxy(host="127.0.0.2") as proxy:
        yield proxy


@pytest.fixture
def new(old):
    with LdapProxy(host="127.0.0.3", port=old.port) as proxy:
        yield proxy


def test_name_is_resolved_at_run_time(nginx, dns, old):
    dns.set(NAME, old.host)
    server = nginx.start(
        http=resolver(dns) + resolving_server("users", old.port), server=protected_location("users")
    )

    assert server.get(auth=creds("alice")).status_code == 200
    assert dns.queries[NAME] >= 1
    assert old.connections >= 1
    assert "Unable to resolve" not in server.log()
    assert "Could not resolve" not in server.log()


def test_address_is_named_in_the_log(nginx, dns, old):
    dns.set(NAME, old.host)
    old.close()
    server = nginx.start(
        http=resolver(dns) + resolving_server("users", old.port), server=protected_location("users")
    )

    assert server.get(auth=creds("alice")).status_code == 503
    assert f'Could not connect to "{old.host}:{old.port}" of ldap_server "users"' in server.log()


def test_new_address_once_the_old_server_is_gone(nginx, dns, old, new):
    # kvspb#63: the old servers went away and the record pointed elsewhere.
    dns.set(NAME, old.host)
    server = nginx.start(
        http=resolver(dns) + resolving_server("users", old.port), server=protected_location("users")
    )
    assert server.get(auth=creds("alice")).status_code == 200

    dns.set(NAME, new.host)
    old.refuse()
    old.drop()

    assert wait_for(lambda: server.get(auth=creds("bob")).status_code == 200)
    assert new.connections >= 1


def test_open_connections_stay_on_the_old_address(nginx, dns, old, new):
    # Connections are kept open: a changed record is used when they reconnect.
    dns.set(NAME, old.host)
    server = nginx.start(
        http=resolver(dns) + resolving_server("users", old.port), server=protected_location("users")
    )
    assert server.get(auth=creds("alice")).status_code == 200

    dns.set(NAME, new.host)
    time.sleep(1.5)

    assert server.get(auth=creds("bob")).status_code == 200
    assert new.connections == 0


def test_name_that_does_not_resolve_is_skipped(nginx, dns, old):
    # NXDOMAIN: the server cannot decide; the next server is asked.
    http = resolver(dns) + resolving_server("first", old.port) + ldap_server("second")
    server = nginx.start(http=http, server=protected_location("first second"))
    assert wait_for(lambda: dns.queries[NAME] >= 1)

    # At once: the first server is known to fail, nobody waits for it.
    started = time.monotonic()
    assert server.get(auth=creds("alice")).status_code == 200
    assert time.monotonic() - started < 0.5
    assert f'Could not resolve "{NAME}" of ldap_server "first" (3: Host not found)' in server.log()
    assert old.connections == 0


def test_name_that_does_not_resolve_alone_is_503(nginx, dns, old):
    server = nginx.start(
        http=resolver(dns) + resolving_server("users", old.port), server=protected_location("users")
    )

    assert server.get(auth=creds("alice")).status_code == 503


def test_dns_that_does_not_answer(nginx, dns, old):
    dns.set(NAME, old.host)
    dns.hold()
    server = nginx.start(
        http=resolver(dns, timeout="2s") + resolving_server("users", old.port),
        server=protected_location("users"),
    )

    assert server.get(auth=creds("alice")).status_code == 503
    # Not before resolver_timeout.
    assert "Operation timed out" not in server.log()
    assert wait_for(lambda: "(110: Operation timed out)" in server.log())


def test_resolver_after_the_ldap_server_block(nginx, dns, old):
    dns.set(NAME, old.host)
    server = nginx.start(
        http=resolving_server("users", old.port) + resolver(dns), server=protected_location("users")
    )

    assert server.get(auth=creds("alice")).status_code == 200


def test_ldaps_checks_the_certificate_against_the_name(nginx, dns):
    # The certificate of the test server names "ldap"; the address comes
    # from the resolver.
    dns.set("ldap", LDAP_IPV4)
    body = (
        f"require valid_user;\nresolve on;\nssl_check_cert on;\nssl_ca_file {TLS_DIR / 'ca.crt'};{TIMEOUTS}"
    )
    server = nginx.start(
        http=resolver(dns) + ldap_server("tls", body, url=ldaps_url("ldap")), server=protected_location("tls")
    )

    assert server.get(auth=creds("alice")).status_code == 200
    assert dns.queries["ldap"] >= 1


def test_address_in_the_url_needs_no_resolver_query(nginx, dns, old):
    server = nginx.start(
        http=resolver(dns)
        + ldap_server("users", f"require valid_user;\nresolve on;{TIMEOUTS}", url=url(old.port, old.host)),
        server=protected_location("users"),
    )

    assert server.get(auth=creds("alice")).status_code == 200
    assert sum(dns.queries.values()) == 0


def test_reload_while_resolving(nginx, dns, old):
    # The DNS server never answers and resolver_timeout is long: the old
    # worker must still exit at once, and nothing may crash.
    dns.set(NAME, old.host)
    dns.hold()
    server = nginx.start(
        http=resolver(dns, timeout="30s") + resolving_server("users", old.port),
        server=protected_location("users"),
    )
    assert wait_for(lambda: dns.queries[NAME] >= 1)
    before = server.worker_pids() or frozenset()

    server.reload()

    assert wait_for(lambda: not (before & (server.worker_pids() or frozenset())), timeout=5), (
        "the old worker waited for the resolver"
    )
    assert server.quit(timeout=5)


@pytest.mark.parametrize(
    ("http", "text"),
    [
        pytest.param(
            ldap_server("users", "resolve on;", url=url(389)),
            '"resolve" in ldap_server "users" needs a "resolver" in the http block',
            id="no-resolver",
        ),
        pytest.param(
            ldap_server("plain") + ldap_server("users", "resolve on;", url=url(389)),
            '"resolve" in ldap_server "users" needs a "resolver" in the http block',
            id="no-resolver-second-server",
        ),
        pytest.param(
            "resolver 127.0.0.1;\n"
            + ldap_server("users", "resolve on;", url=f"ldapi://%2Frun%2Fslapd%2Fldapi/{PEOPLE_DN}?uid?sub"),
            '"resolve" does not apply to the ldapi:// url of ldap_server "users"',
            id="ldapi",
        ),
        pytest.param(
            ldap_server("users", url=url(389, "no-such-host.invalid")),
            'host not found in LDAP hostname "no-such-host.invalid',
            id="unresolved-without-resolve",
        ),
    ],
)
def test_invalid_resolve(nginx, http, text):
    result = nginx.check_config(http=http, server=protected_location("users"))

    assert result.returncode == 1, result.stderr
    assert text in result.stderr


def test_name_need_not_resolve_when_nginx_starts(nginx):
    http = "resolver 127.0.0.1;\n" + ldap_server("users", "resolve on;", url=url(389, "no-such-host.invalid"))
    result = nginx.check_config(http=http, server=protected_location("users"))

    assert result.returncode == 0, result.stderr
