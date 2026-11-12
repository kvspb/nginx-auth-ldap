"""Several ldap_server blocks in one location are tried in order."""

import re
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import TIMEOUTS, ldap_server, protected_location, url_for
from ldapdata import (
    LDAP_HOST,
    PEOPLE_DN,
    TWIN_OTHER_SECRET,
    TWIN_UID,
    changed_password,
    creds,
    group_dn,
    password,
)
from ldapproxy import LdapProxy

# The first server only admits members of "ops"; the second admits any user.
RESTRICTED = f"""
group_attribute member;
group_attribute_is_dn on;
satisfy all;
require group "{group_dn("ops")}";
"""

SERVERS = ldap_server("restricted", RESTRICTED) + ldap_server("anyone")
CACHE = """
auth_ldap_cache_enabled on;
auth_ldap_cache_expiration_time 10000;
auth_ldap_cache_size 1000;
"""


class TestFallThrough:
    """No cache: each request walks the servers from the first one."""

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        return shared_nginx.start(http=SERVERS, server=protected_location("restricted anyone"))

    @pytest.mark.parametrize(
        ("auth", "expected"),
        [
            # alice is denied by "restricted" but allowed by "anyone".
            pytest.param(creds("alice"), 200, id="denied-by-first-allowed-by-second"),
            pytest.param(("alice", "not-the-password"), 401, id="rejected-by-every-server"),
        ],
    )
    def test_outcome(self, server, auth, expected):
        assert server.get(auth=auth).status_code == expected


# Cache tests keep a fresh nginx each: the cache is per-worker state that
# would leak between tests sharing an instance.
#
# A cached answer is told from a fresh one by changing erin's password in the
# directory: the old password can then only succeed, and a new wrong one can
# only fail, through the cache. The cache key includes the password.
#
# Regression tests for kvspb#245 and #228: the lookup read conf->servers (an
# array of pointers) as an array of structs, and every outcome was stored
# under the key of the last server looked up, not of the server that
# produced it. A DENY from one server then denied the user on the next one.


def test_cache_does_not_leak_a_deny_to_the_next_server(nginx):
    server = nginx.start(http=CACHE + SERVERS, server=protected_location("restricted anyone"))

    # erin is denied by "restricted" (not in ops) and allowed by "anyone".
    assert [server.get(auth=creds("erin")).status_code for _ in range(2)] == [200, 200]


def test_cache_serves_an_allow_from_a_later_server(nginx):
    server = nginx.start(http=CACHE + SERVERS, server=protected_location("restricted anyone"))
    assert server.get(auth=creds("erin")).status_code == 200

    with changed_password("erin", "rotated-secret"):
        assert server.get(auth=creds("erin")).status_code == 200


def test_cache_serves_a_deny_for_the_same_server(nginx):
    server = nginx.start(http=CACHE + ldap_server("anyone"), server=protected_location("anyone"))
    assert server.get(auth=("erin", "rotated-secret")).status_code == 401

    with changed_password("erin", "rotated-secret"):
        assert server.get(auth=("erin", "rotated-secret")).status_code == 401


def test_cache_keeps_serving_an_allow(nginx):
    server = nginx.start(http=CACHE + ldap_server("anyone"), server=protected_location("anyone"))

    assert [server.get(auth=creds("bob")).status_code for _ in range(3)] == [200, 200, 200]


def test_without_cache_the_directory_is_asked_every_time(nginx):
    # Guards the method above: without a cache the password change is seen.
    server = nginx.start(http=SERVERS, server=protected_location("restricted anyone"))
    assert server.get(auth=creds("erin")).status_code == 200

    with changed_password("erin", "rotated-secret"):
        assert server.get(auth=creds("erin")).status_code == 401


def test_cache_rejects_a_wrong_password_with_several_servers(nginx):
    # A cache miss on another server must not count as an allow.
    server = nginx.start(http=CACHE + SERVERS, server=protected_location("restricted anyone"))

    assert server.get(auth=("erin", "not-the-password")).status_code == 401


def test_cache_allow_from_another_server_skips_an_unreachable_one(nginx, closed_port):
    # kvspb#201: an allow cached by any server of the location is used first,
    # so /both answers from the cache without waiting for "down".
    down = ldap_server("down", "require valid_user;" + TIMEOUTS, url=url_for("127.0.0.1", closed_port))
    locations = protected_location("anyone", path="/anyone/") + protected_location(
        "down anyone", path="/both/"
    )
    server = nginx.start(http=CACHE + SERVERS + down, server=locations)
    assert server.get("/anyone/", auth=creds("erin")).status_code == 200

    assert server.get("/both/", auth=creds("erin")).status_code == 200


# The location below has no auth_ldap of its own: it inherits the http-level
# auth_ldap / auth_ldap_servers placed before the last ldap_server block.
INHERITING_LOCATION = """
location / {
    root html;
    default_type text/plain;
    try_files /ok =404;
}
"""

HTTP_LEVEL_AUTH = """
auth_ldap "Restricted";
auth_ldap_servers s1;
"""


@pytest.mark.parametrize(
    "http",
    [
        # Regression: auth_ldap_servers kept a pointer into the array of
        # servers, which moved when a later ldap_server block grew it past
        # its capacity (7 by default). The location then pointed at a stale
        # copy with uninitialised queues and the worker crashed.
        pytest.param(
            "".join(ldap_server(f"s{i}") for i in range(1, 8)) + HTTP_LEVEL_AUTH + ldap_server("s8"),
            id="eighth-server-after-reference",
        ),
        pytest.param(
            "auth_ldap_servers_size 1;\n" + ldap_server("s1") + HTTP_LEVEL_AUTH + ldap_server("s2"),
            id="servers-size-1-second-server-after-reference",
        ),
        # The value sized the array of servers: with 0 the pointer to a server
        # was written past an empty array and overwritten by the next block.
        pytest.param(
            "auth_ldap_servers_size 0;\n" + ldap_server("s1") + HTTP_LEVEL_AUTH + ldap_server("s2"),
            id="servers-size-0",
        ),
    ],
)
def test_server_referenced_before_a_later_ldap_server_block(nginx, http):
    server = nginx.start(http=http, server=INHERITING_LOCATION)

    assert server.get(auth=creds("alice")).status_code == 200


# The user search of each server must find its own entry. A search that is
# rejected because it found two entries (twin, see ldapdata.TWIN_UID) left
# the DN of its first entry behind, and the next server's search reused it
# as the user DN: that server then bound an entry it never returned.
# "ambiguous" finds both twins; each "only-*" server holds one of them, so
# whichever entry the ambiguous search returns first, one case below would
# bind the wrong twin.
TWIN_PEOPLE_DN = f"uid={TWIN_UID},{PEOPLE_DN}"
TWIN_CONTRACTORS_DN = f"uid={TWIN_UID},ou=contractors,{PEOPLE_DN}"
TWIN_SERVERS = (
    ldap_server("ambiguous")
    + ldap_server(
        "only_people", url=f"ldap://{LDAP_HOST}:389/{PEOPLE_DN}?uid?one?(objectClass=inetOrgPerson)"
    )
    + ldap_server(
        "only_contractors",
        url=f"ldap://{LDAP_HOST}:389/ou=contractors,{PEOPLE_DN}?uid?sub?(objectClass=inetOrgPerson)",
    )
)
FOUND_ENTRY_RE = re.compile(r'http_auth_ldap: Found entry with DN "([^"]*)"')


class TestRejectedAmbiguousSearchThenNextServer:
    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        return shared_nginx.start(
            http=TWIN_SERVERS,
            server=protected_location("ambiguous only_people", path="/people")
            + protected_location("ambiguous only_contractors", path="/contractors"),
        )

    @pytest.mark.parametrize(
        ("path", "secret", "expected", "own_dn"),
        [
            pytest.param("/people", password(TWIN_UID), 200, TWIN_PEOPLE_DN, id="people-own-password"),
            pytest.param("/people", TWIN_OTHER_SECRET, 401, TWIN_PEOPLE_DN, id="people-other-twin-password"),
            pytest.param(
                "/contractors", TWIN_OTHER_SECRET, 200, TWIN_CONTRACTORS_DN, id="contractors-own-password"
            ),
            pytest.param(
                "/contractors",
                password(TWIN_UID),
                401,
                TWIN_CONTRACTORS_DN,
                id="contractors-other-twin-password",
            ),
        ],
    )
    def test_next_server_uses_its_own_entry(self, server, path, secret, expected, own_dn):
        since = server.log_size()

        assert server.get(path, auth=(TWIN_UID, secret)).status_code == expected

        # Debug builds log every recorded entry: the last one is the user DN
        # the second server worked with.
        found = FOUND_ENTRY_RE.findall(server.log(since))
        if found:
            assert found[-1] == own_dn


# Failover (kvspb#115 #198 #33 #34): a server that cannot answer must not
# stop the request; the next server in auth_ldap_servers decides.

FAILOVER_TIMEOUTS = """
connect_timeout 1s;
bind_timeout 1s;
reconnect_timeout 1s;
request_timeout 1s;
"""


def failover_server(nginx, first_url: str, second: str = "", first_body: str = "require valid_user;"):
    http = ldap_server("first", first_body + FAILOVER_TIMEOUTS, url=first_url)
    http += ldap_server("second", "require valid_user;" + FAILOVER_TIMEOUTS + second)
    server = nginx.start(http=http, server=protected_location("first second"))
    # Let the second server's pool bind; the first one never becomes ready.
    time.sleep(0.3)
    return server


def timed_get(server, auth) -> tuple[int, float]:
    started = time.monotonic()
    code = server.get(auth=auth, timeout=10).status_code
    return code, time.monotonic() - started


def test_unreachable_first_server_is_skipped_at_once(nginx, closed_port):
    server = failover_server(nginx, url_for("127.0.0.1", closed_port))

    code, elapsed = timed_get(server, creds("alice"))

    assert code == 200
    # Not after the first server's request_timeout (1 s): it has no
    # connection at all, so nothing can be gained by waiting for it.
    assert elapsed < 0.5, f"answered after {elapsed:.2f} s"
    code, _ = timed_get(server, ("alice", "wrong"))
    # The unreachable server might know the user: not a definitive 401.
    assert code == 503


def test_first_server_that_rejects_the_service_bind_is_skipped(nginx):
    http = ldap_server("first", "require valid_user;" + FAILOVER_TIMEOUTS, bind_secret="wrong-secret")
    http += ldap_server("second", "require valid_user;" + FAILOVER_TIMEOUTS)
    server = nginx.start(http=http, server=protected_location("first second"))
    time.sleep(0.3)

    code, elapsed = timed_get(server, creds("alice"))

    assert code == 200
    assert elapsed < 0.5, f"answered after {elapsed:.2f} s"


def test_silent_first_server_is_left_after_its_request_timeout(nginx):
    with LdapProxy() as proxy:
        server = failover_server(nginx, url_for("127.0.0.1", proxy.port))
        # Both pools are bound now; then the first server stops answering.
        assert server.get(auth=creds("alice")).status_code == 200
        proxy.hold()

        code, elapsed = timed_get(server, creds("bob"))

    assert code == 200
    assert 0.9 < elapsed < 3, f"answered after {elapsed:.2f} s"


def test_every_server_unreachable_is_503(nginx, closed_port):
    url = url_for("127.0.0.1", closed_port)
    http = ldap_server("first", "require valid_user;" + FAILOVER_TIMEOUTS, url=url)
    http += ldap_server("second", "require valid_user;" + FAILOVER_TIMEOUTS, url=url)
    server = nginx.start(http=http, server=protected_location("first second"))

    code, elapsed = timed_get(server, creds("alice"))

    assert code == 503
    # The last server is waited for: it may come back within request_timeout.
    assert 0.9 < elapsed < 3, f"answered after {elapsed:.2f} s"


def test_single_server_is_waited_for_while_it_starts(nginx):
    # Right after start the pool may still be connecting: with no other
    # server to try, the request waits for it instead of failing.
    server = nginx.start(http=ldap_server("users"), server=protected_location("users"))

    assert server.get(auth=creds("alice")).status_code == 200


def test_first_server_that_went_away_is_skipped_at_once(nginx):
    # It was bound, then its connections broke and it refuses new ones: the
    # module must notice that no connection is left, not wait for one.
    with LdapProxy() as proxy:
        server = failover_server(nginx, url_for("127.0.0.1", proxy.port))
        assert server.get(auth=creds("alice")).status_code == 200
        proxy.refuse()
        proxy.drop()
        time.sleep(0.3)

        code, elapsed = timed_get(server, creds("bob"))

    assert code == 200
    assert elapsed < 0.5, f"answered after {elapsed:.2f} s"


def test_server_that_is_still_connecting_is_waited_for(nginx):
    # Right after a worker starts, no connection of a server is bound yet.
    # Such a server used to be skipped as if it were unreachable, so the
    # first requests went to the next server, or got 503 when that one
    # denied. A server is only skipped once a connection to it has failed.
    with LdapProxy() as proxy:
        proxy.hold()
        first = ldap_server("first", f"require valid_user;{TIMEOUTS}", url=url_for("127.0.0.1", proxy.port))
        # The second server admits nobody but bob.
        second = ldap_server("second", f'require user "uid=bob,{PEOPLE_DN}";{TIMEOUTS}')
        server = nginx.start(http=first + second, server=protected_location("first second"))

        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(server.get, auth=creds("alice"), timeout=10)
            time.sleep(0.3)
            proxy.release()
            response = pending.result()

    assert response.status_code == 200
    assert "has no connection" not in server.log()


def test_server_that_reconnects_after_a_drop_is_waited_for(nginx):
    # A connection that the server closed is reopened at once. Until it is
    # bound again the server has no connection, but nothing failed: requests
    # wait for it instead of going to the next server.
    with LdapProxy() as proxy:
        first = ldap_server("first", f"require valid_user;{TIMEOUTS}", url=url_for("127.0.0.1", proxy.port))
        second = ldap_server("second", f'require user "uid=bob,{PEOPLE_DN}";{TIMEOUTS}')
        server = nginx.start(http=first + second, server=protected_location("first second"))
        deadline = time.monotonic() + 5
        while server.get(auth=creds("alice")).status_code != 200 and time.monotonic() < deadline:
            time.sleep(0.1)

        proxy.hold()
        proxy.drop()
        time.sleep(0.3)
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(server.get, auth=creds("alice"), timeout=10)
            time.sleep(0.3)
            proxy.release()
            response = pending.result()

    assert response.status_code == 200


def test_server_whose_connect_fails_at_once_is_skipped(nginx):
    # connect() to a link-local address without a zone fails at once
    # (EINVAL), before any event: that counts as a failed connection too.
    first = ldap_server("first", f"require valid_user;{TIMEOUTS}", url=url_for("[fe80::1]", 389))
    server = nginx.start(http=first + ldap_server("second"), server=protected_location("first second"))
    time.sleep(0.2)

    started = time.monotonic()
    assert server.get(auth=creds("alice")).status_code == 200
    assert time.monotonic() - started < 0.5
    assert 'Server "first" has no connection' in server.log()
