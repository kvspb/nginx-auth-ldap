"""Several ldap_server blocks in one location are tried in order."""

import re

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
