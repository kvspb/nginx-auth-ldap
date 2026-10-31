"""Several ldap_server blocks in one location are tried in order."""

import pytest

from conftest import TIMEOUTS, ldap_server, protected_location, url_for
from ldapdata import changed_password, creds, group_dn

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
