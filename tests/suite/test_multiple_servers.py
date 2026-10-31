"""Several ldap_server blocks in one location are tried in order."""

import pytest

from conftest import ldap_server, protected_location
from ldapdata import creds, group_dn

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


@pytest.mark.xfail(
    reason="the cache lookup reads conf->servers (an array of pointers) as an array of "
    "structs, so a DENY cached for one server is returned for the next one (#245, #228)"
)
def test_cache_does_not_leak_a_deny_to_the_next_server(nginx):
    server = nginx.start(http=CACHE + SERVERS, server=protected_location("restricted anyone"))

    assert server.get(auth=creds("alice")).status_code == 200


def test_cache_keeps_serving_an_allow(nginx):
    server = nginx.start(http=CACHE + ldap_server("anyone"), server=protected_location("anyone"))

    assert [server.get(auth=creds("bob")).status_code for _ in range(3)] == [200, 200, 200]
