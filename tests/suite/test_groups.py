"""Group membership requirements ("require group") and "satisfy" modes.

Fixture users: alice (admins, devs), bob (devs, ops), carol (no group),
dave (admins, ops).
"""

import base64
import http.client

import pytest

from conftest import ldap_server, protected_location
from ldapdata import GROUPS_DN, SPECIAL_GROUP_DNS, creds, group_dn


def groups_server(nginx, satisfy: str, *groups: str):
    requires = "\n".join(f'require group "{group_dn(cn)}";' for cn in groups)
    body = f"""
group_attribute member;
group_attribute_is_dn on;
satisfy {satisfy};
{requires}
"""
    return nginx.start(http=ldap_server("groups", body), server=protected_location("groups"))


class TestSingleGroup:
    """satisfy all; require group admins."""

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        return groups_server(shared_nginx, "all", "admins")

    @pytest.mark.parametrize(
        ("uid", "expected"),
        [
            pytest.param("alice", 200, id="member"),
            pytest.param("bob", 401, id="member-of-other-groups"),
            pytest.param("carol", 401, id="member-of-no-group"),
        ],
    )
    def test_access(self, server, uid, expected):
        assert server.get(auth=creds(uid)).status_code == expected


class TestSatisfyAnyOfTwoGroups:
    """satisfy any; require group admins; require group ops."""

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        return groups_server(shared_nginx, "any", "admins", "ops")

    @pytest.mark.parametrize(
        ("uid", "expected"),
        [
            pytest.param("alice", 200, id="first-group-only"),
            pytest.param("bob", 200, id="second-group-only"),
            pytest.param("dave", 200, id="both-groups"),
            pytest.param("carol", 401, id="neither-group"),
        ],
    )
    def test_access(self, server, uid, expected):
        assert server.get(auth=creds(uid)).status_code == expected

    def test_wrong_password_is_rejected_even_for_a_member(self, server):
        assert server.get(auth=("alice", "not-the-password")).status_code == 401


class TestSatisfyAllOfTwoGroups:
    """satisfy all over admins and ops, in both orders.

    Regression for kvspb#194, #225, #240: the DN found by one group search
    was kept for the next one, so membership in the first group satisfied
    every later group. Checking both orders catches that from either side.
    """

    @pytest.fixture(
        scope="class",
        params=[("admins", "ops"), ("ops", "admins")],
        ids=["admins-then-ops", "ops-then-admins"],
    )
    def server(self, request, shared_nginx):
        return groups_server(shared_nginx, "all", *request.param)

    @pytest.mark.parametrize(
        ("uid", "expected"),
        [
            pytest.param("dave", 200, id="both-groups"),
            pytest.param("alice", 401, id="admins-only"),
            pytest.param("bob", 401, id="ops-only"),
            pytest.param("carol", 401, id="neither-group"),
        ],
    )
    def test_access(self, server, uid, expected):
        assert server.get(auth=creds(uid)).status_code == expected


class TestGroupDnWithSpecialCharacters:
    """require group with a DN that holds filter or DN special characters.

    The group check used to cut the DN at its first comma and put the RDN
    into a filter unescaped: "(" ")" made the filter invalid, an escaped
    comma split the DN in the wrong place, and "*" became a wildcard that
    also matched cn=a-b, whose only member is bob.
    """

    @pytest.fixture(scope="class", params=list(SPECIAL_GROUP_DNS), ids=list(SPECIAL_GROUP_DNS))
    def server(self, request, shared_nginx):
        body = f"""
group_attribute member;
group_attribute_is_dn on;
require group "{SPECIAL_GROUP_DNS[request.param]}";
"""
        return shared_nginx.start(http=ldap_server("special", body), server=protected_location("special"))

    @pytest.mark.parametrize(
        ("uid", "expected"),
        [
            pytest.param("alice", 200, id="member"),
            pytest.param("bob", 401, id="member-of-a-wildcard-match"),
            pytest.param("carol", 401, id="member-of-no-group"),
        ],
    )
    def test_access(self, server, uid, expected):
        assert server.get(auth=creds(uid)).status_code == expected


def get_raw(server, path: str, uid: str) -> int:
    """GET ``path`` sent as is: requests would percent-encode "|", and $arg_* is not decoded."""
    token = base64.b64encode(":".join(creds(uid)).encode()).decode()
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=15)
    try:
        conn.request("GET", path, headers={"Authorization": f"Basic {token}"})
        return conn.getresponse().status
    finally:
        conn.close()


class TestGroupDnFromRequestVariable:
    """require group "cn=$arg_team,<groups>": the request picks the group.

    The RDN used to reach the filter unescaped: ?team=* gave
    (&(cn=*)(member=...)) and a member of any group passed. libldap rejects
    the unbalanced filter of ?team=*)(|(cn=*, but nothing may depend on that.
    """

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        body = f"""
group_attribute member;
group_attribute_is_dn on;
require group "cn=$arg_team,{GROUPS_DN}";
"""
        return shared_nginx.start(http=ldap_server("team", body), server=protected_location("team"))

    @pytest.mark.parametrize(
        ("uid", "query", "expected"),
        [
            pytest.param("alice", "team=admins", 200, id="member"),
            pytest.param("carol", "team=admins", 401, id="not-a-member"),
            pytest.param("bob", "team=*", 401, id="wildcard-injection"),
            pytest.param("bob", "team=a*", 401, id="partial-wildcard-injection"),
            pytest.param("carol", "team=*)(|(cn=*", 401, id="filter-injection"),
        ],
    )
    def test_access(self, server, uid, query, expected):
        assert get_raw(server, f"/?{query}", uid) == expected


class TestGroupAttributeIsDnOff:
    """group_attribute_is_dn on, then off: the last value wins and the login is searched."""

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        body = f"""
group_attribute memberUid;
group_attribute_is_dn on;
group_attribute_is_dn off;
require group "{group_dn("posix-staff")}";
"""
        return shared_nginx.start(http=ldap_server("posix", body), server=protected_location("posix"))

    @pytest.mark.parametrize(
        ("uid", "expected"),
        [
            pytest.param("alice", 200, id="member-by-login"),
            pytest.param("bob", 401, id="not-a-member"),
        ],
    )
    def test_access(self, server, uid, expected):
        assert server.get(auth=creds(uid)).status_code == expected


@pytest.mark.parametrize(
    ("body", "log_text"),
    [
        # Debug builds crashed here: a NULL u_char * was logged with %V (nal-5br.13).
        pytest.param(
            f'require group "{group_dn("admins")}";',
            None,
            id="no-group-attribute",
        ),
        pytest.param(
            'group_attribute member;\ngroup_attribute_is_dn on;\nrequire group "admins";',
            'Incorrect group DN: "admins"',
            id="group-dn-without-parent",
        ),
        pytest.param(
            'group_attribute member;\ngroup_attribute_is_dn on;\nrequire group "cn=admins,ou=nowhere,dc=example,dc=org";',
            # The search fails with 32 (No such object), but no entry was found
            # either, and that check comes first.
            "ldap_search_ext() returned NULL result",
            id="group-under-missing-base",
        ),
    ],
)
def test_misconfigured_group_denies_even_members(nginx, body, log_text):
    server = nginx.start(http=ldap_server("groups", body), server=protected_location("groups"))

    assert server.get(auth=creds("alice")).status_code == 401
    if log_text is not None:
        assert log_text in server.log()
