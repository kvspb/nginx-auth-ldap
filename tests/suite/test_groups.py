"""Group membership requirements ("require group") and "satisfy" modes.

Fixture users: alice (admins, devs), bob (devs, ops), carol (no group),
dave (admins, ops).
"""

import pytest

from conftest import ldap_server, protected_location
from ldapdata import creds, group_dn


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


@pytest.mark.parametrize(
    ("body", "log_text"),
    [
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
