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
    """satisfy all; require group admins; require group ops."""

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        return groups_server(shared_nginx, "all", "admins", "ops")

    @pytest.mark.parametrize(
        ("uid", "expected"),
        [
            pytest.param("dave", 200, id="both-groups"),
            pytest.param("bob", 401, id="second-group-only"),
            pytest.param(
                "alice",
                401,
                id="first-group-only",
                marks=pytest.mark.xfail(
                    reason="ctx->dn keeps the DN found for the previous group, so membership in the "
                    "first group satisfies every later one (#194, #225, #240)"
                ),
            ),
        ],
    )
    def test_access(self, server, uid, expected):
        assert server.get(auth=creds(uid)).status_code == expected
