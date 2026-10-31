"""User requirements: "require user <dn>" and "require valid_user <dn template>"."""

import pytest

from conftest import ldap_server, protected_location
from ldapdata import PEOPLE_DN, creds, user_dn


def users_server(nginx, satisfy: str, *uids: str, dns: tuple[str, ...] = ()):
    requires = [f'require user "{user_dn(uid)}";' for uid in uids]
    requires += [f'require user "{dn}";' for dn in dns]
    body = f"satisfy {satisfy};\n" + "\n".join(requires)
    return nginx.start(http=ldap_server("users", body), server=protected_location("users"))


class TestSatisfyAnyOfTwoUsers:
    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        return users_server(shared_nginx, "any", "alice", "bob")

    @pytest.mark.parametrize(
        ("auth", "expected"),
        [
            pytest.param(creds("alice"), 200, id="first-user"),
            pytest.param(creds("bob"), 200, id="second-user"),
            pytest.param(creds("carol"), 401, id="other-valid-user"),
            pytest.param(("alice", "not-the-password"), 401, id="listed-user-wrong-password"),
        ],
    )
    def test_access(self, server, auth, expected):
        assert server.get(auth=auth).status_code == expected


class TestSatisfyAllOfOneUser:
    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        return users_server(shared_nginx, "all", "alice")

    @pytest.mark.parametrize(
        ("uid", "expected"),
        [
            pytest.param("alice", 200, id="listed-user"),
            pytest.param("bob", 401, id="other-valid-user"),
        ],
    )
    def test_access(self, server, uid, expected):
        assert server.get(auth=creds(uid)).status_code == expected


@pytest.mark.xfail(
    reason="require user compares DNs byte by byte, but DNs are case-insensitive (kvspb#3, nal-toj.8)"
)
def test_require_user_dn_is_compared_case_insensitively(nginx):
    server = users_server(nginx, "any", dns=(f"UID=alice,{PEOPLE_DN.upper()}",))

    assert server.get(auth=creds("alice")).status_code == 200
