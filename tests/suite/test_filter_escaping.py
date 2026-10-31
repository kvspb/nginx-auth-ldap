"""Values placed into LDAP search filters must be escaped (RFC 4515).

Upstream: #618, #180, #224, CVE-2020-14013; unmerged fix in PR #239.
"""

import pytest

from conftest import ldap_server, protected_location
from ldapdata import group_dn, password

UNESCAPED = pytest.mark.xfail(
    reason="user and group filters are built without escaping (#618, #180, #224, CVE-2020-14013)"
)


class TestUserSearchFilter:
    """The login name from the Authorization header goes into the user search."""

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        return shared_nginx.start(http=ldap_server("users"), server=protected_location("users"))

    @pytest.mark.parametrize(
        ("auth", "expected"),
        [
            # "ali*" must be looked up literally; unescaped it matches uid=alice
            # and lets the caller authenticate with a name that does not exist.
            pytest.param(("ali*", password("alice")), 401, id="wildcard-matches-nobody", marks=UNESCAPED),
            pytest.param(("john(x)", password("john(x)")), 200, id="parentheses-in-login", marks=UNESCAPED),
        ],
    )
    def test_login_is_matched_literally(self, server, auth, expected):
        assert server.get(auth=auth).status_code == expected


class TestGroupFilter:
    """The user DN goes into the group search when group_attribute_is_dn is on."""

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        body = f"""
group_attribute member;
group_attribute_is_dn on;
require group "{group_dn("staff")}";
"""
        return shared_nginx.start(http=ldap_server("staff", body), server=protected_location("staff"))

    @UNESCAPED
    def test_escaped_comma_in_user_dn(self, server):
        # The user DN is "cn=Doe\, John,ou=people,..."; its backslash must be
        # escaped as \5c inside the group filter.
        assert server.get(auth=("jdoe", password("jdoe"))).status_code == 200
