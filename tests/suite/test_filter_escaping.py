"""Values placed into LDAP search filters must be escaped (RFC 4515).

Regression tests for CVE-2020-14013 (kvspb#618, #180, #224; PR #239): the
login name and the user DN went into the filters verbatim, so a login could
inject filter syntax and legitimate names with special characters failed.
"""

import pytest

from conftest import ldap_server, protected_location
from ldapdata import group_dn, password


class TestUserSearchFilter:
    """The login name from the Authorization header goes into the user search."""

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        return shared_nginx.start(http=ldap_server("users"), server=protected_location("users"))

    @pytest.mark.parametrize(
        ("auth", "expected"),
        [
            # Unescaped, "ali*" matches uid=alice and the caller authenticates
            # under a name that does not exist.
            pytest.param(("ali*", password("alice")), 401, id="wildcard-matches-nobody"),
            # A special character in the first position must be counted too,
            # or the escaped value overflows its buffer.
            pytest.param(("*lice", password("alice")), 401, id="wildcard-at-the-start-matches-nobody"),
            # Unescaped, this closes the uid clause and adds one of its own.
            pytest.param(("alice)(uid=alice", password("alice")), 401, id="injected-filter-clause"),
            pytest.param(("john(x)", password("john(x)")), 200, id="parentheses-in-login"),
            pytest.param(("back\\slash", password("back\\slash")), 200, id="backslash-in-login"),
        ],
    )
    def test_login_is_matched_literally(self, server, auth, expected):
        assert server.get(auth=auth).status_code == expected


class TestGroupFilterByDn:
    """group_attribute_is_dn on: the user DN goes into the group search."""

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        body = f"""
group_attribute member;
group_attribute_is_dn on;
require group "{group_dn("staff")}";
"""
        return shared_nginx.start(http=ldap_server("staff", body), server=protected_location("staff"))

    @pytest.mark.parametrize(
        ("uid", "expected"),
        [
            # The user DN is "cn=Doe\, John,ou=people,..."; its backslash must
            # be escaped as \5c inside the group filter.
            pytest.param("jdoe", 200, id="escaped-comma-in-member-dn"),
            pytest.param("alice", 401, id="not-a-member"),
        ],
    )
    def test_access(self, server, uid, expected):
        assert server.get(auth=(uid, password(uid))).status_code == expected


class TestGroupFilterByLogin:
    """group_attribute_is_dn off: the login name goes into the group search."""

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        body = f"""
group_attribute memberUid;
require group "{group_dn("posix-staff")}";
"""
        return shared_nginx.start(http=ldap_server("posix", body), server=protected_location("posix"))

    @pytest.mark.parametrize(
        ("uid", "expected"),
        [
            pytest.param("alice", 200, id="plain-login"),
            pytest.param("john(x)", 200, id="parentheses-in-login"),
            pytest.param("bob", 401, id="not-a-member"),
        ],
    )
    def test_access(self, server, uid, expected):
        assert server.get(auth=(uid, password(uid))).status_code == expected
