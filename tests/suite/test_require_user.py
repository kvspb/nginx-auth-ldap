"""User requirements: "require user <dn>" and "require valid_user <dn template>"."""

import base64

import pytest

from conftest import ldap_server, protected_location
from ldapdata import NESTED_UID, PEOPLE_DN, creds, password, user_dn


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


@pytest.mark.parametrize(
    ("dn", "alice"),
    [
        pytest.param(f"UID=alice,{PEOPLE_DN.upper()}", 200, id="other-case"),
        pytest.param("uid=alice, ou=people, dc=example, dc=org", 200, id="spaces-after-commas"),
        pytest.param("uid=alice+cn=nobody,ou=people,dc=example,dc=org", 401, id="multi-valued-rdn"),
        pytest.param("uid=alicex,ou=people,dc=example,dc=org", 401, id="longer-value"),
    ],
)
def test_require_user_dn_is_compared_as_a_dn(nginx, dn, alice):
    # DNs are equal when they name the same entry, not when their text is
    # equal (RFC 4514; kvspb#3, nal-toj.8).
    server = users_server(nginx, "all", dns=(dn,))

    assert server.get(auth=creds("alice")).status_code == alice
    assert server.get(auth=creds("bob")).status_code == 401


class TestValidUserDnTemplate:
    """require valid_user "<dn>": bind with a DN built from the login, no search.

    Regression for nal-5br.12: the evaluated template was passed to
    ldap_sasl_bind() without a NUL terminator (heap over-read under ASan,
    wrong DN and 401 for valid users without it).
    """

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        body = f'require valid_user "uid=$remote_user,{PEOPLE_DN}";'
        return shared_nginx.start(http=ldap_server("template", body), server=protected_location("template"))

    @pytest.mark.parametrize(
        ("auth", "expected"),
        [
            pytest.param(creds("alice"), 200, id="valid-credentials"),
            pytest.param(("alice", "not-the-password"), 401, id="wrong-password"),
            pytest.param(("mallory", "mallory-secret"), 401, id="unknown-user"),
            # jdoe exists, but under cn=..., so the template DN does not.
            pytest.param(creds("jdoe"), 401, id="dn-outside-the-template"),
        ],
    )
    def test_access(self, server, auth, expected):
        assert server.get(auth=auth).status_code == expected


def basic(login: str, secret: str) -> dict[str, str]:
    """A raw Authorization header, so that the login may hold any byte."""
    token = base64.b64encode(f"{login}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


class TestValidUserDnTemplateLoginIsAnRdnValue:
    """The login fills one RDN value of the template, never more of the DN.

    A NUL used to cut the DN where ldap_sasl_bind() read it, and DN
    metacharacters in the login changed its structure, so a user could bind
    as an entry outside the template (FIX-04).
    """

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        body = f'require valid_user "uid=$remote_user,{PEOPLE_DN}";'
        return shared_nginx.start(http=ldap_server("rdn", body), server=protected_location("rdn"))

    @pytest.mark.parametrize(
        ("login", "secret", "expected"),
        [
            pytest.param("alice", password("alice"), 200, id="plain-login"),
            pytest.param(f"alice,{PEOPLE_DN}\x00x", password("alice"), 401, id="nul-cuts-the-suffix"),
            pytest.param(f"{NESTED_UID},ou=services", password(NESTED_UID), 401, id="comma-adds-an-rdn"),
            # A backslash is a literal character of the uid, not a DN escape.
            pytest.param("back\\slash", password("back\\slash"), 200, id="backslash-is-literal"),
            # A leading '#' would start a hex-encoded (BER) value.
            pytest.param("#hash", password("#hash"), 200, id="leading-hash-is-literal"),
        ],
    )
    def test_access(self, server, login, secret, expected):
        assert server.get(headers=basic(login, secret)).status_code == expected

    def test_login_with_nul_is_rejected(self, server):
        # The DN would be cut at the NUL, whatever the escaping: reject it.
        since = server.log_size()

        assert server.get(headers=basic("\x00alice", password("alice"))).status_code == 401
        assert "http_auth_ldap: Login with a NUL byte rejected" in server.log(since)


class TestValidUserDnTemplateWithDerivedVariables:
    """A variable copied from $remote_user is not escaped like it.

    "set" copies the raw login in the rewrite phase, before the module
    escapes $remote_user, and "map" may have been evaluated before too. So
    the module checks the shape of the DN it built: it must have the RDNs
    and attribute-value pairs of the template, whatever the variables hold
    (audit V-03).
    """

    @pytest.fixture(scope="class", params=["set", "map"])
    def server(self, request, shared_nginx):
        body = f'require valid_user "uid=$login,{PEOPLE_DN}";'
        http = ldap_server("derived", body)
        extra = ""
        if request.param == "set":
            extra = "set $login $remote_user;"
        else:
            http += "map $remote_user $login { default $remote_user; }\n"
            # Evaluated before the access phase, as by a rewrite rule.
            extra = 'if ($login = "-") { return 403; }'
        return shared_nginx.start(http=http, server=protected_location("derived", extra=extra))

    @pytest.mark.parametrize(
        ("login", "secret", "expected", "rejected"),
        [
            pytest.param("alice", password("alice"), 200, False, id="plain-login"),
            pytest.param(f"{NESTED_UID},ou=services", password(NESTED_UID), 401, True, id="comma-adds-an-rdn"),
            pytest.param(f"{NESTED_UID}+cn=x", password(NESTED_UID), 401, True, id="plus-adds-an-ava"),
            # An escaped comma is part of the value: the shape is kept.
            pytest.param("no\\,such", "x", 401, False, id="escaped-comma"),
            pytest.param(f"alice,{PEOPLE_DN}\x00x", password("alice"), 401, False, id="nul-cuts-the-suffix"),
        ],
    )
    def test_access(self, server, login, secret, expected, rejected):
        since = server.log_size()

        assert server.get(headers=basic(login, secret)).status_code == expected
        assert ("does not have the RDNs of the template" in server.log(since)) is rejected

    def test_template_that_is_a_whole_variable_is_not_checked(self, nginx):
        # A DN taken whole from a variable has no shape to keep.
        http = ldap_server("whole", 'require valid_user "$dn";')
        http += f"map $remote_user $dn {{ default uid=$remote_user,{PEOPLE_DN}; }}\n"
        server = nginx.start(http=http, server=protected_location("whole"))

        assert server.get(auth=creds("alice")).status_code == 200
