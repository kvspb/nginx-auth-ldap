"""$ldap_user_dn and $ldap_attr_<name>: the user entry as nginx variables.

Applications behind nginx asked for the display name and the e-mail
address of the user (kvspb#173), or for another attribute than the login,
such as the uid of a user who logged in with a mail address (kvspb#59).
user_attributes in an ldap_server block names the attributes that the
user search fetches; once LDAP allowed the request, $ldap_attr_<name>
holds the first value of each and $ldap_user_dn the DN of the user.
"""

from __future__ import annotations

import pytest
import requests

from conftest import ldap_server, protected_location
from ldapdata import PEOPLE_DN, changed_password, creds, password, user_dn

ATTRIBUTES = "require valid_user;\nuser_attributes displayName description title mail;"
CACHE = """
auth_ldap_cache_enabled on;
auth_ldap_cache_expiration_time 10000;
auth_ldap_cache_size 1000;
"""

# $early is set in the rewrite phase, before the access phase: the value
# of a variable read that early must not stick to the request.
HEADERS = """
set $early "[$ldap_attr_mail]";
add_header X-DN $ldap_user_dn always;
add_header X-Mail $ldap_attr_mail always;
add_header X-Name $ldap_attr_DisplayName always;
add_header X-Desc $ldap_attr_description always;
add_header X-Title $ldap_attr_title always;
add_header X-Sn $ldap_attr_sn always;
add_header X-Early $early always;
"""


def headers(response: requests.Response) -> dict[str, str]:
    names = ("X-DN", "X-Mail", "X-Name", "X-Desc", "X-Title", "X-Sn")
    return {name: response.headers[name] for name in names if name in response.headers}


class TestUserAttributes:
    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        http = (
            ldap_server("attrs", ATTRIBUTES)
            + ldap_server("template", f'require valid_user "uid=$remote_user,{PEOPLE_DN}";')
            # Finds frank and checks his password, but admits only alice.
            + ldap_server(
                "only_alice", f'satisfy all;\nrequire user "{user_dn("alice")}";\nuser_attributes mail;'
            )
            + ldap_server("names", "require valid_user;\nuser_attributes displayName;")
        )
        locations = (
            protected_location("attrs", "/attrs/", HEADERS)
            + protected_location("template", "/template/", HEADERS)
            + protected_location("only_alice names", "/two/", HEADERS)
            + f"""
location /off/ {{
    auth_ldap off;
    {HEADERS}
    root html;
    try_files /ok =404;
}}

location = /page.shtml {{
    auth_ldap "Restricted";
    auth_ldap_servers attrs;
    ssi on;
    default_type text/html;
    root html;
}}

location = /part {{
    return 200 "[$ldap_attr_mail]";
}}
"""
        )
        instance = shared_nginx.start(http=http, server=locations)
        (shared_nginx.prefix / "html" / "page.shtml").write_text('<!--# include virtual="/part" -->')
        return instance

    def test_attributes_of_the_user(self, server):
        response = server.get("/attrs/", auth=creds("frank"))

        assert response.status_code == 200
        # The first mail value; sn is in the entry but not in user_attributes.
        assert headers(response) == {
            "X-DN": user_dn("frank"),
            "X-Mail": "frank@example.org",
            "X-Name": "Frank Castle",
        }
        assert response.headers["X-Early"] == "[]"

    def test_entry_without_the_attributes(self, server):
        response = server.get("/attrs/", auth=creds("alice"))

        assert response.status_code == 200
        assert headers(response) == {"X-DN": user_dn("alice")}

    def test_control_characters_cannot_add_a_header(self, server):
        response = server.get("/attrs/", auth=creds("grace"))

        assert response.status_code == 200
        assert response.headers["X-Desc"] == "Grace\\x0d\\x0aX-Injected: yes"
        assert response.headers["X-Title"] == "\\x01first"
        assert "X-Injected" not in response.headers

    @pytest.mark.parametrize(
        ("path", "auth", "status"),
        [
            pytest.param("/attrs/", ("frank", "wrong"), 401, id="wrong-password"),
            pytest.param("/attrs/", None, 401, id="no-credentials"),
            pytest.param("/off/", creds("frank"), 200, id="auth-ldap-off"),
        ],
    )
    def test_nothing_without_an_ldap_allow(self, server, path, auth, status):
        response = server.get(path, auth=auth)

        assert response.status_code == status
        assert headers(response) == {}

    def test_dn_built_from_a_template(self, server):
        response = server.get("/template/", auth=creds("frank"))

        assert response.status_code == 200
        assert headers(response) == {"X-DN": user_dn("frank")}

    def test_attributes_of_the_server_that_allowed(self, server):
        # only_alice finds frank and fetches his mail, then denies him;
        # names allows him: only its attributes are his variables.
        response = server.get("/two/", auth=creds("frank"))

        assert response.status_code == 200
        assert headers(response) == {"X-DN": user_dn("frank"), "X-Name": "Frank Castle"}

    def test_subrequest_sees_the_attributes_of_the_main_request(self, server):
        response = server.get("/page.shtml", auth=creds("frank"))

        assert response.status_code == 200
        assert response.text == "[frank@example.org]"


def test_cached_allow_keeps_the_attributes(nginx):
    server = nginx.start(
        http=CACHE + ldap_server("attrs", ATTRIBUTES), server=protected_location("attrs", extra=HEADERS)
    )
    expected = {"X-DN": user_dn("erin"), "X-Mail": "erin@example.org"}
    assert headers(server.get(auth=creds("erin"))) == expected

    # The directory no longer takes the old password: only the cache does.
    with changed_password("erin", "erin-new-" + "secret"):
        response = server.get(auth=creds("erin"))

    assert response.status_code == 200
    assert headers(response) == expected


def test_cached_allow_of_another_server_brings_its_attributes(nginx):
    # kvspb#201: an allow cached by any server of the location is used.
    http = CACHE + ldap_server("attrs", ATTRIBUTES) + ldap_server("plain")
    locations = protected_location("attrs", "/attrs/", HEADERS) + protected_location(
        "plain attrs", "/both/", HEADERS
    )
    server = nginx.start(http=http, server=locations)
    assert server.get("/attrs/", auth=creds("frank")).status_code == 200

    response = server.get("/both/", auth=creds("frank"))

    assert response.status_code == 200
    assert headers(response)["X-Mail"] == "frank@example.org"


def test_cached_allow_of_a_server_without_user_attributes(nginx):
    server = nginx.start(http=CACHE + ldap_server("plain"), server=protected_location("plain", extra=HEADERS))

    for _ in range(2):
        response = server.get(auth=creds("frank"))
        assert response.status_code == 200
        assert headers(response) == {"X-DN": user_dn("frank")}


def test_allow_pushed_out_of_the_cache(nginx):
    # A bucket holds eight entries of one login: eight denies with other
    # passwords push the allow out, and its attributes are freed.
    server = nginx.start(
        http=CACHE + ldap_server("attrs", ATTRIBUTES), server=protected_location("attrs", extra=HEADERS)
    )
    assert server.get(auth=creds("frank")).status_code == 200

    for i in range(8):
        response = server.get(auth=("frank", f"wrong-{i}"))
        assert response.status_code == 401
        assert headers(response) == {}

    assert headers(server.get(auth=creds("frank")))["X-Mail"] == "frank@example.org"


@pytest.mark.parametrize("cache", ["", CACHE], ids=["variable", "cache"])
def test_attributes_of_a_denying_server_are_not_kept_for_a_dn_template(nginx, cache):
    # only_alice finds frank and fetches his mail, then denies him; template
    # allows him without a search and has no user_attributes. The values of
    # only_alice stayed in the request, and both the variable and the cache
    # entry of the allow read them by the attribute names of template: a
    # NULL pointer, the worker crashed.
    http = (
        cache
        + ldap_server(
            "only_alice", f'satisfy all;\nrequire user "{user_dn("alice")}";\nuser_attributes mail;'
        )
        + ldap_server("template", f'require valid_user "uid=$remote_user,{PEOPLE_DN}";')
    )
    server = nginx.start(http=http, server=protected_location("only_alice template", extra=HEADERS))

    for _ in range(2):
        response = server.get(auth=creds("frank"))
        assert response.status_code == 200
        assert headers(response) == {"X-DN": user_dn("frank")}


@pytest.mark.parametrize(
    ("body", "text"),
    [
        pytest.param(
            f'require valid_user "uid=$remote_user,{PEOPLE_DN}";\nuser_attributes mail;',
            '"user_attributes" need the user search',
            id="with-dn-template",
        ),
        pytest.param(
            "user_attributes mail;\nuser_attributes cn;", '"user_attributes" is duplicate', id="duplicate"
        ),
        pytest.param(
            "user_attributes msDS-PrincipalName;", 'invalid attribute name "msDS-PrincipalName"', id="hyphen"
        ),
        pytest.param("user_attributes 2.5.4.3;", 'invalid attribute name "2.5.4.3"', id="oid"),
        pytest.param("user_attributes 2cn;", 'invalid attribute name "2cn"', id="digit-first"),
        pytest.param("user_attributes;", 'invalid number of arguments in "user_attributes"', id="no-name"),
        *[
            pytest.param(f'user_attributes "a{c}";', f'invalid attribute name "a{c}"', id=f"char-{c}")
            for c in "`{@[/:"
        ],
        pytest.param('user_attributes "cn;lang-en";', 'invalid attribute name "cn;lang-en"', id="option"),
    ],
)
def test_invalid_user_attributes(nginx, body, text):
    result = nginx.check_config(http=ldap_server("users", body), server=protected_location("users"))

    assert result.returncode == 1, result.stderr
    assert text in result.stderr


@pytest.mark.parametrize("names", ["az AZ", "a09 Z9"])
def test_valid_user_attributes(nginx, names):
    result = nginx.check_config(
        http=ldap_server("users", f"user_attributes {names};"), server=protected_location("users")
    )

    assert result.returncode == 0, result.stderr


def test_login_by_mail_and_uid_as_a_variable(nginx):
    # kvspb#59: log in with the e-mail address, pass the uid on.
    body = 'require valid_user;\nuser_filter "(mail=$remote_user)";\nuser_attributes uid;'
    server = nginx.start(
        http=ldap_server("users", body),
        server=protected_location("users", extra="add_header X-Uid $ldap_attr_uid;"),
    )

    response = server.get(auth=("frank@example.org", password("frank")))

    assert response.status_code == 200
    assert response.headers["X-Uid"] == "frank"
