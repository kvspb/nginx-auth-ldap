"""user_filter: find the user by a filter template instead of one attribute.

The attribute of the url was the only way to find a user, and only the
first one of a list was used (kvspb#90). user_filter takes a filter in
which $remote_user stands for the login, escaped as a filter value
(RFC 4515), so that users can log in by one of several attributes.
"""

from __future__ import annotations

import pytest

from conftest import ldap_server, protected_location
from ldapdata import LDAP_HOST, PEOPLE_DN, creds, password

BY_UID_OR_MAIL = 'user_filter "(|(uid=$remote_user)(mail=$remote_user))";'
NO_ATTRIBUTE_URL = f"ldap://{LDAP_HOST}:389/{PEOPLE_DN}??sub?(objectClass=inetOrgPerson)"


class TestUserFilter:
    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        http = (
            ldap_server("either", f"require valid_user;\n{BY_UID_OR_MAIL}")
            + ldap_server("braces", 'require valid_user;\nuser_filter "(mail=${remote_user})";')
            # The filter of the url still applies to every user.
            + ldap_server(
                "not_carol",
                'require valid_user;\nuser_filter "(uid=$remote_user)";',
                url=f"ldap://{LDAP_HOST}:389/{PEOPLE_DN}?uid?sub?(!(uid=carol))",
            )
            + ldap_server("no_attribute", f"require valid_user;\n{BY_UID_OR_MAIL}", url=NO_ATTRIBUTE_URL)
        )
        locations = (
            protected_location("either", "/either/")
            + protected_location("braces", "/braces/")
            + protected_location("not_carol", "/not-carol/")
            + protected_location("no_attribute", "/no-attribute/")
        )
        return shared_nginx.start(http=http, server=locations)

    @pytest.mark.parametrize(
        ("path", "auth", "status"),
        [
            pytest.param("/either/", creds("alice"), 200, id="by-uid"),
            pytest.param("/either/", ("castle@example.org", password("frank")), 200, id="by-second-mail"),
            pytest.param("/either/", ("frank@example.org", "wrong"), 401, id="wrong-password"),
            pytest.param("/either/", ("nobody@example.org", "x"), 401, id="unknown"),
            # uid=frank and the mail "frank" of grace: ambiguous, never picked.
            pytest.param("/either/", creds("frank"), 401, id="two-entries"),
            pytest.param("/braces/", ("frank@example.org", password("frank")), 200, id="braces"),
            pytest.param("/braces/", creds("alice"), 401, id="braces-no-uid"),
            pytest.param("/not-carol/", creds("alice"), 200, id="url-filter-allows"),
            pytest.param("/not-carol/", creds("carol"), 401, id="url-filter-denies"),
            pytest.param(
                "/no-attribute/", ("frank@example.org", password("frank")), 200, id="url-without-attribute"
            ),
        ],
    )
    def test_login(self, server, path, auth, status):
        assert server.get(path, auth=auth).status_code == status

    @pytest.mark.parametrize(
        "login",
        [
            pytest.param("*", id="wildcard"),
            pytest.param("frank@example.org)(uid=*", id="close-and-or"),
            pytest.param("*)(|(mail=*", id="nested"),
        ],
    )
    def test_login_cannot_change_the_filter(self, server, login):
        assert server.get("/either/", auth=(login, password("frank"))).status_code == 401

    def test_ambiguous_login_is_logged(self, server):
        since = server.log_size()
        server.get("/either/", auth=creds("frank"))

        assert 'User search for "frank" returned more than one entry' in server.log(since)


@pytest.mark.parametrize(
    ("body", "url", "text"),
    [
        pytest.param('user_filter "(uid=alice)";', None, "does not use $remote_user", id="no-remote-user"),
        pytest.param('user_filter "(uid=$remote_user";', None, "Invalid user_filter", id="unbalanced"),
        pytest.param('user_filter "uid=$remote_user";', None, "Invalid user_filter", id="no-parentheses"),
        pytest.param(
            'user_filter "(&(uid=$remote_user)(host=$host))";',
            None,
            'only "$remote_user"',
            id="other-variable",
        ),
        pytest.param(
            'user_filter "(uid=$remote_users)";', None, 'only "$remote_user"', id="longer-variable-name"
        ),
        pytest.param(
            'user_filter "(uid=$remote_user)";\nuser_filter "(mail=$remote_user)";',
            None,
            '"user_filter" is duplicate',
            id="duplicate",
        ),
        pytest.param(
            f'user_filter "(uid=$remote_user)";\nrequire valid_user "uid=$remote_user,{PEOPLE_DN}";',
            None,
            '"user_filter" and a "require valid_user" template',
            id="with-dn-template",
        ),
        pytest.param(
            "require valid_user;",
            NO_ATTRIBUTE_URL,
            'No user attribute specified in url of ldap_server "users"',
            id="no-attribute-without-user-filter",
        ),
    ],
)
def test_invalid_user_filter(nginx, body, url, text):
    http = ldap_server("users", body, **({"url": url} if url else {}))
    result = nginx.check_config(http=http, server=protected_location("users"))

    assert result.returncode == 1, result.stderr
    assert text in result.stderr


@pytest.mark.parametrize("next_char", list("azAZ09_"))
def test_longer_variable_name_is_not_remote_user(nginx, next_char):
    http = ldap_server("users", f'user_filter "(uid=$remote_user{next_char})";')
    result = nginx.check_config(http=http, server=protected_location("users"))

    assert result.returncode == 1, result.stderr
    assert 'only "$remote_user"' in result.stderr


@pytest.mark.parametrize("next_char", list("`{@[/:*"))
def test_remote_user_ends_before_other_characters(nginx, next_char):
    http = ldap_server("users", f'user_filter "(uid=$remote_user{next_char})";')
    result = nginx.check_config(http=http, server=protected_location("users"))

    assert result.returncode == 0, result.stderr


def test_long_url_filter_with_user_filter(nginx):
    # The filter of the url is copied in whole (and checked by
    # AddressSanitizer builds).
    long_filter = "(&(objectClass=inetOrgPerson)" + "(!(uid=nobody-at-all))" * 8 + ")"
    url = f"ldap://{LDAP_HOST}:389/{PEOPLE_DN}??sub?{long_filter}"
    http = ldap_server("users", f"require valid_user;\n{BY_UID_OR_MAIL}", url=url)
    server = nginx.start(http=http, server=protected_location("users"))

    assert server.get(auth=("frank@example.org", password("frank"))).status_code == 200


def test_literal_dollar_is_written_as_an_escape(nginx):
    http = ldap_server("users", r'user_filter "(&(uid=$remote_user)(!(cn=a\24b)))";')
    result = nginx.check_config(http=http, server=protected_location("users"))

    assert result.returncode == 0, result.stderr


def test_several_url_attributes_without_user_filter_warn(nginx):
    # Only the first attribute of the url is the login: say so, as the
    # url reads as if every one of them were (kvspb#90).
    url = f"ldap://{LDAP_HOST}:389/{PEOPLE_DN}?uid,mail?sub?(objectClass=inetOrgPerson)"
    result = nginx.check_config(http=ldap_server("users", url=url), server=protected_location("users"))

    assert result.returncode == 0, result.stderr
    assert (
        'only "uid", the first attribute of the url of ldap_server "users", holds the login' in result.stderr
    )
