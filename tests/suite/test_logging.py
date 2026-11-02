"""Failed logins are logged with the login, the server and the reason, never
the password (kvspb#171), one line each, so that tools such as fail2ban can
act on them; nginx adds the client address to every line."""

from __future__ import annotations

import base64

import pytest

from conftest import ldap_server, protected_location
from ldapdata import creds, group_dn, password, user_dn

CACHE = "auth_ldap_cache_enabled on;\nauth_ldap_cache_expiration_time 1h;\n"


def basic(login: str, secret: str) -> dict[str, str]:
    token = base64.b64encode(f"{login}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


class TestFailedLogins:
    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        groups = f'group_attribute member;\ngroup_attribute_is_dn on;\nrequire group "{group_dn("admins")}";'
        http = (
            CACHE
            + ldap_server("users")
            + ldap_server("admins", groups)
            + ldap_server("only_alice", f'satisfy all;\nrequire user "{user_dn("alice")}";')
            + ldap_server("all_groups", "satisfy all;\n" + groups)
        )
        locations = (
            protected_location("users", "/users/")
            + protected_location("admins", "/admins/")
            + protected_location("only_alice", "/alice/")
            + protected_location("all_groups", "/all-groups/")
        )
        return shared_nginx.start(http=http, server=locations)

    @pytest.mark.parametrize(
        ("path", "login", "secret", "line"),
        [
            pytest.param(
                "/users/",
                "alice",
                "Wrong-1",
                'User bind failed for "alice" on server "users" (49: Invalid credentials)',
                id="wrong-password",
            ),
            pytest.param(
                "/users/",
                "mallory",
                "x",
                'Could not find user DN for "mallory" on server "users"',
                id="unknown-user",
            ),
            pytest.param(
                "/admins/",
                "bob",
                password("bob"),
                'User "bob" does not meet the requirements of server "admins"',
                id="not-in-the-group",
            ),
            pytest.param(
                "/alice/",
                "bob",
                password("bob"),
                'User "bob" does not meet the requirements of server "only_alice"',
                id="not-the-required-user",
            ),
            pytest.param(
                "/all-groups/",
                "bob",
                password("bob"),
                'User "bob" does not meet the requirements of server "all_groups"',
                id="satisfy-all-groups",
            ),
            # Control characters, quotes and backslashes cannot forge a line,
            # also at the start of the login.
            pytest.param(
                "/users/",
                '"\\\x01',
                "x",
                'Could not find user DN for "\\x22\\x5c\\x01" on server "users"',
                id="escaped-at-the-start",
            ),
            # Control characters, quotes and backslashes cannot forge a line.
            pytest.param(
                "/users/",
                'eve\n2026/11/01 [error] "x\\',
                "x",
                'Could not find user DN for "eve\\x0a2026/11/01 [error] \\x22x\\x5c" on server "users"',
                id="escaped",
            ),
        ],
    )
    def test_reason_is_logged(self, server, path, login, secret, line):
        since = server.log_size()

        assert server.get(path, headers=basic(login, secret)).status_code == 401

        log = server.log(since)
        assert line in log
        assert "client: 127.0.0.1" in next(entry for entry in log.splitlines() if line in entry)
        if secret != "x":
            assert secret not in log

    def test_cached_denial_is_logged(self, server):
        server.get("/users/", auth=("alice", "Wrong-2"))
        since = server.log_size()

        assert server.get("/users/", auth=("alice", "Wrong-2")).status_code == 401
        assert 'User "alice" denied by the cache of server "users"' in server.log(since)

    def test_success_is_not_logged(self, server):
        since = server.log_size()

        assert server.get("/users/", auth=creds("carol")).status_code == 200
        # Debug builds log the login of every request at the debug level.
        lines = [line for line in server.log(since).splitlines() if "[debug]" not in line]
        assert not [line for line in lines if "carol" in line]
