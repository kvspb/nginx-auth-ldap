"""LDAP errors that say nothing about the credentials (kvspb#115, nal-5br.17).

A server that is busy, unavailable, over a limit, or a connection that
breaks, does not tell whether the password is right. Such a request is
answered with 503 Service Unavailable, the next server is tried, and
nothing is cached: once the directory works again the same credentials
get their real answer. Only answers about the credentials themselves
(invalid credentials, no such entry, inappropriate authentication,
unwilling to perform) deny with 401, and that DENY is cached.

A fake LDAP server gives the answers slapd cannot be made to give.
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest

from conftest import ldap_server, protected_location
from fakeldap import (
    BIND_RESPONSE,
    EXTENDED_RESPONSE,
    SEARCH_DONE,
    FakeLdapServer,
    ber,
    message,
    result,
    search_entry,
    string,
)
from harness import Nginx
from ldapdata import BIND_DN, GROUPS_DN, PEOPLE_DN, creds

CACHE = """
auth_ldap_cache_enabled on;
auth_ldap_cache_expiration_time 10000;
auth_ldap_cache_size 1000;
"""

TIMEOUTS = """
connect_timeout 1s;
bind_timeout 1s;
reconnect_timeout 200ms;
request_timeout 2s;
"""

# Result codes (RFC 4511, appendix A).
SUCCESS = 0
TIME_LIMIT_EXCEEDED = 3
ADMIN_LIMIT_EXCEEDED = 11
NO_SUCH_OBJECT = 32
INVALID_DN_SYNTAX = 34
INAPPROPRIATE_AUTHENTICATION = 48
INVALID_CREDENTIALS = 49
INSUFFICIENT_ACCESS_RIGHTS = 50
BUSY = 51
UNAVAILABLE = 52
UNWILLING_TO_PERFORM = 53
OTHER = 80

# Close the connection instead of answering.
DROP = None


class Directory(FakeLdapServer):
    """Finds alice under ou=people; the service bind always succeeds.

    ``user_bind``, ``search`` and ``group_search`` are the result codes of
    the user bind, the user search and the group search, or DROP.
    """

    def __init__(self) -> None:
        self.user_bind: int | None = SUCCESS
        self.search: int | None = SUCCESS
        self.group_search: int | None = SUCCESS
        super().__init__()

    def answer_bind(self, msgid: int, dn: str) -> bytes | None:
        code = SUCCESS if dn == BIND_DN else self.user_bind
        if code is None:
            return None
        return message(msgid, result(BIND_RESPONSE, code))

    def answer_search(self, msgid: int, base: str) -> bytes | None:
        # The user search starts at ou=people, a group search at the group.
        group = base.endswith(GROUPS_DN)
        code = self.group_search if group else self.search
        if code is None:
            return None
        entry = base if group else f"uid=alice,{PEOPLE_DN}"
        found = search_entry(msgid, entry) if code == SUCCESS else b""
        return found + message(msgid, result(SEARCH_DONE, code))


@pytest.fixture
def directory() -> Iterator[Directory]:
    directory = Directory()
    yield directory
    directory.close()


def start(nginx, *directories: Directory, body: str = "require valid_user;", cache: bool = True):
    http = CACHE if cache else ""
    names = []
    for index, directory in enumerate(directories):
        name = f"fake{index}"
        names.append(name)
        http += ldap_server(name, body + "\nconnections 1;" + TIMEOUTS, url=directory.url())
    return nginx.start(http=http, server=protected_location(" ".join(names)))


def status(server) -> int:
    return server.get(auth=creds("alice"), timeout=10).status_code


@pytest.mark.parametrize(
    "code",
    [
        pytest.param(INVALID_CREDENTIALS, id="invalid-credentials"),
        pytest.param(NO_SUCH_OBJECT, id="no-such-object"),
        pytest.param(INVALID_DN_SYNTAX, id="invalid-dn-syntax"),
        pytest.param(INAPPROPRIATE_AUTHENTICATION, id="inappropriate-authentication"),
        pytest.param(INSUFFICIENT_ACCESS_RIGHTS, id="insufficient-access-rights"),
        pytest.param(UNWILLING_TO_PERFORM, id="unwilling-to-perform"),
    ],
)
def test_answer_about_the_credentials_denies_and_is_cached(nginx, directory, code):
    server = start(nginx, directory)
    directory.user_bind = code

    assert status(server) == 401

    # The DENY is cached: the directory is not asked again.
    directory.user_bind = SUCCESS
    assert status(server) == 401


@pytest.mark.parametrize(
    "code",
    [
        pytest.param(BUSY, id="busy"),
        pytest.param(UNAVAILABLE, id="unavailable"),
        pytest.param(TIME_LIMIT_EXCEEDED, id="time-limit-exceeded"),
        pytest.param(ADMIN_LIMIT_EXCEEDED, id="admin-limit-exceeded"),
        pytest.param(OTHER, id="other"),
        pytest.param(DROP, id="connection-closed"),
    ],
)
def test_server_failure_during_the_user_bind_is_503_and_not_cached(nginx, directory, code):
    server = start(nginx, directory)
    directory.user_bind = code

    assert status(server) == 503

    directory.user_bind = SUCCESS
    assert status(server) == 200


@pytest.mark.parametrize(
    "code",
    [
        pytest.param(BUSY, id="busy"),
        pytest.param(UNAVAILABLE, id="unavailable"),
        pytest.param(DROP, id="connection-closed"),
    ],
)
def test_server_failure_during_the_user_search_is_503(nginx, directory, code):
    server = start(nginx, directory)
    directory.search = code

    assert status(server) == 503

    directory.search = SUCCESS
    assert status(server) == 200


def test_search_that_finds_nobody_still_denies(nginx, directory):
    server = start(nginx, directory, cache=False)
    directory.search = NO_SUCH_OBJECT

    assert status(server) == 401


def test_next_server_decides_when_the_first_is_unavailable(nginx):
    first, second = Directory(), Directory()
    try:
        server = start(nginx, first, second)
        first.user_bind = UNAVAILABLE

        assert status(server) == 200
    finally:
        first.close()
        second.close()


def test_unavailable_server_is_not_hidden_by_a_deny_of_another(nginx):
    # The user may be known to the first server only: a DENY from the
    # second one is not the answer, the outage is.
    first, second = Directory(), Directory()
    try:
        server = start(nginx, first, second, cache=False)
        first.user_bind = UNAVAILABLE
        second.user_bind = INVALID_CREDENTIALS

        assert status(server) == 503
    finally:
        first.close()
        second.close()


REFERRAL = 10


class ReferringConnectionSetup(FakeLdapServer):
    """Answers the service bind and StartTLS with a referral."""

    def answer_bind(self, msgid: int, dn: str) -> bytes | None:
        return message(msgid, result(BIND_RESPONSE, REFERRAL, ber(0xA3, string("ldap://elsewhere.example/"))))

    def answer_extended(self, msgid: int) -> bytes | None:
        return message(
            msgid, result(EXTENDED_RESPONSE, REFERRAL, ber(0xA3, string("ldap://elsewhere.example/")))
        )


@pytest.mark.skipif(
    "-fsanitize=address" not in Nginx._configure_args(), reason="needs an AddressSanitizer build (SANITIZE=1)"
)
@pytest.mark.parametrize("starttls", [False, True], ids=["service-bind", "starttls"])
def test_referral_in_a_connection_setup_answer_is_freed(nginx, starttls):
    # The read handler returned from the StartTLS and the failed service
    # bind answers without freeing the referrals ldap_parse_result() gave
    # it: one leak per reconnect while the server refers elsewhere.
    fake = ReferringConnectionSetup()
    try:
        body = "require valid_user;\nreconnect_timeout 100ms;"
        if starttls:
            body += "\nstarttls on;\nssl_check_cert off;"
        nginx.env["ASAN_OPTIONS"] = f"detect_leaks=1:fast_unwind_on_malloc=0:log_path={nginx.prefix}/lsan"
        nginx.start(
            http=ldap_server("referring", body, url=fake.url()), server=protected_location("referring")
        )
        end = time.monotonic() + 3
        while fake.connections < 3 and time.monotonic() < end:
            time.sleep(0.05)
        assert fake.connections >= 3
        assert nginx.quit(timeout=10)
    finally:
        fake.close()

    reports = "".join(path.read_text() for path in nginx.prefix.glob("lsan*"))
    assert "ldap_parse_result" not in reports, reports


def test_server_failure_during_a_group_search_is_503(nginx, directory):
    body = f'group_attribute member;\ngroup_attribute_is_dn on;\nrequire group "cn=admins,{GROUPS_DN}";'
    server = start(nginx, directory, body=body, cache=False)
    assert status(server) == 200

    directory.group_search = BUSY
    assert status(server) == 503
