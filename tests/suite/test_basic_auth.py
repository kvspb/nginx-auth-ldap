"""Baseline behaviour: HTTP Basic credentials checked against the directory."""

import base64

import pytest

from conftest import ldap_server, protected_location, url_for
from ldapdata import LDAP_IPV4, LDAP_IPV6, TWIN_OTHER_SECRET, TWIN_UID, UNICODE_UID, creds, password


class TestSingleServer:
    """One ldap_server with "require valid_user"."""

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        return shared_nginx.start(http=ldap_server("users"), server=protected_location("users"))

    def test_valid_credentials_are_accepted(self, server):
        response = server.get(auth=creds("alice"))

        assert response.status_code == 200
        assert response.text == "ok"

    @pytest.mark.parametrize(
        "auth",
        [
            pytest.param(("alice", "not-the-password"), id="wrong-password"),
            pytest.param(("mallory", "mallory-secret"), id="unknown-user"),
            # An empty password would turn the user bind into an unauthenticated
            # bind (RFC 4513, section 5.1.2), which LDAP servers report as success.
            pytest.param(("alice", ""), id="empty-password"),
        ],
    )
    def test_invalid_credentials_are_rejected(self, server, auth):
        assert server.get(auth=auth).status_code == 401

    def test_missing_credentials_get_a_basic_challenge(self, server):
        response = server.get()

        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == 'Basic realm="Restricted", charset="UTF-8"'

    def test_repeated_requests_reuse_the_connection_pool(self, server):
        statuses = [server.get(auth=creds(uid)).status_code for uid in ("alice", "bob", "alice", "carol")]

        assert statuses == [200, 200, 200, 200]


class TestAmbiguousUser:
    """A login whose search matches several entries is rejected, whichever password is given."""

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        return shared_nginx.start(http=ldap_server("ambiguous"), server=protected_location("ambiguous"))

    @pytest.mark.parametrize(
        "secret",
        [
            pytest.param(password(TWIN_UID), id="first-entry-password"),
            pytest.param(TWIN_OTHER_SECRET, id="second-entry-password"),
        ],
    )
    def test_login_matching_two_entries_is_rejected(self, server, secret):
        offset = server.log_size()

        assert server.get(auth=(TWIN_UID, secret)).status_code == 401
        assert "more than one entry" in server.log(offset)

    @pytest.mark.parametrize("uid", [pytest.param("bob", id="bob"), pytest.param("carol", id="carol")])
    def test_unique_login_is_accepted(self, server, uid):
        assert server.get(auth=creds(uid)).status_code == 200


@pytest.mark.parametrize(
    "host",
    [
        pytest.param(LDAP_IPV4, id="ipv4-address"),
        # An IPv6 address goes in brackets (RFC 3986, RFC 4516).
        pytest.param(f"[{LDAP_IPV6}]", id="ipv6-address"),
    ],
)
def test_server_given_by_address(nginx, host):
    server = nginx.start(
        http=ldap_server("byaddr", url=url_for(host, 389)), server=protected_location("byaddr")
    )

    assert server.get(auth=creds("alice")).status_code == 200
    assert server.get(auth=("alice", "wrong")).status_code == 401


def basic(login: str, secret: str, encoding: str) -> dict[str, str]:
    token = base64.b64encode(f"{login}:{secret}".encode(encoding)).decode()
    return {"Authorization": f"Basic {token}"}


class TestNonAsciiCredentials:
    """A login and password that are not ASCII (kvspb#145).

    LDAP strings are UTF-8, and the challenge asks the browser for UTF-8
    (RFC 7617, charset="UTF-8"). Credentials sent in ISO-8859-1, as old
    browsers did without that parameter, do not match.
    """

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        return shared_nginx.start(http=ldap_server("users"), server=protected_location("users"))

    @pytest.mark.parametrize(
        ("encoding", "expected"),
        [pytest.param("utf-8", 200, id="utf-8"), pytest.param("iso-8859-1", 401, id="iso-8859-1")],
    )
    def test_credentials(self, server, encoding, expected):
        assert server.get(headers=basic(UNICODE_UID, password(UNICODE_UID), encoding)).status_code == expected
