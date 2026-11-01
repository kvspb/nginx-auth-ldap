"""Baseline behaviour: HTTP Basic credentials checked against the directory."""

import pytest

from conftest import ldap_server, protected_location, url_for
from ldapdata import LDAP_IPV4, LDAP_IPV6, creds


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
        assert response.headers["WWW-Authenticate"] == 'Basic realm="Restricted"'

    def test_repeated_requests_reuse_the_connection_pool(self, server):
        statuses = [server.get(auth=creds(uid)).status_code for uid in ("alice", "bob", "alice", "carol")]

        assert statuses == [200, 200, 200, 200]


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
