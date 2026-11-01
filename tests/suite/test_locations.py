"""Location-level directives: auth_ldap off, auth_ldap without servers."""

import pytest

from conftest import ldap_server, protected_location
from ldapdata import creds


class TestAuthLdapOff:
    """auth_ldap at server level, switched off for one location."""

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        locations = (
            protected_location("users", path="/")
            + """
location /public {
    auth_ldap off;
    root html;
    try_files /ok =404;
}
"""
        )
        return shared_nginx.start(http=ldap_server("users"), server=locations)

    def test_location_with_auth_ldap_off_needs_no_credentials(self, server):
        assert server.get("/public").status_code == 200

    def test_other_locations_stay_protected(self, server):
        assert server.get("/").status_code == 401
        assert server.get("/", auth=creds("alice")).status_code == 200


def test_auth_ldap_without_servers_rejects_and_logs(nginx):
    location = """
location / {
    auth_ldap "Restricted";
    root html;
    try_files /ok =404;
}
"""
    server = nginx.start(http=ldap_server("users"), server=location)

    response = server.get(auth=creds("alice"))

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == 'Basic realm="Restricted", charset="UTF-8"'
    assert '"auth_ldap" requires one or more "auth_ldap_servers"' in server.log()


class TestRealmWithVariables:
    """auth_ldap takes variables, and a value of "off" turns it off, as
    auth_basic does (kvspb#77, kvspb#238). A geo or map variable switches
    the check per client or per request without an "if" (PR #257)."""

    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        http = (
            ldap_server("users")
            + """
geo $ldap_realm {
    default "Restricted";
    127.0.0.1 off;
}
map $arg_zone $zone_realm {
    default "Zone $arg_zone";
    "" "Restricted";
    open off;
    quote 'Say "hi" \\\\ bye';
}
"""
        )
        locations = """
location / {
    auth_ldap $ldap_realm;
    auth_ldap_servers users;
    root html;
    try_files /ok =404;
}

location /zone {
    auth_ldap $zone_realm;
    auth_ldap_servers users;
    root html;
    try_files /ok =404;
}
"""
        return shared_nginx.start(http=http, server=locations)

    @pytest.mark.parametrize(
        ("query", "realm"),
        [
            pytest.param("", "Restricted", id="default"),
            pytest.param("?zone=a", "Zone a", id="from-a-variable"),
            # Quotes and backslashes are escaped in the quoted string (RFC 9110).
            pytest.param("?zone=quote", 'Say \\"hi\\" \\\\ bye', id="escaped"),
        ],
    )
    def test_realm_is_expanded(self, server, query, realm):
        response = server.get("/zone" + query)

        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == f'Basic realm="{realm}", charset="UTF-8"'

    def test_off_from_a_variable_turns_it_off(self, server):
        assert server.get("/zone?zone=open").status_code == 200

    def test_ldap_still_checks_when_on(self, server):
        assert server.get("/zone?zone=a", auth=creds("alice")).status_code == 200
        assert server.get("/zone?zone=a", auth=("alice", "wrong")).status_code == 401

    def test_geo_lets_a_network_in(self, server):
        # The suite talks to nginx from 127.0.0.1, which the geo block exempts.
        assert server.get("/").status_code == 200
