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
    assert response.headers["WWW-Authenticate"] == 'Basic realm="Restricted"'
    assert '"auth_ldap" requires one or more "auth_ldap_servers"' in server.log()
