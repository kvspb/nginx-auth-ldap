"""Subrequests of a request that was authenticated over LDAP.

A request that waits for LDAP is run again from the read handler of the
LDAP connection, not from an event of its own client connection. nginx
runs the subrequests a request posts (SSI includes, mirror, addition)
only after an event handler of the client connection: the module has to
run them itself, or the response stalls until the client sends something
(audit F09).
"""

from __future__ import annotations

from conftest import ldap_server
from ldapdata import creds

PAGE = 'before <!--# include virtual="/part" --> after\n'

LOCATIONS = """
location = /page.shtml {
    auth_ldap "Restricted";
    auth_ldap_servers users;
    ssi on;
    default_type text/html;
    root html;
}

location = /part {
    root html;
    default_type text/plain;
    try_files /ok =404;
}
"""


def test_ssi_include_after_ldap(nginx):
    server = nginx.start(http=ldap_server("users"), server=LOCATIONS)
    (nginx.prefix / "html" / "page.shtml").write_text(PAGE)

    response = server.get("/page.shtml", auth=creds("alice"), timeout=3)

    assert response.status_code == 200
    assert response.text == "before ok after\n"
