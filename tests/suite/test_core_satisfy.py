"""Interaction with nginx core "satisfy any" and other access modules."""

from conftest import ldap_server, protected_location
from ldapdata import creds

# glibc fills fresh allocations with this byte, so fields the module leaves
# uninitialised hold garbage instead of the zeroes a new page usually has.
POISON = {"MALLOC_PERTURB_": "165"}

ALLOW_LOCAL = """
satisfy any;
allow 127.0.0.1;
deny all;
"""


def test_satisfy_any_with_allow_lets_local_clients_in(nginx):
    # Regression for kvspb#249: on nginx >= 1.23 the core walks the
    # WWW-Authenticate list through ->next once another access module allows
    # the request, so the header pushed by the module must terminate it.
    nginx.env.update(POISON)
    server = nginx.start(http=ldap_server("users"), server=protected_location("users", extra=ALLOW_LOCAL))

    # No credentials: the module answers 401, then "allow" grants access.
    response = server.get()

    assert response.status_code == 200
    assert not server.crashes()


def test_satisfy_any_still_accepts_ldap_credentials(nginx):
    deny_everyone = "satisfy any;\ndeny all;"
    server = nginx.start(http=ldap_server("users"), server=protected_location("users", extra=deny_everyone))

    assert server.get(auth=creds("alice")).status_code == 200
