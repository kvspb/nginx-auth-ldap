"""Interaction with nginx core "satisfy any" and other access modules."""

import pytest

from conftest import ldap_server, protected_location
from harness import nginx_version
from ldapdata import creds

# glibc fills fresh allocations with this byte, so fields the module leaves
# uninitialised hold garbage instead of the zeroes a new page usually has.
POISON = {"MALLOC_PERTURB_": "165"}

ALLOW_LOCAL = """
satisfy any;
allow 127.0.0.1;
deny all;
"""


@pytest.mark.xfail(
    nginx_version() >= (1, 23, 0),
    reason="WWW-Authenticate is pushed without initialising ->next; with satisfy any the "
    "core walks that list once another access module allows the request (#249)",
)
def test_satisfy_any_with_allow_lets_local_clients_in(nginx):
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
