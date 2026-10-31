"""ldap_server options that change how connections are used."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import ldap_server, protected_location
from ldapdata import creds

UIDS = ["alice", "bob", "carol", "dave"] * 4


@pytest.mark.parametrize("referral", ["on", "off"])
def test_referral_setting_keeps_authentication_working(nginx, referral):
    body = f"require valid_user;\nreferral {referral};"
    server = nginx.start(http=ldap_server("users", body), server=protected_location("users"))

    assert server.get(auth=creds("alice")).status_code == 200


def test_one_connection_serves_concurrent_requests_in_turn(nginx):
    # With a single pooled connection the other requests wait in the queue and
    # are woken one after another as the connection is returned.
    body = "require valid_user;\nconnections 1;"
    server = nginx.start(http=ldap_server("users", body), server=protected_location("users"))

    with ThreadPoolExecutor(max_workers=len(UIDS)) as pool:
        statuses = list(pool.map(lambda uid: server.get(auth=creds(uid)).status_code, UIDS))

    assert statuses == [200] * len(UIDS)


def test_max_down_retries_is_accepted(nginx):
    body = "require valid_user;\nmax_down_retries 2;"
    server = nginx.start(http=ldap_server("users", body), server=protected_location("users"))

    assert server.get(auth=creds("alice")).status_code == 200
