"""Referrals in search answers are never chased.

libldap chases a referral with a blocking connect() and its own socket,
outside the event loop of nginx: one answer that points to a host which
drops packets stalls the worker for every client, and nginx connects to any
host a server (or a man in the middle on ldap://) names. The module turns
referral chasing off whatever the ``referral`` setting says.
"""

from __future__ import annotations

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import TIMEOUTS, ldap_server, protected_location
from fakeldap import SEARCH_DONE, FakeLdapServer, ber, message, result, string
from ldapdata import PEOPLE_DN, creds

# Packets to this address are dropped: a connect() hangs until it times out.
BLACK_HOLE = "10.255.255.1"

UNPROTECTED = """
location /free {
    return 200 "free";
}
"""


class ReferringLdapServer(FakeLdapServer):
    """Binds succeed, every search answers with a referral.

    ``kind`` "reference" sends a SearchResultReference and then an empty
    successful SearchResultDone; "result" sends a SearchResultDone with the
    resultCode referral (10).
    """

    def __init__(self, referral_url: str, kind: str) -> None:
        self.referral_url = referral_url
        self.kind = kind
        self.referred = threading.Event()
        super().__init__()

    def answer_search(self, msgid: int, base: str) -> bytes:
        self.referred.set()
        if self.kind == "reference":
            reference = message(msgid, ber(0x73, string(self.referral_url)))
            return reference + message(msgid, result(SEARCH_DONE, 0))
        referral = ber(0xA3, string(self.referral_url))
        return message(msgid, result(SEARCH_DONE, 10, referral))


@pytest.fixture
def referring_server(request):
    servers: list[ReferringLdapServer] = []

    def make(referral_url: str, kind: str) -> ReferringLdapServer:
        server = ReferringLdapServer(referral_url, kind)
        servers.append(server)
        return server

    yield make
    for server in servers:
        server.close()


@pytest.mark.parametrize(
    "setting",
    [
        pytest.param("", id="default"),
        pytest.param("referral on;", id="referral-on"),
    ],
)
def test_referral_to_a_black_hole_does_not_stall_the_worker(nginx, referring_server, setting):
    ldap = referring_server(f"ldap://{BLACK_HOLE}/{PEOPLE_DN}??sub", "reference")
    body = f"require valid_user;\n{setting}\n{TIMEOUTS}"
    server = nginx.start(
        http=ldap_server("users", body, url=ldap.url()),
        server=protected_location("users") + UNPROTECTED,
    )

    with ThreadPoolExecutor(max_workers=1) as pool:
        protected = pool.submit(server.get, auth=creds("alice"), timeout=10)
        assert ldap.referred.wait(5), "the module never searched"
        # Give the worker time to read the reference (and chase it, if it does).
        time.sleep(0.2)

        started = time.monotonic()
        try:
            status = server.get("/free", timeout=2).status_code
        except OSError as error:
            status = repr(error)
        elapsed = time.monotonic() - started

        assert status == 200, "unprotected request not answered while a referral is chased"
        assert elapsed < 0.2, f"unprotected request took {elapsed:.3f} s"
        assert protected.result().status_code in (401, 503)


@pytest.mark.parametrize("kind", ["reference", "result"])
@pytest.mark.parametrize(
    "setting",
    [
        pytest.param("", id="default"),
        pytest.param("referral on;", id="referral-on"),
        pytest.param("referral off;", id="referral-off"),
    ],
)
def test_referral_host_is_never_contacted(nginx, referring_server, kind, setting):
    with socket.create_server(("127.0.0.1", 0)) as target:
        target.settimeout(0.5)
        target_port = target.getsockname()[1]
        ldap = referring_server(f"ldap://127.0.0.1:{target_port}/{PEOPLE_DN}??sub", kind)
        body = f"require valid_user;\n{setting}\n{TIMEOUTS}"
        server = nginx.start(
            http=ldap_server("users", body, url=ldap.url()), server=protected_location("users")
        )

        try:
            status = server.get(auth=creds("alice"), timeout=5).status_code
        except OSError as error:
            status = repr(error)
        assert ldap.referred.is_set()
        try:
            target.accept()[0].close()
            contacted = True
        except TimeoutError:
            contacted = False

        assert not contacted, "nginx connected to the referral host"
        assert status in (401, 503)
