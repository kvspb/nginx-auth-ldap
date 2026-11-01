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
from ldapdata import PEOPLE_DN, creds

# Packets to this address are dropped: a connect() hangs until it times out.
BLACK_HOLE = "10.255.255.1"

UNPROTECTED = """
location /free {
    return 200 "free";
}
"""


def _ber(tag: int, content: bytes) -> bytes:
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(encoded)]) + encoded + content


def _integer(value: int) -> bytes:
    return _ber(0x02, value.to_bytes(4, "big", signed=True).lstrip(b"\x00") or b"\x00")


def _string(value: str) -> bytes:
    return _ber(0x04, value.encode())


def _result(tag: int, code: int, extra: bytes = b"") -> bytes:
    return _ber(tag, _ber(0x0A, bytes([code])) + _string("") + _string("") + extra)


def _message(msgid: int, op: bytes) -> bytes:
    return _ber(0x30, _integer(msgid) + op)


def _read_element(sock: socket.socket) -> bytes | None:
    """One BER element, or None when the peer closed the connection."""

    def read(count: int) -> bytes | None:
        data = b""
        while len(data) < count:
            chunk = sock.recv(count - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    head = read(2)
    if head is None:
        return None
    length = head[1]
    if length & 0x80:
        raw = read(length & 0x7F)
        if raw is None:
            return None
        length = int.from_bytes(raw, "big")
    body = read(length)
    return None if body is None else head + body


class ReferringLdapServer:
    """A fake LDAP server: binds succeed, every search answers with a referral.

    ``kind`` "reference" sends a SearchResultReference and then an empty
    successful SearchResultDone; "result" sends a SearchResultDone with the
    resultCode referral (10).
    """

    def __init__(self, referral_url: str, kind: str) -> None:
        self.referral_url = referral_url
        self.kind = kind
        self.referred = threading.Event()
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port: int = self._listener.getsockname()[1]
        self._clients: list[socket.socket] = []
        threading.Thread(target=self._accept, daemon=True).start()

    def url(self) -> str:
        return f"ldap://127.0.0.1:{self.port}/{PEOPLE_DN}?uid?sub?(objectClass=inetOrgPerson)"

    def close(self) -> None:
        self._listener.close()
        for client in self._clients:
            client.close()

    def _accept(self) -> None:
        while True:
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            self._clients.append(client)
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client: socket.socket) -> None:
        try:
            while (message := _read_element(client)) is not None:
                # SEQUENCE header, then messageID (short INTEGER), then the op.
                offset = 2 if message[1] < 0x80 else 2 + (message[1] & 0x7F)
                id_len = message[offset + 1]
                msgid = int.from_bytes(message[offset + 2 : offset + 2 + id_len], "big")
                op = message[offset + 2 + id_len]
                if op == 0x60:  # BindRequest
                    client.sendall(_message(msgid, _result(0x61, 0)))
                elif op == 0x63:  # SearchRequest
                    client.sendall(self._search_answer(msgid))
                    self.referred.set()
                elif op == 0x42:  # UnbindRequest
                    return
        except OSError:
            return

    def _search_answer(self, msgid: int) -> bytes:
        if self.kind == "reference":
            reference = _message(msgid, _ber(0x73, _string(self.referral_url)))
            return reference + _message(msgid, _result(0x65, 0))
        referral = _ber(0xA3, _string(self.referral_url))
        return _message(msgid, _result(0x65, 10, referral))


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
