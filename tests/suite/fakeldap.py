"""A scriptable fake LDAP server for answers slapd cannot be made to give.

It speaks just enough LDAPv3 (BER over TCP) for the module: BindRequest,
SearchRequest and UnbindRequest. Subclasses or callers decide the answers.
"""

from __future__ import annotations

import socket
import threading

from ldapdata import PEOPLE_DN

# protocolOp tags
BIND_REQUEST = 0x60
BIND_RESPONSE = 0x61
SEARCH_REQUEST = 0x63
SEARCH_ENTRY = 0x64
SEARCH_DONE = 0x65
UNBIND_REQUEST = 0x42


def ber(tag: int, content: bytes) -> bytes:
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(encoded)]) + encoded + content


def integer(value: int) -> bytes:
    return ber(0x02, value.to_bytes(4, "big", signed=True).lstrip(b"\x00") or b"\x00")


def string(value: str) -> bytes:
    return ber(0x04, value.encode())


def result(tag: int, code: int, extra: bytes = b"") -> bytes:
    """An LDAPResult: resultCode, matchedDN, diagnosticMessage[, extra]."""
    return ber(tag, ber(0x0A, bytes([code])) + string("") + string("") + extra)


def message(msgid: int, op: bytes) -> bytes:
    return ber(0x30, integer(msgid) + op)


def search_entry(msgid: int, dn: str) -> bytes:
    """A SearchResultEntry without attributes."""
    return message(msgid, ber(SEARCH_ENTRY, string(dn) + ber(0x30, b"")))


def read_element(sock: socket.socket) -> bytes | None:
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


def parse_message(data: bytes) -> tuple[int, int, bytes]:
    """messageID, protocolOp tag and the protocolOp contents of an LDAPMessage."""
    offset = 2 if data[1] < 0x80 else 2 + (data[1] & 0x7F)
    id_len = data[offset + 1]
    msgid = int.from_bytes(data[offset + 2 : offset + 2 + id_len], "big")
    op_start = offset + 2 + id_len
    op = data[op_start]
    op_len = data[op_start + 1]
    content_start = op_start + 2
    if op_len & 0x80:
        size = op_len & 0x7F
        op_len = int.from_bytes(data[content_start : content_start + size], "big")
        content_start += size
    return msgid, op, data[content_start : content_start + op_len]


def bind_dn(content: bytes) -> str:
    """The name of a BindRequest: version INTEGER, then name OCTET STRING."""
    version_len = content[1]
    name = content[2 + version_len :]
    return name[2 : 2 + name[1]].decode()


def search_base(content: bytes) -> str:
    """The baseObject of a SearchRequest, its first element."""
    return content[2 : 2 + content[1]].decode()


class FakeLdapServer:
    """Accepts connections on 127.0.0.1 and answers each request through
    the answer_bind() and answer_search() methods, which return the bytes
    to send or None to close the connection instead."""

    def __init__(self) -> None:
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port: int = self._listener.getsockname()[1]
        self._clients: list[socket.socket] = []
        threading.Thread(target=self._accept, daemon=True).start()

    def url(self, base: str = PEOPLE_DN) -> str:
        return f"ldap://127.0.0.1:{self.port}/{base}?uid?sub?(objectClass=inetOrgPerson)"

    def close(self) -> None:
        self._listener.close()
        for client in self._clients:
            client.close()

    def answer_bind(self, msgid: int, dn: str) -> bytes | None:
        return message(msgid, result(BIND_RESPONSE, 0))

    def answer_search(self, msgid: int, base: str) -> bytes | None:
        return message(msgid, result(SEARCH_DONE, 0))

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
            while (data := read_element(client)) is not None:
                msgid, op, content = parse_message(data)
                if op == BIND_REQUEST:
                    answer = self.answer_bind(msgid, bind_dn(content))
                elif op == SEARCH_REQUEST:
                    answer = self.answer_search(msgid, search_base(content))
                elif op == UNBIND_REQUEST:
                    return
                else:
                    continue
                if answer is None:
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                    return
                client.sendall(answer)
        except OSError:
            return
