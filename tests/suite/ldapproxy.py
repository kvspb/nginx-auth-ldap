"""A TCP proxy in front of the LDAP server that can hold its answers.

It listens on a loopback port, or on a Unix socket when given a path (for
ldapi:// urls).

Tests use it to keep LDAP operations in flight for as long as they need:
while held, everything the server sends is buffered; release() delivers it.
"""

from __future__ import annotations

import select
import socket
import struct
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType
from typing import Self

from ldapdata import LDAP_HOST


def _operation_tags(data: bytes) -> list[int]:
    """The protocolOp tags of the complete LDAPMessages at the start of data."""
    tags = []
    pos = 0
    while pos + 2 <= len(data) and data[pos] == 0x30:
        length = data[pos + 1]
        start = pos + 2
        if length & 0x80:
            count = length & 0x7F
            length = int.from_bytes(data[start : start + count], "big")
            start += count
        # messageID: INTEGER, short length form.
        op = start + 2 + data[start + 1] if start + 1 < len(data) else len(data)
        if op < len(data):
            tags.append(data[op])
        pos = start + length
    return tags


class LdapProxy:
    def __init__(
        self,
        upstream: tuple[str, int] = (LDAP_HOST, 389),
        unix_path: Path | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.upstream = upstream
        self.unix_path = unix_path
        self.host = host
        if unix_path is None:
            self._listener = socket.create_server((host, port))
            self.port: int = self._listener.getsockname()[1]
        else:
            self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._listener.bind(str(unix_path))
            self._listener.listen()
            self.port = 0
        self._held = threading.Event()
        self._hold_tag: int | None = None
        self._hold_skip = 0
        self._released = threading.Condition()
        self._stopping = threading.Event()
        self._refusing = threading.Event()
        self._refuse_after_request = False
        self._threads: list[threading.Thread] = []
        self._sockets: list[socket.socket] = []
        self.connections = 0
        # Everything nginx sent, to check what crosses the wire in clear.
        self.sent = bytearray()
        self._accept_thread = threading.Thread(target=self._accept, daemon=True)
        self._accept_thread.start()

    # Control -----------------------------------------------------------

    def hold(self) -> None:
        """Buffer the server's answers from now on."""
        self._held.set()

    def hold_at(self, tag: int, skip: int = 0) -> None:
        """Hold from a server message whose protocolOp has this tag.

        For example 0x61 holds the next BindResponse; skip=1 lets one
        through and holds the one after it. Answers before it pass through.
        """
        self._hold_skip = skip
        self._hold_tag = tag

    @property
    def is_holding(self) -> bool:
        return self._held.is_set()

    def release(self) -> None:
        """Deliver what was buffered and pass answers through again."""
        with self._released:
            self._hold_tag = None
            self._held.clear()
            self._released.notify_all()

    @contextmanager
    def holding(self) -> Iterator[None]:
        self.hold()
        try:
            yield
        finally:
            self.release()

    def drop(self) -> None:
        """Cut every proxied connection, as a restarting LDAP server would."""
        sockets, self._sockets = self._sockets, []
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def reset(self) -> None:
        """Reset every proxied connection: nginx gets a TCP RST, not a FIN."""
        sockets, self._sockets = self._sockets, []
        for sock in sockets:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            except OSError:
                pass
            sock.close()

    def refuse(self, after_request: bool = False) -> None:
        """Close new connections, optionally after the first request starts.

        Waiting for a request makes the failure occur in LDAP I/O rather
        than racing the nginx connect handler.
        """
        self._refuse_after_request = after_request
        self._refusing.set()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._stopping.set()
        self.release()
        self._listener.close()
        if self.unix_path is not None:
            self.unix_path.unlink(missing_ok=True)
        for sock in self._sockets:
            try:
                sock.close()
            except OSError:
                pass

    # Plumbing -----------------------------------------------------------

    def _accept(self) -> None:
        while not self._stopping.is_set():
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            if self._refusing.is_set():
                self.connections += 1
                if self._refuse_after_request:
                    client.settimeout(2)
                    try:
                        client.recv(65536)
                    except OSError:
                        pass
                client.close()
                continue
            try:
                server = socket.create_connection(self.upstream, timeout=5)
            except OSError:
                client.close()
                continue
            server.settimeout(None)
            self.connections += 1
            self._sockets += [client, server]
            thread = threading.Thread(target=self._pump, args=(client, server), daemon=True)
            thread.start()
            self._threads.append(thread)

    def _pump(self, client: socket.socket, server: socket.socket) -> None:
        pending = b""
        try:
            while not self._stopping.is_set():
                readable, _, _ = select.select([client, server], [], [], 0.05)
                if client in readable:
                    data = client.recv(65536)
                    if not data:
                        return
                    self.sent += data
                    server.sendall(data)
                if server in readable:
                    data = server.recv(65536)
                    if not data:
                        return
                    if self._hold_tag is not None:
                        for tag in _operation_tags(data):
                            if tag != self._hold_tag:
                                continue
                            if self._hold_skip == 0:
                                self._held.set()
                                break
                            self._hold_skip -= 1
                    pending += data
                if pending and not self._held.is_set():
                    client.sendall(pending)
                    pending = b""
        except (OSError, ValueError):
            return
        finally:
            for sock in (client, server):
                try:
                    sock.close()
                except OSError:
                    pass
