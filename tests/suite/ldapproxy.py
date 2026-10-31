"""A TCP proxy in front of the LDAP server that can hold its answers.

Tests use it to keep LDAP operations in flight for as long as they need:
while held, everything the server sends is buffered; release() delivers it.
"""

from __future__ import annotations

import select
import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from ldapdata import LDAP_HOST


class LdapProxy:
    def __init__(self, upstream: tuple[str, int] = (LDAP_HOST, 389)) -> None:
        self.upstream = upstream
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port: int = self._listener.getsockname()[1]
        self._held = threading.Event()
        self._released = threading.Condition()
        self._stopping = threading.Event()
        self._threads: list[threading.Thread] = []
        self._sockets: list[socket.socket] = []
        self.connections = 0
        self._accept_thread = threading.Thread(target=self._accept, daemon=True)
        self._accept_thread.start()

    # Control -----------------------------------------------------------

    def hold(self) -> None:
        """Buffer the server's answers from now on."""
        self._held.set()

    def release(self) -> None:
        """Deliver what was buffered and pass answers through again."""
        with self._released:
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

    def close(self) -> None:
        self._stopping.set()
        self.release()
        self._listener.close()
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
                    server.sendall(data)
                if server in readable:
                    data = server.recv(65536)
                    if not data:
                        return
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
