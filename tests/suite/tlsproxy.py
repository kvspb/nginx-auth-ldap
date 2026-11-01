"""A TLS server in front of the plain LDAP server, run by the tests.

The TLS proxies of the ldap container (tests/ldap/entrypoint.sh) present
fixed certificates. This one runs in the test process, so that a test can
see what the module sent in its handshake (the SNI host name, the TLS
version) and choose what the server accepts.
"""

from __future__ import annotations

import select
import socket
import ssl
import threading
from types import TracebackType
from typing import Self

from ldapdata import LDAP_HOST, TLS_DIR


class TlsProxy:
    def __init__(
        self,
        cert: str = "server",
        upstream: tuple[str, int] = (LDAP_HOST, 389),
        maximum_version: ssl.TLSVersion | None = None,
    ) -> None:
        self.upstream = upstream
        # SNI host names of the handshakes, None for a handshake without one.
        self.server_names: list[str | None] = []
        self.versions: list[str] = []
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(TLS_DIR / f"{cert}.crt", TLS_DIR / f"{cert}.key")
        if maximum_version is not None:
            # TLS 1.0 and 1.1 need security level 0 in OpenSSL 3.
            self.context.set_ciphers("DEFAULT:@SECLEVEL=0")
            self.context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            self.context.maximum_version = maximum_version
        self.context.sni_callback = self._sni
        # Both loopback addresses: "localhost" resolves to each of them.
        self._listener = socket.create_server(("::", 0), family=socket.AF_INET6, dualstack_ipv6=True)
        self.port: int = self._listener.getsockname()[1]
        self._stopping = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def _sni(self, sock: ssl.SSLObject, name: str | None, context: ssl.SSLContext) -> None:
        self.server_names.append(name)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._stopping.set()
        self._listener.close()

    def _accept(self) -> None:
        while not self._stopping.is_set():
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client: socket.socket) -> None:
        try:
            tls = self.context.wrap_socket(client, server_side=True)
        except (ssl.SSLError, OSError):
            client.close()
            return
        self.versions.append(tls.version() or "")
        try:
            server = socket.create_connection(self.upstream, timeout=5)
        except OSError:
            tls.close()
            return
        try:
            while not self._stopping.is_set():
                readable, _, _ = select.select([tls, server], [], [], 0.05)
                if tls in readable or tls.pending():
                    data = tls.recv(65536)
                    if not data:
                        return
                    server.sendall(data)
                if server in readable:
                    data = server.recv(65536)
                    if not data:
                        return
                    tls.sendall(data)
        except OSError:
            return
        finally:
            tls.close()
            server.close()
