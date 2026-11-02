"""A DNS server on a loopback UDP port for the nginx resolver.

It answers A queries from a table that tests change at run time, answers
AAAA queries with no records, unknown names with NXDOMAIN, and can stop
answering altogether (hold) to make the resolver time out.
"""

from __future__ import annotations

import socket
import struct
import threading
from collections import Counter
from types import TracebackType
from typing import Self

TYPE_A = 1


class FakeDns:
    def __init__(self, records: dict[str, list[str]] | None = None, ttl: int = 1) -> None:
        self.records: dict[str, list[str]] = {name.lower(): ips for name, ips in (records or {}).items()}
        self.ttl = ttl
        self.queries: Counter[str] = Counter()
        self.held = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.settimeout(0.1)
        self.port: int = self._sock.getsockname()[1]
        self._stopping = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def address(self) -> str:
        return f"127.0.0.1:{self.port}"

    def set(self, name: str, *ips: str) -> None:
        self.records[name.lower()] = list(ips)

    def hold(self) -> None:
        """Leave every query unanswered from now on."""
        self.held.set()

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
        self._thread.join(timeout=2)
        self._sock.close()

    def _serve(self) -> None:
        while not self._stopping.is_set():
            try:
                query, peer = self._sock.recvfrom(512)
            except TimeoutError:
                continue
            except OSError:
                return
            answer = self._answer(query)
            if answer is not None and not self.held.is_set():
                self._sock.sendto(answer, peer)

    def _answer(self, query: bytes) -> bytes | None:
        if len(query) < 12:
            return None
        ident, flags = struct.unpack("!HH", query[:4])
        labels = []
        pos = 12
        while pos < len(query) and query[pos] != 0:
            length = query[pos]
            labels.append(query[pos + 1 : pos + 1 + length].decode(errors="replace"))
            pos += 1 + length
        question = query[12 : pos + 5]
        qtype = struct.unpack("!H", query[pos + 1 : pos + 3])[0]
        name = ".".join(labels).lower()
        self.queries[name] += 1

        ips = self.records.get(name)
        rcode = 3 if ips is None else 0
        answers = b""
        count = 0
        if ips is not None and qtype == TYPE_A:
            for ip in ips:
                answers += struct.pack("!HHHIH", 0xC00C, TYPE_A, 1, self.ttl, 4) + socket.inet_aton(ip)
                count += 1
        # QR, opcode of the query, RD as asked, RA.
        reply_flags = 0x8000 | (flags & 0x7900) | 0x0080 | rcode
        return struct.pack("!HHHHHH", ident, reply_flags, 1, count, 0, 0) + question + answers
