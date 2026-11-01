"""TCP keepalive on LDAP connections (so_keepalive, nal-toj.3, kvspb#51).

A firewall or NAT that forgets an idle connection drops its packets without
a word; the next request on it waited for request_timeout. TCP keepalive
probes find such a connection while it is idle: the kernel then reports an
error and the module reopens the connection. The kernel default waits two
hours before the first probe, longer than most firewalls keep a connection,
so the module probes after 60 s by default.

The tests read the socket options of the worker's LDAP connections through
pidfd_getfd(2): nginx is a child of the test process, so it may be traced.
"""

from __future__ import annotations

import ctypes
import os
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from conftest import ldap_server, protected_location, url_for
from ldapdata import creds
from ldapproxy import LdapProxy

SYS_PIDFD_GETFD = 438
SYSTEM = tuple(
    int(Path(f"/proc/sys/net/ipv4/tcp_keepalive_{name}").read_text()) for name in ("time", "intvl", "probes")
)


@pytest.fixture
def proxy() -> Iterator[LdapProxy]:
    with LdapProxy() as proxy:
        yield proxy


def ldap_sockets(pid: int, port: int) -> list[socket.socket]:
    """Copies of the worker's established connections to port."""
    inodes = set()
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        fields = line.split()
        if int(fields[2].split(":")[1], 16) == port and fields[3] == "01":
            inodes.add(fields[9])
    libc = ctypes.CDLL(None, use_errno=True)
    pidfd = os.pidfd_open(pid)
    try:
        found = []
        for fd in Path(f"/proc/{pid}/fd").iterdir():
            try:
                target = os.readlink(fd)
            except FileNotFoundError:
                # Another descriptor (the client connection) just closed.
                continue
            if target.removeprefix("socket:[").removesuffix("]") in inodes:
                copy = libc.syscall(SYS_PIDFD_GETFD, pidfd, int(fd.name), 0)
                assert copy >= 0, os.strerror(ctypes.get_errno())
                found.append(socket.socket(fileno=copy))
        return found
    finally:
        os.close(pidfd)


def keepalive(sock: socket.socket) -> tuple[int, int, int, int]:
    """SO_KEEPALIVE, then the idle time, interval and count."""
    return (
        sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE),
        sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE),
        sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL),
        sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT),
    )


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        pytest.param("", (1, 60, 10, 3), id="default"),
        pytest.param("so_keepalive 30s:5s:2;", (1, 30, 5, 2), id="all-set"),
        pytest.param("so_keepalive 2m::;", (1, 120, SYSTEM[1], SYSTEM[2]), id="idle-only"),
        pytest.param("so_keepalive :20s:;", (1, SYSTEM[0], 20, SYSTEM[2]), id="interval-only"),
        pytest.param("so_keepalive ::7;", (1, SYSTEM[0], SYSTEM[1], 7), id="count-only"),
        pytest.param("so_keepalive on;", (1, *SYSTEM), id="system-timings"),
        pytest.param("so_keepalive off;", (0, *SYSTEM), id="off"),
    ],
)
def test_keepalive_options(nginx, proxy, extra, expected):
    body = f"require valid_user;\nconnections 2;\n{extra}"
    url = url_for("127.0.0.1", proxy.port)
    server = nginx.start(http=ldap_server("proxied", body, url=url), server=protected_location("proxied"))
    assert server.get(auth=creds("alice"), timeout=5).status_code == 200
    (worker,) = server.worker_pids()

    sockets = ldap_sockets(worker, proxy.port)
    try:
        assert [keepalive(sock) for sock in sockets] == [expected] * 2
    finally:
        for sock in sockets:
            sock.close()
    assert "setsockopt" not in server.log()


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("maybe", id="word"),
        pytest.param("1x:2:3", id="bad-idle"),
        pytest.param("1:2:x", id="bad-count"),
        pytest.param("1:2:3s", id="count-with-unit"),
        pytest.param("1:2", id="two-parts"),
        pytest.param("::", id="nothing-set"),
    ],
)
def test_invalid_so_keepalive(nginx, value):
    result = nginx.check_config(
        http=ldap_server("users", f"require valid_user;\nso_keepalive {value};"),
        server=protected_location("users"),
    )

    assert result.returncode == 1, result.stderr
    assert f'invalid value "{value}" for so_keepalive' in result.stderr
