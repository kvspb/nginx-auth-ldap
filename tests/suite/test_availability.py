"""Behaviour when the LDAP server is unreachable, silent or rejects the service bind.

The request waits for a usable connection until request_timeout expires and
is then answered with 503 Service Unavailable (nal-toj.18, kvspb#115).
Failover to another server is tested in test_multiple_servers.py.
"""

from __future__ import annotations

import errno
import socket
import time
from collections.abc import Iterator

import pytest

from conftest import TIMEOUTS, ldap_server, protected_location, url_for
from ldapdata import creds


@pytest.fixture
def silent_port() -> Iterator[int]:
    """A loopback port that completes the TCP handshake but never answers."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(16)
        yield sock.getsockname()[1]


def assert_times_out(server, log_text: str) -> None:
    started = time.monotonic()
    response = server.get(auth=creds("alice"))
    elapsed = time.monotonic() - started

    assert response.status_code == 503

    # request_timeout is 1 s.
    assert 0.5 < elapsed < 5
    log = server.log()
    assert "Authentication timed out" in log
    assert log_text in log


def down_server(nginx, port: int):
    url = url_for("127.0.0.1", port)
    return nginx.start(
        http=ldap_server("down", "require valid_user;" + TIMEOUTS, url=url), server=protected_location("down")
    )


def test_refused_connection(nginx, closed_port):
    server = down_server(nginx, closed_port)

    assert_times_out(server, "http_auth_ldap: Could not connect")


@pytest.mark.parametrize("events", ["epoll", "poll"])
def test_refused_connection_is_logged_with_its_error(nginx, closed_port, events):
    # The connect handler never read SO_ERROR: the log did not say why the
    # connect failed.
    url = url_for("127.0.0.1", closed_port)
    server = nginx.start(
        http=ldap_server("down", "require valid_user;" + TIMEOUTS, url=url),
        server=protected_location("down"),
        events=f"use {events};",
    )
    end = time.monotonic() + 3
    while "Could not connect" not in server.log() and time.monotonic() < end:
        time.sleep(0.05)

    line = next(line for line in server.log().splitlines() if "Could not connect" in line)
    assert f'"127.0.0.1:{closed_port}" of ldap_server "down"' in line
    assert f"({errno.ECONNREFUSED}: " in line


def test_connect_that_times_out_is_closed_and_retried(nginx):
    # 192.0.2.1 (TEST-NET-1) never answers the SYN: the connect_timeout
    # ends the attempt, which is logged with its error, and the connection
    # is closed and tried again every reconnect_timeout.
    body = "require valid_user;\nconnect_timeout 300ms;\nreconnect_timeout 200ms;"
    server = nginx.start(
        http=ldap_server("blackhole", body, url=url_for("192.0.2.1", 389)),
        server=protected_location("blackhole"),
    )

    def attempts() -> list[str]:
        return [line for line in server.log().splitlines() if "Could not connect" in line]

    end = time.monotonic() + 3
    while len(attempts()) < 2 and time.monotonic() < end:
        time.sleep(0.05)

    lines = attempts()
    assert len(lines) >= 2, server.log()
    # By number: musl says "Operation timed out", glibc "Connection timed out".
    assert all(f"({errno.ETIMEDOUT}: " in line for line in lines), lines


def test_timeout_is_answered_with_503(nginx, closed_port):
    server = down_server(nginx, closed_port)

    response = server.get(auth=creds("alice"))

    assert response.status_code == 503
    # The connection stays usable for the next request.
    assert server.get(auth=creds("alice")).status_code == 503


def test_server_that_never_answers_the_service_bind(nginx, silent_port):
    url = url_for("127.0.0.1", silent_port)
    server = nginx.start(
        http=ldap_server("silent", "require valid_user;" + TIMEOUTS, url=url),
        server=protected_location("silent"),
    )

    assert_times_out(server, "http_auth_ldap: Request timed out")


def test_rejected_service_bind(nginx):
    body = "require valid_user;" + TIMEOUTS
    server = nginx.start(
        http=ldap_server("badbind", body, bind_secret="wrong-secret"), server=protected_location("badbind")
    )

    assert_times_out(server, "Initial bind failed (49: Invalid credentials")


def test_reconnects_keep_running_while_the_server_is_down(nginx, closed_port):
    server = down_server(nginx, closed_port)

    time.sleep(2.5)

    # One attempt at start plus at least two reconnects, reconnect_timeout apart.
    assert server.log().count("http_auth_ldap: Could not connect") >= 3
