"""Behaviour when the LDAP server is unreachable, silent or rejects the service bind.

These tests document the current behaviour: the request waits for a usable
connection until request_timeout expires, then the module returns NGX_ERROR
and nginx closes the client connection without any HTTP response
(nal-toj.18, kvspb#115). Failover to another server is nal-toj.1.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Iterator

import pytest
import requests

from conftest import ldap_server, protected_location
from ldapdata import PEOPLE_DN, creds

# Short timeouts keep these tests fast; the defaults are 10 s each.
TIMEOUTS = """
connect_timeout 1s;
bind_timeout 1s;
reconnect_timeout 1s;
request_timeout 1s;
"""


def url_for(host: str, port: int) -> str:
    return f"ldap://{host}:{port}/{PEOPLE_DN}?uid?sub?(objectClass=inetOrgPerson)"


@pytest.fixture
def closed_port() -> int:
    """A loopback port nobody listens on: connections are refused."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def silent_port() -> Iterator[int]:
    """A loopback port that completes the TCP handshake but never answers."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(16)
        yield sock.getsockname()[1]


def assert_times_out(server, log_text: str) -> None:
    started = time.monotonic()
    with pytest.raises(requests.ConnectionError):
        server.get(auth=creds("alice"))
    elapsed = time.monotonic() - started

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


@pytest.mark.xfail(reason="a timed-out authentication closes the connection without a response (nal-toj.18)")
def test_timeout_is_answered_with_an_http_error(nginx, closed_port):
    server = down_server(nginx, closed_port)

    assert server.get(auth=creds("alice")).status_code >= 500


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
