"""Requests whose LDAP operation is cut off: the LDAP connection dies or the
request times out while it waits for an answer or for a free connection.

A request must not be left behind on a connection or in the waiting queue
once its operation ends one way or another: the pool of connections has to
stay consistent for the requests that follow (kvspb#62 #99 #104 #118 #132).

The LDAP server is reached through LdapProxy, which can hold its answers
and cut the connections. connections 1 keeps the pool easy to reason about.
"""

from __future__ import annotations

import base64
import socket
import subprocess
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests

from conftest import ldap_server, protected_location, url_for
from harness import nginx_version
from ldapdata import creds, password
from ldapproxy import LdapProxy

TIMEOUTS = """
connect_timeout 1s;
bind_timeout 1s;
reconnect_timeout 200ms;
request_timeout 1s;
"""


@pytest.fixture
def proxy() -> Iterator[LdapProxy]:
    proxy = LdapProxy()
    yield proxy
    proxy.close()


def start(nginx, proxy: LdapProxy, connections: int = 1):
    body = f"require valid_user;\nconnections {connections};{TIMEOUTS}"
    url = url_for("127.0.0.1", proxy.port)
    server = nginx.start(http=ldap_server("proxied", body, url=url), server=protected_location("proxied"))
    wait_until_ready(server)
    return server


def wait_until_ready(server, deadline: float = 5) -> None:
    """Wait until the pool has (re)connected and authenticates again."""
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            if server.get(auth=creds("alice"), timeout=3).status_code == 200:
                return
        except requests.ConnectionError:
            pass
        time.sleep(0.1)
    pytest.fail("the LDAP connection pool did not become ready")


def status(server, uid: str = "alice", timeout: float = 5) -> int | None:
    """The status code, or None when nginx closed the connection without one."""
    try:
        return server.get(auth=creds(uid), timeout=timeout).status_code
    except requests.ConnectionError:
        return None


def test_request_in_flight_when_the_connection_dies_gets_an_answer(nginx, proxy):
    server = start(nginx, proxy)

    with ThreadPoolExecutor(max_workers=1) as pool:
        proxy.hold()
        future = pool.submit(status, server)
        time.sleep(0.3)
        started = time.monotonic()
        proxy.drop()
        proxy.release()
        result = future.result()
        elapsed = time.monotonic() - started

    # Not answered by the request_timeout (1 s) long after the failure.
    assert elapsed < 0.8, f"the request waited {elapsed:.1f} s for a dead connection"
    assert result == 401


def test_pool_stays_consistent_after_a_connection_died_under_a_request(nginx, proxy):
    server = start(nginx, proxy)

    with ThreadPoolExecutor(max_workers=1) as pool:
        proxy.hold()
        stuck = pool.submit(status, server)
        time.sleep(0.3)
        proxy.drop()
        proxy.release()
        stuck.result()

    wait_until_ready(server)
    # Several requests at once share the single connection one after another.
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda uid: status(server, uid), ["alice", "bob", "carol", "dave"] * 3))

    assert results == [200] * 12


def test_waiting_requests_are_served_after_one_timed_out(nginx, proxy):
    server = start(nginx, proxy)

    with ThreadPoolExecutor(max_workers=8) as pool:
        # The first request takes the only connection and stays on it; the
        # next ones wait in the queue until it times out and frees it.
        proxy.hold()
        first = pool.submit(status, server)
        time.sleep(0.2)
        waiting = [pool.submit(status, server, uid) for uid in ["bob", "carol", "dave"]]
        time.sleep(0.2)
        proxy.release()

        assert first.result() in (200, 503)
        assert [w.result() for w in waiting] == [200, 200, 200]

    assert status(server) == 200


def test_requests_taken_from_the_queue_time_out_cleanly(nginx, proxy):
    # The server never answers and request_timeout is 1 s. A takes the only
    # connection; B and C wait. A's timeout hands the connection to B, D
    # arrives and waits, B's timeout hands it to C, C's to D. B and C left
    # the queue when they were woken: their timeouts must not remove them a
    # second time. In non-debug builds that relinked the queue to C, so C's
    # timeout woke C itself and finalized it twice, and D was never served.
    server = start(nginx, proxy)

    with ThreadPoolExecutor(max_workers=4) as pool, proxy.holding():
        pending = []
        for uid, delay in [("alice", 0.25), ("bob", 0.25), ("carol", 0.6), ("dave", 0)]:
            pending.append(pool.submit(status, server, uid, 10))
            time.sleep(delay)
        results = [p.result() for p in pending]

    assert results == [503] * 4
    assert server.log().count("Authentication timed out") == 4
    wait_until_ready(server)
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda uid: status(server, uid), ["alice", "bob", "carol", "dave"])) == [200] * 4


def test_request_that_timed_out_in_the_queue_is_forgotten(nginx, proxy):
    # No connection is ever ready while the request waits: the server does
    # not answer the service bind. The request times out in the queue and
    # is freed; the connection that binds later must not wake it.
    body = f"require valid_user;\nconnections 1;{TIMEOUTS}"
    url = url_for("127.0.0.1", proxy.port)
    proxy.hold()
    server = nginx.start(http=ldap_server("proxied", body, url=url), server=protected_location("proxied"))

    assert status(server, "bob") == 503
    proxy.release()
    wait_until_ready(server)


def abort_http1(server, uid: str, after: float) -> None:
    """Send a request and close the connection before the answer comes."""
    sock = socket.create_connection(("127.0.0.1", server.port))
    token = base64.b64encode(f"{uid}:{password(uid)}".encode()).decode()
    sock.sendall(f"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {token}\r\n\r\n".encode())
    time.sleep(after)
    sock.close()


def abort_http2(server, uid: str, after: float) -> None:
    """The same over HTTP/2: curl resets the stream and closes the connection."""
    subprocess.run(
        [
            "curl",
            "-s",
            "--http2-prior-knowledge",
            "--max-time",
            str(after),
            "-u",
            f"{uid}:{password(uid)}",
            server.url(),
        ],
        check=False,
    )


@pytest.mark.parametrize("abort", [abort_http1, abort_http2], ids=["http1", "http2"])
@pytest.mark.parametrize("where", ["in-flight", "queued"])
def test_client_that_goes_away_leaves_the_pool_usable(nginx, proxy, abort, where):
    # nginx does not notice a client that leaves during the access phase
    # (HTTP/1 reading is blocked; an HTTP/2 reset or close only marks the
    # stream), so the request lives on until its LDAP operation or its
    # request_timeout ends. Afterwards the pool must work as before.
    if abort is abort_http2 and nginx_version() < (1, 25, 1):
        pytest.skip('"http2 on" needs nginx 1.25.1')
    body = f"require valid_user;\nconnections 1;{TIMEOUTS}"
    url = url_for("127.0.0.1", proxy.port)
    extra = "http2 on;\n" if abort is abort_http2 else ""
    server = nginx.start(
        http=ldap_server("proxied", body, url=url), server=extra + protected_location("proxied")
    )
    wait_until_ready(server)

    with ThreadPoolExecutor(max_workers=2) as pool:
        proxy.hold()
        blocker = pool.submit(status, server, "bob", 10) if where == "queued" else None
        time.sleep(0.1)
        abort(server, "alice", 0.3)
        proxy.release()
        if blocker is not None:
            blocker.result()

    # The aborted request is finished by its request_timeout at the latest.
    time.sleep(1.2)
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda uid: status(server, uid), ["alice", "bob", "carol", "dave"])) == [200] * 4


@pytest.mark.parametrize("retries", [0, 2])
def test_connection_dropped_by_the_server_is_reconnected_once(nginx, proxy, retries):
    # With max_down_retries the read handler used to connect again at once
    # through the freed nginx connection, besides the reconnect timer that
    # close_connection() had already set.
    body = f"require valid_user;\nconnections 1;\nmax_down_retries {retries};{TIMEOUTS}"
    url = url_for("127.0.0.1", proxy.port)
    server = nginx.start(http=ldap_server("proxied", body, url=url), server=protected_location("proxied"))
    wait_until_ready(server)
    assert proxy.connections == 1

    proxy.drop()
    time.sleep(1)

    assert proxy.connections == 2
    wait_until_ready(server)
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda uid: status(server, uid), ["alice", "bob", "carol", "dave"])) == [200] * 4


@pytest.mark.parametrize(("retries", "reconnected"), [(0, False), (1, True)])
def test_max_down_retries_reconnects_without_waiting(nginx, proxy, retries, reconnected):
    body = f"require valid_user;\nconnections 1;\nmax_down_retries {retries};\nreconnect_timeout 5s;"
    url = url_for("127.0.0.1", proxy.port)
    server = nginx.start(http=ldap_server("proxied", body, url=url), server=protected_location("proxied"))
    wait_until_ready(server)

    proxy.drop()
    time.sleep(0.5)

    assert (proxy.connections == 2) is reconnected


def test_keepalive_connection_works_after_a_timed_out_request(nginx, proxy):
    server = start(nginx, proxy)

    with requests.Session() as session:
        with proxy.holding():
            first = session.get(server.url(), auth=creds("alice"), timeout=5)
        wait_until_ready(server)
        second = session.get(server.url(), auth=creds("alice"), timeout=5)

    assert first.status_code == 503
    assert second.status_code == 200


@pytest.mark.parametrize("auth", [("", "some-secret"), ("", "")], ids=["empty-login", "empty-login-and-password"])
def test_empty_login_is_rejected_without_asking_ldap(nginx, proxy, auth):
    server = start(nginx, proxy)

    with proxy.holding():
        response = server.get(auth=auth, timeout=5)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == 'Basic realm="Restricted"'
