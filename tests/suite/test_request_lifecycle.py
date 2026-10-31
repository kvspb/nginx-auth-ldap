"""Requests whose LDAP operation is cut off: the request times out while it
waits for an answer or for a free connection.

A request must not be left behind on a connection or in the waiting queue
once its operation ends one way or another: the pool of connections has to
stay consistent for the requests that follow (kvspb#62 #99 #104 #118 #132).

The LDAP server is reached through LdapProxy, which can hold its answers
and cut the connections. connections 1 keeps the pool easy to reason about.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests

from conftest import ldap_server, protected_location, url_for
from ldapdata import creds
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

        assert first.result() in (200, None)
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

    assert results == [None] * 4
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

    assert status(server, "bob") is None
    proxy.release()
    wait_until_ready(server)
