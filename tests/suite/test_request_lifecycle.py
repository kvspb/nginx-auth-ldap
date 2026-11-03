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
import os
import resource
import signal
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import requests

from conftest import ldap_server, protected_location, url_for
from fakeldap import BIND_REQUEST, FakeLdapServer
from harness import nginx_version
from ldapdata import PEOPLE_DN, ROTATING_DN, ROTATING_SECRET, creds, password, rotating_service_password
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

    # Not answered by the request_timeout (1 s) long after the failure, and
    # not with 401: a broken connection says nothing about the password.
    assert elapsed < 0.8, f"the request waited {elapsed:.1f} s for a dead connection"
    assert result == 503


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


def test_queued_local_failures_do_not_recurse_through_the_waiting_queue(nginx, proxy):
    # Every search fails locally before sending, then returns the connection
    # to the next waiter. An inline wake nests the entire queue on the C
    # stack. Bound the stack rather than needing thousands of clients.
    nginx.worker_connections = 1024
    proxy.hold()
    url = url_for("127.0.0.1", proxy.port).replace("?uid?", "?%29?")
    server = nginx.start(
        http=ldap_server(
            "bad_filter", "require valid_user; connections 1; bind_timeout 30s; request_timeout 30s;", url=url
        ),
        server=protected_location("bad_filter"),
    )
    (worker,) = server.worker_pids()
    _, hard = resource.prlimit(worker, resource.RLIMIT_STACK)
    resource.prlimit(worker, resource.RLIMIT_STACK, (256 * 1024, hard))
    clients = []
    token = base64.b64encode(b"alice:alice-secret").decode()
    request = f"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {token}\r\nConnection: close\r\n\r\n"
    try:
        for _ in range(512):
            client = socket.create_connection(("127.0.0.1", server.port), timeout=10)
            clients.append(client)
            client.sendall(request.encode())
        time.sleep(0.5)
        proxy.release()
        for client in clients:
            assert client.recv(4096).startswith(b"HTTP/1.1 401 ")
        assert "Bad search filter" in server.log()
    finally:
        proxy.release()
        for client in clients:
            client.close()


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


def test_waiter_that_leaves_before_it_runs_passes_the_connection_on(nginx, proxy):
    # The service bind answers while two requests wait for the connection.
    # The first waiter is woken through a posted event, and its client goes
    # away in the same batch of events, before that event runs: closing it
    # drops the event. The second waiter used to stay in the queue with the
    # connection free until its request_timeout.
    body = "require valid_user;\nconnections 1;\nbind_timeout 30s;\nrequest_timeout 5s;"
    proxy.hold()
    server = nginx.start(
        http=ldap_server("proxied", body, url=url_for("127.0.0.1", proxy.port)),
        server=protected_location("proxied"),
    )
    end = time.monotonic() + 3
    while not proxy.sent and time.monotonic() < end:
        time.sleep(0.01)
    assert proxy.sent, "the service bind never arrived"
    (worker,) = server.worker_pids()

    token = base64.b64encode(f"alice:{password('alice')}".encode()).decode()
    first = socket.create_connection(("127.0.0.1", server.port))
    first.sendall(f"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {token}\r\n\r\n".encode())
    time.sleep(0.2)
    with ThreadPoolExecutor(max_workers=1) as pool:
        second = pool.submit(status, server, "bob", 10)
        time.sleep(0.2)
        started = time.monotonic()
        os.kill(worker, signal.SIGSTOP)
        try:
            proxy.release()
            time.sleep(0.2)
            first.close()
            time.sleep(0.2)
        finally:
            os.kill(worker, signal.SIGCONT)
        result = second.result()
        elapsed = time.monotonic() - started

    assert result == 200
    assert elapsed < 2, f"the second waiter got the free connection after {elapsed:.1f} s"


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
    # A client that leaves during LDAP I/O or while queued must not leave
    # stale pointers behind when the delayed answers finally arrive.
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


@pytest.mark.parametrize("abort", [abort_http1, abort_http2], ids=["http1", "http2"])
@pytest.mark.parametrize("where", ["in-flight", "queued"])
@pytest.mark.parametrize(
    ("events", "unwatch"), [("epoll", False), ("poll", False), ("epoll", True), ("poll", True)]
)
def test_client_abort_is_cleaned_up_before_the_ldap_timeout(nginx, proxy, abort, where, events, unwatch):
    if abort is abort_http2 and nginx_version() < (1, 25, 1):
        pytest.skip('"http2 on" needs nginx 1.25.1')
    body = (
        f'require valid_user "uid=$remote_user,{PEOPLE_DN}";\nconnections 1;\n'
        "request_timeout 10s;\nbind_timeout 10s;"
    )
    extra = "http2 on;\n" if abort is abort_http2 else ""
    if unwatch:
        if abort is abort_http2:
            pytest.skip("HTTP/2 stream events are not registered with the socket event backend")
        extra += "test_unwatch_read on;\n"
    server = nginx.start(
        http=ldap_server("proxied", body, url=url_for("127.0.0.1", proxy.port)),
        server=extra + protected_location("proxied"),
        events=f"use {events};",
    )
    wait_until_ready(server)
    since = server.log_size()
    proxy.sent.clear()

    with ThreadPoolExecutor(max_workers=1) as pool:
        proxy.hold()
        try:
            blocker = pool.submit(status, server, "bob", 15) if where == "queued" else None
            if blocker is not None:
                end = time.monotonic() + 2
                while b"uid=bob," not in proxy.sent and time.monotonic() < end:
                    time.sleep(0.01)
                assert b"uid=bob," in proxy.sent
            abort(server, "alice", 0.3)
            end = time.monotonic() + 2
            while "client prematurely closed connection" not in server.log(since) and time.monotonic() < end:
                time.sleep(0.01)
            assert "client prematurely closed connection" in server.log(since)
            if where == "in-flight":
                end = time.monotonic() + 2
                while proxy.connections == 1 and time.monotonic() < end:
                    time.sleep(0.01)
                assert proxy.connections == 2, "the aborted request still owns its LDAP connection"
        finally:
            proxy.release()
        if blocker is not None:
            assert blocker.result() == 200
            assert b"uid=alice," not in proxy.sent, "the aborted request was left in the queue"

    assert "Authentication timed out" not in server.log(since)
    wait_until_ready(server)


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


def drop_under_a_request(server, proxy: LdapProxy) -> None:
    """Cut the connection while a request is in flight on it: a busy
    connection, unlike an idle one, is reconnected at once only through
    max_down_retries."""
    with ThreadPoolExecutor(max_workers=1) as pool:
        proxy.hold()
        stuck = pool.submit(status, server)
        time.sleep(0.2)
        proxy.drop()
        proxy.release()
        assert stuck.result() == 503


@pytest.mark.parametrize(("retries", "reconnected"), [(0, False), (1, True)])
def test_max_down_retries_reconnects_without_waiting(nginx, proxy, retries, reconnected):
    body = f"require valid_user;\nconnections 1;\nmax_down_retries {retries};\nreconnect_timeout 5s;"
    url = url_for("127.0.0.1", proxy.port)
    server = nginx.start(http=ldap_server("proxied", body, url=url), server=protected_location("proxied"))
    wait_until_ready(server)

    drop_under_a_request(server, proxy)
    time.sleep(0.5)

    assert (proxy.connections == 2) is reconnected


@pytest.mark.parametrize("retries", [1, 2])
def test_max_down_retries_does_not_loop_against_a_server_that_closes_at_once(nginx, proxy, retries):
    # The retry counter was reset on every connect, before the bind, so a
    # server that accepts and closes at once was reconnected in a busy loop.
    # Wait for the first bind bytes before closing so every retry fails in
    # LDAP I/O, not in connect() before the LDAP handle exists. It must make
    # exactly max_down_retries immediate attempts, then wait for reconnect_timeout.
    body = f"require valid_user;\nconnections 1;\nmax_down_retries {retries};\nreconnect_timeout 5s;"
    url = url_for("127.0.0.1", proxy.port)
    server = nginx.start(http=ldap_server("proxied", body, url=url), server=protected_location("proxied"))
    wait_until_ready(server)
    connections = proxy.connections

    proxy.refuse(after_request=True)
    drop_under_a_request(server, proxy)
    time.sleep(1)

    assert proxy.connections - connections == retries, server.log()


def test_keepalive_connection_works_after_a_timed_out_request(nginx, proxy):
    server = start(nginx, proxy)

    with requests.Session() as session:
        with proxy.holding():
            first = session.get(server.url(), auth=creds("alice"), timeout=5)
        wait_until_ready(server)
        second = session.get(server.url(), auth=creds("alice"), timeout=5)

    assert first.status_code == 503
    assert second.status_code == 200


@pytest.mark.parametrize(
    "auth", [("", "some-secret"), ("", "")], ids=["empty-login", "empty-login-and-password"]
)
def test_empty_login_is_rejected_without_asking_ldap(nginx, proxy, auth):
    server = start(nginx, proxy)

    with proxy.holding():
        response = server.get(auth=auth, timeout=5)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == 'Basic realm="Restricted", charset="UTF-8"'


def test_connection_is_not_reused_when_the_rebind_fails(nginx):
    # After a user bind the connection binds as the service account again.
    # If that fails, the connection is still bound as the user: it must be
    # closed, not handed to the next request, which would then search with
    # the rights of that user.
    body = f"require valid_user;\nconnections 1;{TIMEOUTS}"
    http = ldap_server("rotating", body, bind_dn=ROTATING_DN, bind_secret=ROTATING_SECRET)
    server = nginx.start(http=http, server=protected_location("rotating"))
    wait_until_ready(server)

    with rotating_service_password("changed-" + "secret"):
        # Search and user bind succeed; the rebind afterwards fails.
        assert status(server, "bob") == 200
        assert "binddn bind failed (49: Invalid credentials)" in server.log()
        # The reconnect cannot bind as the service account either.
        assert status(server, "carol") == 503

    wait_until_ready(server)


def start_with_user_bind(nginx, proxy: LdapProxy):
    """A server whose first operation for a request is the user bind."""
    body = f'require valid_user "uid=$remote_user,{PEOPLE_DN}";\nconnections 1;{TIMEOUTS}'
    url = url_for("127.0.0.1", proxy.port)
    server = nginx.start(http=ldap_server("proxied", body, url=url), server=protected_location("proxied"))
    wait_until_ready(server)
    return server


def test_connection_is_not_reused_when_the_user_bind_timed_out(nginx, proxy):
    # The request times out while its user bind is in flight. The connection
    # may still become bound as that user, and the next request would send
    # its operation before the BindResponse arrives: close it instead.
    server = start_with_user_bind(nginx, proxy)
    assert proxy.connections == 1

    with proxy.holding():
        assert status(server, "alice") == 503

    wait_until_ready(server)
    assert proxy.connections == 2


def test_dead_connection_is_not_handed_out_after_a_timeout(nginx, proxy):
    # The server stops answering for good. The connection of the request
    # that timed out must not be given to the next request: a new one is
    # opened instead.
    server = start_with_user_bind(nginx, proxy)

    with proxy.holding():
        assert status(server, "alice") == 503
        assert status(server, "bob") == 503
        assert proxy.connections >= 2

    wait_until_ready(server)


def test_connection_lost_under_the_user_bind_fails_over_at_once(nginx, proxy):
    # The connection dies while the user bind is in flight: the server said
    # nothing about the password, so the next server decides. The request
    # used to go on to the rebind as binddn with no connection left and
    # wait in the queue for the reconnect (30 s here), until its
    # request_timeout gave up on the server.
    body = (
        f'require valid_user "uid=$remote_user,{PEOPLE_DN}";\nconnections 1;\n'
        "reconnect_timeout 30s;\nrequest_timeout 1s;"
    )
    http = ldap_server("proxied", body, url=url_for("127.0.0.1", proxy.port)) + ldap_server("direct")
    server = nginx.start(http=http, server=protected_location("proxied direct"))
    wait_until_ready(server)
    since = server.log_size()

    with ThreadPoolExecutor(max_workers=1) as pool:
        proxy.hold()
        future = pool.submit(status, server)
        time.sleep(0.3)
        started = time.monotonic()
        proxy.drop()
        proxy.release()
        result = future.result()
        elapsed = time.monotonic() - started

    assert result == 200
    assert elapsed < 0.5, f"the request waited {elapsed:.1f} s before trying the next server"
    assert "Authentication timed out" not in server.log(since)


def test_request_freed_while_it_waits_is_forgotten(nginx, proxy):
    # A reload makes the old worker shut down; worker_shutdown_timeout then
    # closes every connection in one pass: the client connections, which
    # terminates the requests still in the access phase without going
    # through the module, and the LDAP connections. A in flight on the only
    # connection and B in the waiting queue must not be left behind,
    # whichever of the connections is closed first: closing A's LDAP
    # connection must not wake a freed request, and the worker must exit
    # without a socket left open.
    body = f"require valid_user;\nconnections 1;{TIMEOUTS}"
    http = ldap_server("proxied", body, url=url_for("127.0.0.1", proxy.port))
    server = nginx.start(
        http=http, server=protected_location("proxied"), main="worker_shutdown_timeout 300ms;"
    )
    wait_until_ready(server)
    (old_worker,) = server.worker_pids()

    with ThreadPoolExecutor(max_workers=2) as pool, proxy.holding():
        pending = [pool.submit(status, server, uid) for uid in ["alice", "bob"]]
        time.sleep(0.3)
        server.reload()
        results = [p.result() for p in pending]
        end = time.monotonic() + 3
        while old_worker in server.worker_pids() and time.monotonic() < end:
            time.sleep(0.05)

    assert old_worker not in server.worker_pids(), "the old worker did not exit"
    # The request in flight (either one: they race for the connection) may
    # get the 503 of its closed LDAP connection before its client
    # connection is closed; the queued one is terminated without an answer.
    assert set(results) <= {None, 503}
    assert results.count(503) <= 1
    assert "open socket" not in server.log()
    wait_until_ready(server)


def start_with_reruns(nginx, proxy: LdapProxy):
    """A server whose requests run their phases again every 10 ms.

    test_rerun_phases (tests/modules/rerun_phases) stands in for events that
    run the phase engine while an LDAP operation is in flight, as an HTTP/3
    MAX_STREAM_DATA frame or another module may do.
    """
    body = f"require valid_user;\nconnections 1;{TIMEOUTS}"
    url = url_for("127.0.0.1", proxy.port)
    server = nginx.start(
        http=ldap_server("proxied", body, url=url),
        server="test_rerun_phases 10ms;\n" + protected_location("proxied"),
    )
    wait_until_ready(server)
    return server


@pytest.mark.parametrize(
    ("auth", "skip", "expected"),
    [
        pytest.param(("alice", "not-the-password"), 0, 401, id="user-bind"),
        pytest.param(creds("alice"), 1, 200, id="rebind"),
    ],
)
def test_bind_is_not_judged_before_its_answer_arrives(nginx, proxy, auth, skip, expected):
    # The search answer leaves ctx->replied set and ctx->error_code at
    # LDAP_SUCCESS. A run of the phases while the user bind is in flight
    # took that for a successful bind and allowed a wrong password; while
    # the rebind was in flight it returned the connection to the pool.
    server = start_with_reruns(nginx, proxy)

    with ThreadPoolExecutor(max_workers=1) as pool:
        proxy.hold_at(0x61, skip=skip)
        future = pool.submit(lambda: server.get(auth=auth, timeout=5).status_code)
        end = time.monotonic() + 2
        while not proxy.is_holding and time.monotonic() < end:
            time.sleep(0.01)
        assert proxy.is_holding, "the bind never reached the server"
        time.sleep(0.2)
        answered_early = future.done()
        proxy.release()
        result = future.result()

    assert not answered_early, f"answered {result} before the BindResponse arrived"
    assert result == expected
    assert "running the phases again" in server.log()


def session_status(session: requests.Session, url: str) -> int | None:
    """The status code, or None when no answer came within 5 s."""
    try:
        return session.get(url, auth=creds("bob"), timeout=5).status_code
    except (requests.ConnectionError, requests.Timeout):
        return None


def keepalive_requests_while_the_connection_is_reset(
    server, proxy: LdapProxy, count: int
) -> list[int | None]:
    """Send requests on kept-alive client connections and reset the LDAP
    connection, all while the worker is stopped: the worker then sees the
    requests before it reads the reset, and sends the first operation on a
    connection the kernel has already reset."""
    sessions = [requests.Session() for _ in range(count)]
    for session in sessions:
        assert session.get(server.url(), auth=creds("alice"), timeout=5).status_code == 200
    (worker,) = server.worker_pids()

    with ThreadPoolExecutor(max_workers=count) as pool:
        os.kill(worker, signal.SIGSTOP)
        try:
            futures = [pool.submit(session_status, session, server.url()) for session in sessions]
            time.sleep(0.3)
            proxy.reset()
            time.sleep(0.3)
        finally:
            os.kill(worker, signal.SIGCONT)
        return [future.result() for future in futures]


@pytest.mark.parametrize("starter", [start, start_with_user_bind], ids=["search", "user-bind"])
def test_operation_sent_on_a_reset_connection_is_503(nginx, proxy, starter):
    # The failed send made OpenLDAP close its sockbuf inside
    # ldap_search_ext(); shutdown() of the reset socket failed, and the
    # sockbuf close called close_connection(), which unbound the same LDAP
    # handle again from inside the library: the worker hung for good
    # (PR #250 a02deb2, PR #251 3bdf4bc). Then the failed call was taken
    # for an answer about the credentials (401), and the dead connection
    # went back to the pool.
    server = starter(nginx, proxy)

    (result,) = keepalive_requests_while_the_connection_is_reset(server, proxy, 1)

    assert result is not None, "the request was never answered"
    assert result == 503
    assert "failed (-1: Can't contact LDAP server)" in server.log()
    wait_until_ready(server)


def test_connection_reset_under_a_send_is_not_handed_to_the_next_request(nginx, proxy):
    # The connection whose send failed has lost its socket inside OpenLDAP.
    # Given back to the pool, it went to the next request, which failed on
    # it too instead of waiting for the reconnect.
    server = start(nginx, proxy)

    results = keepalive_requests_while_the_connection_is_reset(server, proxy, 2)

    assert sorted(results, key=str) == [200, 503]


def test_connection_closed_after_a_request_timeout_is_reconnected_at_once(nginx, proxy):
    # The request that timed out took its connection down with it; nothing
    # says the server is down. With a long reconnect_timeout the next
    # requests waited for it and timed out too (audit V-04, PR #251 90708be).
    body = "require valid_user;\nconnections 1;\nreconnect_timeout 30s;\nrequest_timeout 1s;"
    url = url_for("127.0.0.1", proxy.port)
    server = nginx.start(http=ldap_server("proxied", body, url=url), server=protected_location("proxied"))
    wait_until_ready(server)

    with proxy.holding():
        assert status(server, "alice") == 503

    assert status(server, "bob") == 200
    assert proxy.connections == 2


@pytest.mark.parametrize("cut", ["drop", "reset"])
def test_idle_connection_closed_by_the_server_is_replaced_at_once(nginx, proxy, cut):
    # Servers and firewalls close idle connections (Active Directory after
    # 15 minutes by default). That is not an outage: the connection is
    # opened again at once and quietly, without waiting for
    # reconnect_timeout, during which every request failed with 503 and
    # each drop was logged as an error (kvspb#136 #222 #51).
    body = "require valid_user;\nconnections 1;\nreconnect_timeout 30s;\nrequest_timeout 2s;"
    url = url_for("127.0.0.1", proxy.port)
    server = nginx.start(http=ldap_server("proxied", body, url=url), server=protected_location("proxied"))
    wait_until_ready(server)
    since = server.log_size()

    getattr(proxy, cut)()
    time.sleep(0.3)

    assert status(server, "bob") == 200
    assert proxy.connections == 2
    log = server.log(since)
    assert "[error]" not in log, log
    assert "closed the idle connection" in log


class StopsReadingAfterTheBind(FakeLdapServer):
    """Answers the service bind, then reads nothing for a while: a large
    request fills the socket buffers and nginx gets EAGAIN under its send."""

    def __init__(self, pause: float) -> None:
        super().__init__()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        self.pause = pause
        self.bound = threading.Event()

    def close_after(self, op: int) -> bool:
        if op == BIND_REQUEST and not self.bound.is_set():
            self.bound.set()
            time.sleep(self.pause)
        return False


@pytest.mark.parametrize("events", ["epoll", "poll"])
def test_operation_that_fills_the_send_buffer_is_sent_in_full(nginx, events):
    # libldap leaves an operation whose send got EAGAIN in the "writing"
    # state and sends the rest only from ldap_result() once the socket is
    # writable. The write handler of the connection did nothing, so the
    # search waited for the request_timeout although the server read again.
    fake = StopsReadingAfterTheBind(pause=1)
    try:
        body = "require valid_user;\nconnections 1;\nrequest_timeout 5s;"
        nginx.start(
            http=ldap_server("slow", body, url=fake.url()),
            server="large_client_header_buffers 2 8m;\n" + protected_location("slow"),
            events=f"use {events};",
        )
        assert fake.bound.wait(5), "the service bind never arrived"
        # Larger than the socket buffers of both ends together.
        login = "x" * (5 * 1024 * 1024)
        started = time.monotonic()
        response = requests.get(nginx.url(), auth=(login, "secret"), timeout=10)
        elapsed = time.monotonic() - started

        assert response.status_code == 401, nginx.log()
        assert elapsed < 4, f"the search was sent in full only after {elapsed:.1f} s"
        assert "Authentication timed out" not in nginx.log()
    finally:
        fake.close()


class DropsAfterTheBind(FakeLdapServer):
    """Accepts the service bind, then closes the connection at once."""

    def close_after(self, op: int) -> bool:
        return op == BIND_REQUEST


def test_server_that_drops_every_connection_is_not_reconnected_in_a_loop(nginx):
    fake = DropsAfterTheBind()
    try:
        body = "require valid_user;\nconnections 1;\nreconnect_timeout 1s;"
        nginx.start(http=ldap_server("dropping", body, url=fake.url()), server=protected_location("dropping"))
        time.sleep(1.5)

        # The first connect, one immediate reconnect after the first drop,
        # then one per reconnect_timeout.
        assert 2 <= fake.connections <= 4, fake.connections
    finally:
        fake.close()


def open_sockets(pid: int) -> int:
    return sum(1 for fd in Path(f"/proc/{pid}/fd").iterdir() if fd.resolve().name.startswith("socket:"))


def test_connections_do_not_pile_up_under_load_with_drops(nginx, proxy):
    # kvspb#186: with max_down_retries the number of connections in the
    # "writing" state grew steadily under load while the server dropped
    # connections. Neither the LDAP connections nor the client connections
    # of the worker may outgrow the pool once the load is over.
    body = "require valid_user;\nconnections 3;\nmax_down_retries 5;\nreconnect_timeout 200ms;\nrequest_timeout 2s;"
    url = url_for("127.0.0.1", proxy.port)
    server = nginx.start(http=ldap_server("proxied", body, url=url), server=protected_location("proxied"))
    wait_until_ready(server)
    (worker,) = server.worker_pids()
    before = open_sockets(worker)

    with ThreadPoolExecutor(max_workers=16) as pool:
        pending = [pool.submit(status, server, uid, 10) for uid in ["alice", "bob", "carol", "dave"] * 50]
        for _ in range(5):
            time.sleep(0.2)
            proxy.drop()
        results = [p.result() for p in pending]

    assert set(results) <= {200, 503}
    wait_until_ready(server)
    time.sleep(0.5)
    assert open_sockets(worker) <= before
