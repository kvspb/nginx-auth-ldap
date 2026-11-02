"""Requests proxied to an upstream after LDAP authentication.

A request that waits for LDAP is resumed from the read handler of the LDAP
connection, not from an event of its own client connection. The proxy
module then talks to the upstream on behalf of a request that was parked:
reports were "header already sent while reading response header from
upstream" with proxied static files (kvspb#130) and a failed WebSocket
handshake (kvspb#190). Each test holds the LDAP answers so that the
request really waits, then checks what the upstream got and what the
client got.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

from conftest import TIMEOUTS, ldap_server, url_for
from ldapdata import creds
from ldapproxy import LdapProxy

STATIC = bytes(range(256)) * 256  # 64 KiB, larger than the proxy buffers
SLOW_REPLY_DELAY = 1.5
WS_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
WS_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


class Upstream(BaseHTTPRequestHandler):
    """Static files, an echo of the request body, and a WebSocket echo."""

    protocol_version = "HTTP/1.1"
    seen: list[str]

    def log_message(self, format: str, *args) -> None:  # keep pytest output clean
        pass

    def reply(self, body: bytes, content_type: str = "application/octet-stream") -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self.seen.append(f"GET {self.path}")
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self.websocket()
        elif self.path.startswith("/slow/"):
            time.sleep(SLOW_REPLY_DELAY)
            self.reply(STATIC)
        else:
            self.reply(STATIC)

    def do_POST(self) -> None:
        self.seen.append(f"POST {self.path}")
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = bytearray()
            while True:
                size = int(self.rfile.readline().split(b";")[0], 16)
                if size == 0:
                    break
                body += self.rfile.read(size + 2)[:size]
            # Trailer fields, if any, up to the empty line.
            while self.rfile.readline() not in (b"\r\n", b""):
                pass
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.reply(f"{len(body)} {hashlib.sha256(body).hexdigest()}".encode(), "text/plain")

    def websocket(self) -> None:
        # The sample key of RFC 6455, 1.3, and its accept value: the client
        # always sends that key, so no SHA-1 is computed here.
        if self.headers["Sec-WebSocket-Key"] != WS_KEY:
            self.send_error(400)
            return
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", WS_ACCEPT)
        self.end_headers()
        self.wfile.flush()
        # Not a WebSocket implementation: the tunnel only has to carry bytes.
        self.connection.settimeout(5)
        while data := self.connection.recv(4096):
            self.connection.sendall(data)
        self.close_connection = True


class UpstreamServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        self.seen: list[str] = []
        handler = type("Handler", (Upstream,), {"seen": self.seen})
        super().__init__(("127.0.0.1", 0), handler)


@pytest.fixture
def upstream():
    httpd = UpstreamServer()
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def proxy():
    with LdapProxy() as ldap:
        yield ldap


def locations(port: int, servers: str = "users") -> str:
    auth = f'auth_ldap "Restricted";\nauth_ldap_servers {servers};'
    return f"""
location / {{
    {auth}
    proxy_pass http://127.0.0.1:{port};
    proxy_buffer_size 4k;
    proxy_buffers 4 4k;
}}

location /unbuffered/ {{
    {auth}
    proxy_pass http://127.0.0.1:{port};
    proxy_request_buffering off;
    proxy_buffering off;
    # A chunked body is streamed only over HTTP/1.1; with 1.0 nginx
    # buffers it whatever proxy_request_buffering says.
    proxy_http_version 1.1;
}}

location /ws {{
    {auth}
    proxy_pass http://127.0.0.1:{port};
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 10s;
}}
"""


def start(nginx, proxy, upstream, extra_servers: str = "", servers: str = "users"):
    users = ldap_server(
        "users", f"require valid_user;\nconnections 2;{TIMEOUTS}", url=url_for("127.0.0.1", proxy.port)
    )
    server = nginx.start(http=users + extra_servers, server=locations(upstream.server_port, servers))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            if server.get("/warm-up", auth=creds("alice"), timeout=3).status_code == 200:
                upstream.seen.clear()
                return server
        except requests.ConnectionError:
            pass
        time.sleep(0.1)
    pytest.fail("the LDAP connection pool did not become ready")


def assert_clean(server) -> None:
    log = server.log()
    assert "[alert]" not in log, log
    assert "header already sent" not in log, log


def test_proxied_files_after_waiting_for_ldap(nginx, proxy, upstream):
    # kvspb#130: static files behind proxy_pass, many at once on a few
    # LDAP connections, each request waiting for its answer.
    server = start(nginx, proxy, upstream)
    paths = [f"/static/{i}.js" for i in range(24)]

    with requests.Session() as first, requests.Session() as second, ThreadPoolExecutor(max_workers=8) as pool:
        sessions = [first, second]
        proxy.hold()
        futures = [
            pool.submit(sessions[i % 2].get, server.url(path), auth=creds("alice"), timeout=10)
            for i, path in enumerate(paths)
        ]
        time.sleep(0.3)
        proxy.release()
        responses = [future.result() for future in futures]

    assert [response.status_code for response in responses] == [200] * len(paths)
    assert all(response.content == STATIC for response in responses)
    assert sorted(upstream.seen) == sorted(f"GET {path}" for path in paths)
    assert_clean(server)


@pytest.mark.parametrize("path", ["/echo", "/unbuffered/echo"], ids=["buffered", "unbuffered"])
@pytest.mark.parametrize("chunked", [False, True], ids=["content-length", "chunked"])
def test_request_body_reaches_the_upstream_after_waiting_for_ldap(nginx, proxy, upstream, path, chunked):
    # The body arrives while the request waits for LDAP; it must reach the
    # upstream whole, buffered by nginx or streamed.
    server = start(nginx, proxy, upstream)
    body = bytes(range(256)) * 4096  # 1 MiB
    data = (body[i : i + 65536] for i in range(0, len(body), 65536)) if chunked else body

    with ThreadPoolExecutor(max_workers=1) as pool:
        proxy.hold()
        future = pool.submit(
            requests.post,
            server.url(path),
            data=data,
            auth=creds("alice"),
            headers={"Content-Type": "application/octet-stream"},
            timeout=10,
        )
        time.sleep(0.3)
        proxy.release()
        response = future.result()

    assert response.status_code == 200
    assert response.text == f"{len(body)} {hashlib.sha256(body).hexdigest()}"
    assert_clean(server)


def test_request_body_of_a_denied_request_is_not_proxied(nginx, proxy, upstream):
    server = start(nginx, proxy, upstream)

    response = requests.post(server.url("/echo"), data=b"x" * 100000, auth=("alice", "wrong"), timeout=10)

    assert response.status_code == 401
    assert upstream.seen == []
    assert_clean(server)


def websocket_handshake(server, auth: tuple[str, str]) -> tuple[socket.socket, bytes]:
    token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    sock = socket.create_connection(("127.0.0.1", server.port), timeout=10)
    sock.sendall(
        (
            "GET /ws?books=1 HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{server.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {WS_KEY}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Authorization: Basic {token}\r\n"
            "\r\n"
        ).encode()
    )
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(4096)
        if not chunk:
            break
        head += chunk
    return sock, head


@pytest.mark.parametrize("wait", [False, True], ids=["answered-at-once", "after-waiting-for-ldap"])
def test_websocket_upgrade_is_proxied(nginx, proxy, upstream, wait):
    # kvspb#190: the handshake answered 400 behind auth_ldap.
    server = start(nginx, proxy, upstream)

    with ThreadPoolExecutor(max_workers=1) as pool:
        if wait:
            proxy.hold()
        future = pool.submit(websocket_handshake, server, creds("alice"))
        if wait:
            time.sleep(0.3)
            proxy.release()
        sock, head = future.result()

    with sock:
        assert head.startswith(b"HTTP/1.1 101 "), head
        assert f"Sec-WebSocket-Accept: {WS_ACCEPT}".encode() in head
        # The tunnel carries bytes both ways after the upgrade.
        sock.sendall(b"ping through the tunnel")
        assert sock.recv(4096) == b"ping through the tunnel"

    assert upstream.seen == ["GET /ws?books=1"]
    assert_clean(server)


def test_websocket_upgrade_with_a_wrong_password_is_refused(nginx, proxy, upstream):
    server = start(nginx, proxy, upstream)

    sock, head = websocket_handshake(server, ("alice", "wrong"))
    sock.close()

    assert head.startswith(b"HTTP/1.1 401 "), head
    assert upstream.seen == []


def test_late_answer_of_a_timed_out_server_leaves_the_proxied_request_alone(nginx, proxy, upstream):
    # The first server does not answer within its request_timeout, so the
    # second one allows the request, which goes to a slow upstream. The
    # late answer of the first server arrives while nginx waits for the
    # upstream: it must not run the request again (a second proxied
    # request on the same request gives "header already sent").
    second = ldap_server("second")
    server = start(nginx, proxy, upstream, extra_servers=second, servers="users second")

    with ThreadPoolExecutor(max_workers=1) as pool:
        proxy.hold()
        future = pool.submit(server.get, "/slow/app.js", auth=creds("alice"), timeout=10)
        # request_timeout 1s, then the upstream takes SLOW_REPLY_DELAY.
        time.sleep(1.5)
        proxy.release()
        response = future.result()

    assert 'Authentication timed out on server "users"' in server.log()
    assert response.status_code == 200
    assert response.content == STATIC
    assert upstream.seen == ["GET /slow/app.js"]
    assert_clean(server)
