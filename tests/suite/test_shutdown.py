"""Graceful shutdown (SIGQUIT, and the old worker of a reload).

A worker that shuts down gracefully finishes its requests and exits once no
timer that cannot be cancelled is left. The reconnect timer of an LDAP
connection could not be cancelled: while a server was down the worker
reconnected for ever and never exited. A worker that did exit left its
LDAP sockets open, which nginx reports as "open socket ... left" (audit
F03).
"""

from __future__ import annotations

import time

import pytest

from conftest import ldap_server, protected_location, url_for
from ldapdata import LDAP_HOST, LDAPS_PORT, PEOPLE_DN, creds
from ldapproxy import LdapProxy


def test_quit_while_the_server_is_down(nginx, closed_port):
    # Longer than the wait below: the worker must not wait for the timer.
    body = "require valid_user;\nconnect_timeout 1s;\nreconnect_timeout 30s;"
    server = nginx.start(
        http=ldap_server("down", body, url=url_for("127.0.0.1", closed_port)),
        server=protected_location("down"),
    )

    assert server.quit(timeout=5), "the worker kept reconnecting and never exited"


def test_quit_closes_the_ldap_connections(nginx):
    body = "require valid_user;\nconnections 2;"
    http = ldap_server("first", body) + ldap_server("second", body)
    server = nginx.start(http=http, server=protected_location("first second"))
    assert server.get(auth=creds("alice")).status_code == 200

    assert server.quit(timeout=5)
    assert "open socket" not in server.log()


@pytest.mark.parametrize("scheme", ["ldap", "ldaps", "starttls"])
def test_quit_does_not_wait_for_a_connection_that_is_coming_up(nginx, scheme):
    # The server never answers the service bind, the StartTLS request or
    # the TLS handshake. Their connect_timeout and bind_timeout guard only
    # the pool connection, never a request, yet a worker shutting down
    # waited for them as for a request.
    port = LDAPS_PORT if scheme == "ldaps" else 389
    with LdapProxy(upstream=(LDAP_HOST, port)) as silent:
        silent.hold()
        body = "require valid_user;\nconnections 1;\nconnect_timeout 30s;\nbind_timeout 30s;"
        if scheme == "starttls":
            body += "\nstarttls on;\nssl_check_cert off;"
        if scheme == "ldaps":
            body += "\nssl_check_cert off;"
            url = f"ldaps://127.0.0.1:{silent.port}/{PEOPLE_DN}?uid?sub?(objectClass=inetOrgPerson)"
        else:
            url = url_for("127.0.0.1", silent.port)
        server = nginx.start(http=ldap_server("silent", body, url=url), server=protected_location("silent"))
        end = time.monotonic() + 3
        while not silent.sent and time.monotonic() < end:
            time.sleep(0.05)
        assert silent.sent, "nothing reached the server"

        assert server.quit(timeout=5), "the worker waited for the timer of the connection"
        assert "open socket" not in server.log()


def test_shutdown_timeout_closes_a_connection_that_is_still_binding(nginx):
    # worker_shutdown_timeout marks every connection "close" and calls its
    # read handler. The LDAP read handler found nothing to read and kept
    # the connection, so its bind_timeout held the worker until it fired.
    with LdapProxy() as silent:
        silent.hold()
        body = "require valid_user;\nconnections 1;\nbind_timeout 30s;"
        server = nginx.start(
            http=ldap_server("silent", body, url=url_for("127.0.0.1", silent.port)),
            server=protected_location("silent"),
            main="worker_shutdown_timeout 300ms;",
        )
        end = time.monotonic() + 3
        while silent.connections == 0 and time.monotonic() < end:
            time.sleep(0.05)
        assert silent.connections == 1
        # Let the service bind reach the server.
        time.sleep(0.2)

        assert server.quit(timeout=5), "the worker waited for the bind_timeout"
        assert "open socket" not in server.log()
