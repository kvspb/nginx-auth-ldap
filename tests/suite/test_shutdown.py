"""Graceful shutdown (SIGQUIT, and the old worker of a reload).

A worker that shuts down gracefully finishes its requests and exits once no
timer that cannot be cancelled is left. The reconnect timer of an LDAP
connection could not be cancelled: while a server was down the worker
reconnected for ever and never exited. A worker that did exit left its
LDAP sockets open, which nginx reports as "open socket ... left" (audit
F03).
"""

from __future__ import annotations

from conftest import ldap_server, protected_location, url_for
from ldapdata import creds


def test_quit_while_the_server_is_down(nginx, closed_port):
    # Longer than the wait below: the worker must not wait for the timer.
    body = "require valid_user;\nconnect_timeout 1s;\nreconnect_timeout 30s;"
    server = nginx.start(
        http=ldap_server("down", body, url=url_for("127.0.0.1", closed_port)), server=protected_location("down")
    )

    assert server.quit(timeout=5), "the worker kept reconnecting and never exited"


def test_quit_closes_the_ldap_connections(nginx):
    body = "require valid_user;\nconnections 2;"
    http = ldap_server("first", body) + ldap_server("second", body)
    server = nginx.start(http=http, server=protected_location("first second"))
    assert server.get(auth=creds("alice")).status_code == 200

    assert server.quit(timeout=5)
    assert "open socket" not in server.log()
