"""A connect() that completes at once (PR #617).

ngx_event_connect_peer() returns NGX_OK instead of NGX_AGAIN when connect()
succeeds before it returns, as a loopback connect may on Solaris or the
BSDs. With the select and poll event methods nginx then does not add the
write event, so the connect handler never ran: the connection stayed in
STATE_CONNECTING until connect_timeout, was closed and opened again the
same way, and the server was never usable. "test_connect_sync on" (from
tests/modules/connect_sync) makes connect() behave like that on Linux.
"""

from __future__ import annotations

import pytest

from conftest import TIMEOUTS, ldap_server, protected_location, url_for
from ldapdata import LDAP_HOST, TLS_DIR, creds, ldaps_url

CA = TLS_DIR / "ca.crt"
TLS = f"ssl_check_cert on;\nssl_ca_file {CA};\n"


@pytest.mark.parametrize(
    ("url", "extra"),
    [
        pytest.param(url_for(LDAP_HOST, 389), "", id="ldap"),
        pytest.param(ldaps_url(), TLS, id="ldaps"),
        pytest.param(url_for(LDAP_HOST, 389), "starttls on;\n" + TLS, id="starttls"),
    ],
)
@pytest.mark.parametrize("method", ["poll", "epoll"])
def test_connect_that_completes_at_once(nginx, method, url, extra):
    http = "test_connect_sync on;\n" + ldap_server("sync", f"require valid_user;{TIMEOUTS}{extra}", url=url)
    server = nginx.start(http=http, server=protected_location("sync"), events=f"use {method};")

    assert server.get(auth=creds("alice"), timeout=5).status_code == 200
    assert server.get(auth=("alice", "wrong"), timeout=5).status_code == 401
