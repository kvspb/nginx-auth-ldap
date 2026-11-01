"""The result cache keys an outcome on everything the decision depends on.

Each test starts its own nginx: the cache is per-worker state that would
leak between tests sharing an instance.
"""

import time
from collections.abc import Iterator

import pytest

from conftest import ldap_server, protected_location, url_for
from ldapdata import GROUPS_DN, PEOPLE_DN, changed_password, creds, user_dn
from ldapproxy import LdapProxy

CACHE = """
auth_ldap_cache_enabled on;
auth_ldap_cache_expiration_time 10000;
auth_ldap_cache_size 1000;
"""

REQUIRE_USER = f'satisfy all;\nrequire user "uid=$arg_v,{PEOPLE_DN}";'
REQUIRE_GROUP = f'group_attribute member;\ngroup_attribute_is_dn on;\nsatisfy all;\nrequire group "cn=$arg_v,{GROUPS_DN}";'
VALID_USER_DN = f'require valid_user "uid=$arg_v,{PEOPLE_DN}";'
# The variable is in the second template: every template is part of the key.
SECOND_REQUIRE_USER = (
    f'satisfy any;\nrequire user "{user_dn("nobody")}";\nrequire user "uid=$arg_v,{PEOPLE_DN}";'
)

# Each case: server body, a value of $arg_v that admits alice, one that does not.
TEMPLATES = [
    pytest.param(REQUIRE_USER, "alice", "bob", id="require-user"),
    pytest.param(REQUIRE_GROUP, "admins", "ops", id="require-group"),
    pytest.param(VALID_USER_DN, "alice", "bob", id="valid-user-dn"),
    pytest.param(SECOND_REQUIRE_USER, "alice", "bob", id="second-require-user"),
]


@pytest.fixture
def proxy() -> Iterator[LdapProxy]:
    proxy = LdapProxy()
    yield proxy
    proxy.close()


def start(nginx, body: str, url: str | None = None):
    kwargs = {} if url is None else {"url": url}
    return nginx.start(
        http=CACHE + ldap_server("cached", body, **kwargs), server=protected_location("cached")
    )


# A require template that references a request variable gives different
# decisions for the same login and password. An ALLOW stored for one
# expansion must not be served for another one (FIX-12).


@pytest.mark.parametrize(("body", "allowed", "denied"), TEMPLATES)
def test_cache_does_not_serve_an_allow_for_another_template_expansion(nginx, body, allowed, denied):
    server = start(nginx, body)
    assert server.get(f"/?v={allowed}", auth=creds("alice")).status_code == 200

    assert server.get(f"/?v={denied}", auth=creds("alice")).status_code == 401


@pytest.mark.parametrize(("body", "allowed", "denied"), TEMPLATES)
def test_cache_serves_the_same_template_expansion(nginx, proxy, body, allowed, denied):
    # Guards the test above: with the directory unable to answer, only the
    # cache can allow the second request.
    server = start(nginx, body + "\nrequest_timeout 1s;", url=url_for("127.0.0.1", proxy.port))
    assert server.get(f"/?v={allowed}", auth=creds("alice")).status_code == 200

    with proxy.holding():
        assert server.get(f"/?v={allowed}", auth=creds("alice"), timeout=5).status_code == 200


def test_cache_does_not_join_adjacent_template_values(nginx):
    # Values are hashed with their lengths: "...dc=org" + "X" must not give
    # the key of "...dc=or" + "gX".
    body = 'satisfy any;\nrequire user "$arg_a";\nrequire user "$arg_b";'
    server = start(nginx, body)
    alice = user_dn("alice")
    assert server.get(f"/?a={alice}&b=X", auth=creds("alice")).status_code == 200

    assert server.get(f"/?a={alice[:-1]}&b={alice[-1]}X", auth=creds("alice")).status_code == 401


def test_cache_does_not_serve_an_allow_for_another_password(nginx):
    # Same login, a wrong password of the same length.
    server = start(nginx, "require valid_user;")
    assert server.get(auth=creds("alice")).status_code == 200

    login, secret = creds("alice")
    assert server.get(auth=(login, secret[:-1] + "X")).status_code == 401


def test_cache_entry_survives_a_reconnect(nginx, proxy):
    # The key used to hash raw server struct bytes, a runtime retry counter
    # among them, so entries stored before a server flap were lost after it.
    body = "require valid_user;\nconnections 1;\nmax_down_retries 1;\nreconnect_timeout 200ms;"
    server = start(nginx, body, url=url_for("127.0.0.1", proxy.port))
    assert server.get(auth=creds("erin")).status_code == 200

    proxy.drop()
    time.sleep(0.5)
    assert proxy.connections == 2

    with changed_password("erin", "rotated-secret"):
        assert server.get(auth=creds("erin")).status_code == 200


def test_every_slot_of_a_bucket_is_used(nginx, proxy):
    # One login with different passwords always lands in the same bucket of
    # eight entries. The eviction loop never looked at the eighth slot, so
    # the eighth outcome pushed out the first one although a slot was free
    # (nal-toj.17). A ninth outcome replaces the oldest entry of the bucket.
    body = "require valid_user;\nconnections 1;\nrequest_timeout 1s;"
    server = start(nginx, body, url=url_for("127.0.0.1", proxy.port))
    wrong = [f"wrong-{i}" for i in range(9)]
    for secret in wrong:
        assert server.get(auth=("alice", secret)).status_code == 401
        time.sleep(0.01)

    # Answered from the cache (401), or held until request_timeout (503).
    with proxy.holding():
        assert [server.get(auth=("alice", secret)).status_code for secret in wrong] == [503] + [401] * 8


@pytest.mark.parametrize(
    ("expiration", "wait", "expected"),
    [
        # The age limit was computed as now - expiration on the monotonic
        # clock of nginx, which counts from the boot of the host: while the
        # host had been up for less than the expiration time it wrapped below
        # zero, and no cached outcome was ever used (fresh CI runners, any
        # host after a reboot). Ten years is longer than any uptime.
        pytest.param("3650d", 0, 200, id="longer-than-the-uptime"),
        pytest.param("1s", 1.2, 503, id="expired"),
    ],
)
def test_cache_expiration(nginx, proxy, expiration, wait, expected):
    http = f"auth_ldap_cache_enabled on;\nauth_ldap_cache_expiration_time {expiration};\n" + ldap_server(
        "cached", "require valid_user;\nrequest_timeout 1s;", url=url_for("127.0.0.1", proxy.port)
    )
    server = nginx.start(http=http, server=protected_location("cached"))
    assert server.get(auth=creds("alice")).status_code == 200
    time.sleep(wait)

    # Answered from the cache (200), or held until request_timeout (503).
    with proxy.holding():
        assert server.get(auth=creds("alice")).status_code == expected
