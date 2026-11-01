"""Interaction with nginx core "satisfy any" and other access modules."""

import subprocess

import pytest

from conftest import TIMEOUTS, ldap_server, protected_location, url_for
from ldapdata import creds

# glibc fills fresh allocations with this byte, so fields the module leaves
# uninitialised hold garbage instead of the zeroes a new page usually has.
POISON = {"MALLOC_PERTURB_": "165"}

ALLOW_LOCAL = """
satisfy any;
allow 127.0.0.1;
deny all;
"""


def test_satisfy_any_with_allow_lets_local_clients_in(nginx):
    # Regression for kvspb#249: on nginx >= 1.23 the core walks the
    # WWW-Authenticate list through ->next once another access module allows
    # the request, so the header pushed by the module must terminate it.
    # Since the module runs after "allow", it is not even asked here.
    nginx.env.update(POISON)
    server = nginx.start(http=ldap_server("users"), server=protected_location("users", extra=ALLOW_LOCAL))

    # No credentials: "allow" grants access.
    response = server.get()

    assert response.status_code == 200
    assert not server.crashes()


def test_satisfy_any_still_accepts_ldap_credentials(nginx):
    deny_everyone = "satisfy any;\ndeny all;"
    server = nginx.start(http=ldap_server("users"), server=protected_location("users", extra=deny_everyone))

    assert server.get(auth=creds("alice")).status_code == 200


LOCAL = ("local", "local-secret")


def start_with_auth_basic(nginx, satisfy: str, url: str | None = None, body: str = "require valid_user;"):
    """auth_ldap and auth_basic with an htpasswd file in one location.

    auth_ldap runs last, after auth_basic and allow/deny.
    """
    digest = subprocess.run(
        ["openssl", "passwd", "-apr1", LOCAL[1]], capture_output=True, text=True, check=True
    ).stdout.strip()
    (nginx.prefix / "conf").mkdir(parents=True, exist_ok=True)
    (nginx.prefix / "conf" / "htpasswd").write_text(f"{LOCAL[0]}:{digest}\n")
    extra = f'satisfy {satisfy};\nauth_basic "Restricted";\nauth_basic_user_file htpasswd;'
    kwargs = {} if url is None else {"url": url}
    return nginx.start(
        http=ldap_server("users", body, **kwargs), server=protected_location("users", extra=extra)
    )


@pytest.mark.parametrize(
    ("auth", "expected"),
    [
        pytest.param(creds("alice"), 200, id="ldap-user"),
        pytest.param(LOCAL, 200, id="htpasswd-user"),
        pytest.param(("alice", "wrong"), 401, id="neither"),
        pytest.param(None, 401, id="no-credentials"),
    ],
)
def test_satisfy_any_with_auth_basic(nginx, auth, expected):
    # kvspb#256, kvspb#7: either module may let the user in.
    server = start_with_auth_basic(nginx, "any")

    response = server.get(auth=auth)

    assert response.status_code == expected
    if expected == 200:
        assert "WWW-Authenticate" not in response.headers
    else:
        assert 'Basic realm="Restricted"' in response.headers["WWW-Authenticate"]


@pytest.mark.parametrize(
    ("auth", "expected"),
    [
        pytest.param(creds("alice"), 401, id="ldap-user"),
        pytest.param(LOCAL, 401, id="htpasswd-user"),
    ],
)
def test_satisfy_all_with_auth_basic(nginx, auth, expected):
    # Both modules must let the user in: no user is in both.
    server = start_with_auth_basic(nginx, "all")

    assert server.get(auth=auth).status_code == expected


def test_htpasswd_user_gets_in_while_ldap_is_down(nginx, closed_port):
    # kvspb#108: a local fallback for when the directory cannot be reached.
    # An unavailable LDAP server answered 503 at once under satisfy any, and
    # auth_basic never got to allow the user.
    url = url_for("127.0.0.1", closed_port)
    server = start_with_auth_basic(nginx, "any", url=url, body=f"require valid_user;{TIMEOUTS}")

    assert server.get(auth=LOCAL).status_code == 200
    # Nobody let alice in, and LDAP could not decide.
    assert server.get(auth=creds("alice")).status_code == 503


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        pytest.param("satisfy any;\ndeny all;", 503, id="satisfy-any"),
        pytest.param("satisfy all;", 503, id="satisfy-all"),
    ],
)
def test_ldap_down_without_another_way_in_is_503(nginx, closed_port, extra, expected):
    url = url_for("127.0.0.1", closed_port)
    server = nginx.start(
        http=ldap_server("users", f"require valid_user;{TIMEOUTS}", url=url),
        server=protected_location("users", extra=extra),
    )

    assert server.get(auth=creds("alice")).status_code == expected
