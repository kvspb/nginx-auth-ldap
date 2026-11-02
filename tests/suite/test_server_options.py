"""ldap_server options that change how connections are used."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import ldap_server, protected_location
from ldapdata import BIND_SECRET, creds

UIDS = ["alice", "bob", "carol", "dave"] * 4


@pytest.mark.parametrize("referral", ["on", "off"])
def test_referral_setting_keeps_authentication_working(nginx, referral):
    body = f"require valid_user;\nreferral {referral};"
    server = nginx.start(http=ldap_server("users", body), server=protected_location("users"))

    assert server.get(auth=creds("alice")).status_code == 200


def test_one_connection_serves_concurrent_requests_in_turn(nginx):
    # With a single pooled connection the other requests wait in the queue and
    # are woken one after another as the connection is returned.
    body = "require valid_user;\nconnections 1;"
    server = nginx.start(http=ldap_server("users", body), server=protected_location("users"))

    with ThreadPoolExecutor(max_workers=len(UIDS)) as pool:
        statuses = list(pool.map(lambda uid: server.get(auth=creds(uid)).status_code, UIDS))

    assert statuses == [200] * len(UIDS)


def test_max_down_retries_is_accepted(nginx):
    body = "require valid_user;\nmax_down_retries 2;"
    server = nginx.start(http=ldap_server("users", body), server=protected_location("users"))

    assert server.get(auth=creds("alice")).status_code == 200


def secret_file(nginx, name: str, content: bytes):
    path = nginx.prefix / "conf" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def without_password(body: str) -> str:
    """An ldap_server block whose binddn_passwd line is left out."""
    return "\n".join(line for line in body.splitlines() if not line.strip().startswith('binddn_passwd "'))


@pytest.mark.parametrize(
    ("content", "where"),
    [
        pytest.param(BIND_SECRET.encode() + b"\n", "absolute", id="trailing-newline"),
        pytest.param(BIND_SECRET.encode() + b"\r\n", "absolute", id="trailing-crlf"),
        pytest.param(BIND_SECRET.encode(), "relative", id="relative-to-conf"),
    ],
)
def test_binddn_passwd_file(nginx, content, where):
    # The service password from a file of its own, such as a container
    # secret, instead of the configuration (kvspb#105, kvspb#217).
    path = secret_file(nginx, "ldap-secret", content)
    name = path if where == "absolute" else path.name
    http = without_password(ldap_server("users", f"require valid_user;\nbinddn_passwd_file {name};"))
    server = nginx.start(http=http, server=protected_location("users"))

    assert server.get(auth=creds("alice")).status_code == 200


@pytest.mark.parametrize(
    ("content", "extra", "text"),
    [
        pytest.param(None, "", 'cannot read binddn_passwd_file "', id="missing"),
        pytest.param(b"\n", "", 'binddn_passwd_file "', id="empty"),
        pytest.param(
            b"pw-in-file\n",
            f'binddn_passwd "{BIND_SECRET}";',
            '"binddn_passwd_file" and "binddn_passwd"',
            id="both",
        ),
        pytest.param(b"two\nlines\n", "", "more than one line", id="two-lines"),
        pytest.param(b"a" * 50 + b"\nsecond\n", "", "more than one line", id="long-first-line"),
        pytest.param(b"", "", "is empty", id="zero-bytes"),
        pytest.param(b"x" * 5000, "", 'cannot read binddn_passwd_file "', id="too-large"),
        pytest.param("directory", "", 'cannot read binddn_passwd_file "', id="directory"),
    ],
)
def test_binddn_passwd_file_errors(nginx, content, extra, text):
    path = nginx.prefix / "conf" / "ldap-secret"
    if content == "directory":
        path.mkdir(parents=True)
    elif content is not None:
        secret_file(nginx, "ldap-secret", content)
    body = f"require valid_user;\nbinddn_passwd_file {path};\n{extra}"
    result = nginx.check_config(
        http=without_password(ldap_server("users")).replace("require valid_user;", body),
        server=protected_location("users"),
    )

    assert result.returncode == 1, result.stderr
    assert text in result.stderr
    assert "pw-in-file" not in result.stderr


def test_binddn_passwd_file_of_the_largest_size(nginx):
    # Up to 4096 bytes are read; a larger file is refused (see above).
    path = secret_file(nginx, "ldap-secret", b"x" * 4096)
    body = f"require valid_user;\nbinddn_passwd_file {path};"
    result = nginx.check_config(
        http=without_password(ldap_server("users", body)), server=protected_location("users")
    )

    assert result.returncode == 0, result.stderr
