"""Constants describing the directory seeded from tests/ldap/seed.ldif."""

import os
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager

LDAP_HOST = os.environ.get("LDAP_HOST", "ldap")

BASE_DN = "dc=example,dc=org"
PEOPLE_DN = f"ou=people,{BASE_DN}"
GROUPS_DN = f"ou=groups,{BASE_DN}"

# Service account from seed.ldif. Test-only credential of a disposable
# container; override via the environment if the fixture changes.
BIND_DN = os.environ.get("LDAP_BIND_DN", f"cn=nginx,ou=services,{BASE_DN}")
BIND_SECRET = os.environ.get("LDAP_BIND_SECRET", "nginx-" + "secret")  # nosec B105

# Directory manager (rootdn in tests/ldap/slapd.conf), same caveats.
ADMIN_DN = f"cn=admin,{BASE_DN}"
ADMIN_SECRET = os.environ.get("LDAP_ADMIN_SECRET", "admin-" + "secret")  # nosec B105

# User search URL: base, login attribute, scope and filter (RFC 4516).
USERS_URL = f"ldap://{LDAP_HOST}:389/{PEOPLE_DN}?uid?sub?(objectClass=inetOrgPerson)"


def group_dn(cn: str) -> str:
    return f"cn={cn},{GROUPS_DN}"


def password(uid: str) -> str:
    """Every seeded user has the password "<uid>-secret"."""
    return f"{uid}-secret"


def creds(uid: str) -> tuple[str, str]:
    return uid, password(uid)


def user_dn(uid: str) -> str:
    return f"uid={uid},{PEOPLE_DN}"


def _set_password(uid: str, new: str) -> None:
    ldif = f"dn: {user_dn(uid)}\nchangetype: modify\nreplace: userPassword\nuserPassword: {new}\n"
    subprocess.run(
        ["ldapmodify", "-x", "-H", f"ldap://{LDAP_HOST}", "-D", ADMIN_DN, "-w", ADMIN_SECRET],
        input=ldif,
        text=True,
        capture_output=True,
        check=True,
        timeout=10,
    )


@contextmanager
def changed_password(uid: str, new: str) -> Iterator[None]:
    """Change a user's password in the directory, restoring it afterwards.

    Only use it for users reserved for that purpose (erin), so that other
    tests never see the temporary password.
    """
    _set_password(uid, new)
    try:
        yield
    finally:
        _set_password(uid, password(uid))
