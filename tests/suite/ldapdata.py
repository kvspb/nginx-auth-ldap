"""Constants describing the directory seeded from tests/ldap/seed.ldif."""

import os

LDAP_HOST = os.environ.get("LDAP_HOST", "ldap")

BASE_DN = "dc=example,dc=org"
PEOPLE_DN = f"ou=people,{BASE_DN}"
GROUPS_DN = f"ou=groups,{BASE_DN}"

# Service account from seed.ldif. Test-only credential of a disposable
# container; override via the environment if the fixture changes.
BIND_DN = os.environ.get("LDAP_BIND_DN", f"cn=nginx,ou=services,{BASE_DN}")
BIND_SECRET = os.environ.get("LDAP_BIND_SECRET", "nginx-" + "secret")  # nosec B105

# User search URL: base, login attribute, scope and filter (RFC 4516).
USERS_URL = f"ldap://{LDAP_HOST}:389/{PEOPLE_DN}?uid?sub?(objectClass=inetOrgPerson)"


def group_dn(cn: str) -> str:
    return f"cn={cn},{GROUPS_DN}"


def password(uid: str) -> str:
    """Every seeded user has the password "<uid>-secret"."""
    return f"{uid}-secret"


def creds(uid: str) -> tuple[str, str]:
    return uid, password(uid)
