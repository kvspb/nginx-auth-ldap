"""Shared fixtures for the integration suite."""

from __future__ import annotations

import shutil

import pytest

from harness import Nginx, new_prefix
from ldapdata import BIND_DN, BIND_SECRET, USERS_URL


def ldap_server(name: str, body: str = "require valid_user;", url: str = USERS_URL) -> str:
    """Render an ``ldap_server`` block bound with the service account."""
    return f"""
ldap_server {name} {{
    url "{url}";
    binddn "{BIND_DN}";
    binddn_passwd "{BIND_SECRET}";
    {body}
}}
"""


def protected_location(servers: str, path: str = "/", extra: str = "") -> str:
    """A location guarded by auth_ldap that answers 200 "ok" when allowed.

    The body is a static file on purpose: "return" runs in the rewrite phase,
    before the access phase, and would bypass authentication entirely.
    """
    return f"""
location {path} {{
    auth_ldap "Restricted";
    auth_ldap_servers {servers};
    {extra}
    root html;
    default_type text/plain;
    try_files /ok =404;
}}
"""


def _fail_on_crash(
    request: pytest.FixtureRequest, instance: Nginx, since: int, workers: frozenset[int] | None
) -> None:
    """Fail the current test if a worker died or a sanitizer reported an error.

    A documented known bug (marked xfail) may crash: that is part of the
    expected failure.
    """
    crashes = instance.crashes(since=since, workers=workers)
    if crashes and request.node.get_closest_marker("xfail") is None:
        pytest.fail(f"nginx worker crashed: {crashes}\n--- error.log ---\n{instance.log(since)}")


@pytest.fixture
def nginx(request: pytest.FixtureRequest):
    """A fresh nginx instance for one test, checked for crashes afterwards.

    Use it for tests that depend on state (cache, connection pool, a crash,
    environment such as MALLOC_PERTURB_) or that need a unique configuration.
    """
    prefix = new_prefix()
    instance = Nginx(prefix)
    yield instance

    if instance.process is not None:
        _fail_on_crash(request, instance, since=0, workers=instance.started_workers)
    instance.stop()
    shutil.rmtree(prefix, ignore_errors=True)


_SHARED: list[Nginx] = []


@pytest.fixture(scope="class")
def shared_nginx():
    """One nginx instance for a whole test class.

    Start it from a class-scoped fixture of the class. Only for tests that
    neither depend on nor leave behind state, so that their order does not
    matter. Each test is still checked for crashes on its own by
    _crash_guard, which only looks at log lines written during that test.
    """
    prefix = new_prefix()
    instance = Nginx(prefix)
    _SHARED.append(instance)
    yield instance

    _SHARED.remove(instance)
    instance.stop()
    shutil.rmtree(prefix, ignore_errors=True)


@pytest.fixture(autouse=True)
def _crash_guard(request: pytest.FixtureRequest):
    # Class-scoped fixtures are set up before this one, so a shared instance
    # is already running here.
    snapshots = [
        (instance, instance.log_size(), instance.worker_pids())
        for instance in _SHARED
        if instance.process is not None
    ]
    yield
    for instance, since, workers in snapshots:
        _fail_on_crash(request, instance, since, workers)
