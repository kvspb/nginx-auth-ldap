# Integration tests

The suite builds nginx from source with this module and checks real HTTP
requests against a real OpenLDAP server. Everything runs in Docker Compose;
the only host requirements are Docker and `make`.

```sh
make test                                   # nginx 1.30.6 (default)
make test NGINX_VERSION=1.22.1              # any release from nginx.org
make test-matrix                            # 1.22.1 (pre-1.23 API), 1.30.6 (stable), 1.31.8 (mainline)
make test PYTEST_ARGS="-k groups -x -vv"    # pytest arguments
make test PYTEST_ARGS="--runxfail"          # show how known bugs fail today
make test-down                              # stop LDAP, drop the build cache
```

Build options, passed as environment variables (each combination gets its own
cached build directory):

| Variable        | Effect                                                  |
| --------------- | ------------------------------------------------------- |
| `NGINX_VERSION` | nginx release to build against                          |
| `NGINX_DEBUG=1` | `--with-debug`; error logs are written at `debug` level |
| `SANITIZE=1`    | AddressSanitizer; any report fails the test             |

`NGINX_DEBUG=1` changes behaviour: in debug builds `ngx_queue_remove()`
clears the removed node, which hides double-removal bugs. Run the suite
without it as well.

## Layout

```text
tests/
  docker-compose.yml   ldap + tests services
  ldap/                OpenLDAP image; seed.ldif holds the directory fixtures
  runner/              toolchain image; run-tests.sh builds nginx and runs pytest
  suite/
    harness.py         Nginx: per-test prefix, config, start/stop, crash detection
    conftest.py        `nginx` fixture, ldap_server() / protected_location() helpers
    ldapdata.py        DNs and credentials matching seed.ldif
    test_*.py          tests, grouped by behaviour
```

The module source is mounted read-only at `/src`; nginx objects live in the
`build-cache` volume, so editing the module only recompiles one file.

## Writing a test

Group tests by configuration: a test class starts one nginx through the
class-scoped `shared_nginx` fixture, and its cases are parametrized with
readable ids. A known bug in one case is marked on that case only:

```python
class TestSatisfyAllOfTwoGroups:
    @pytest.fixture(scope="class")
    def server(self, shared_nginx):
        return groups_server(shared_nginx, "all", "admins", "ops")

    @pytest.mark.parametrize(("uid", "expected"), [
        pytest.param("dave", 200, id="both-groups"),
        pytest.param("alice", 401, id="first-group-only",
                     marks=pytest.mark.xfail(reason="... (#194)")),
    ])
    def test_access(self, server, uid, expected):
        assert server.get(auth=creds(uid)).status_code == expected
```

Use the function-scoped `nginx` fixture instead when a test depends on or
leaves behind state: the result cache, the connection pool, a crash, or
environment variables such as `MALLOC_PERTURB_`. Shared tests must pass in any
order. Plain classes only: no `unittest.TestCase`, no inheritance between
test classes.

- `protected_location()` serves a static file. Do not use `return` in a
  protected location: it runs in the rewrite phase, before the access phase,
  and bypasses authentication.
- Both fixtures fail the test when a worker dies (`exited on signal`) or
  AddressSanitizer reports an error. For a shared instance only the log lines
  written during that test count, so a crash is reported on the test that
  caused it. Detection compares worker PIDs, so it costs nothing when no
  worker died.
- `nginx.check_config()` runs `nginx -t`. A negative return code means it was
  killed by a signal.
- To add directory data, edit `ldap/seed.ldif` and `suite/ldapdata.py`
  together, then run `make test-down` so the LDAP image is reseeded.

## Known bugs

A test for a confirmed bug that is not fixed yet is marked
`@pytest.mark.xfail(reason="... (#<github issue>)")`. `xfail_strict` is on,
so when a fix makes the test pass the run fails until the marker is removed.
`make test PYTEST_ARGS="--runxfail"` shows the current failures.
