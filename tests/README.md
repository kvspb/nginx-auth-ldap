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
make coverage                               # coverage report in tests/reports/coverage/
make mutate BASE=dev                        # mutation testing of the diff against a git ref
make test-down                              # stop LDAP, drop the build cache
```

Build options, passed as environment variables (each combination gets its own
cached build directory):

| Variable        | Effect                                                  |
| --------------- | ------------------------------------------------------- |
| `NGINX_VERSION` | nginx release to build against                          |
| `NGINX_DEBUG=1` | `--with-debug`; error logs are written at `debug` level |
| `SANITIZE=1`    | AddressSanitizer; any report fails the test             |
| `COVERAGE=1`    | gcov build; writes a report (same as `make coverage`)   |

`NGINX_DEBUG=1` changes behaviour: in debug builds `ngx_queue_remove()`
clears the removed node, which hides double-removal bugs. Run the suite
without it as well.

## Coverage

`make coverage` builds an instrumented nginx (`-O0 --coverage`), runs the
suite and writes `tests/reports/coverage/`:

- `index.html`: annotated source, line and branch counts
- `functions.txt`: per-function line coverage, least covered first
- `summary.txt`, `coverage.json`: totals and raw data

Counters are reset before each run. A worker that crashes loses the counts of
its last requests, so xfail crash tests are slightly undercounted.

## Mutation testing

`make mutate BASE=<git ref>` checks that the tests notice changes to the
code you changed. It builds nginx with clang and the
[Mull](https://mull-project.com) plugin, which compiles every mutant of the
lines that differ from `<ref>` (working tree included) into one binary, and
then runs the suite once per mutant through `mull-runner`. A mutant that
makes any test fail, crash nginx or trip AddressSanitizer is killed; one that
passes the whole suite survives. Results go to `tests/reports/mutation/`
(`mutation.txt` lists survivors with file:line, `mutation.json` is the
Mutation Testing Elements report).

| Variable / argument | Effect |
| --- | --- |
| `BASE` | git ref to diff against; only lines changed since it are mutated |
| `PYTEST_ARGS` | pytest arguments per mutant, e.g. a test file to go faster |
| `MUTATE_TIMEOUT` | minimum timeout per mutant run in ms (default 60000) |
| `MUTATE_ASAN=0` | build without AddressSanitizer and `NGX_DEBUG_PALLOC` |
| `MODULE_SRC` | another checkout to mutate (must contain `.git`) |

Each mutant runs the suite (`pytest -x`), about 8 s, so a diff with 60
mutants takes about 8 minutes. AddressSanitizer with `NGX_DEBUG_PALLOC` is
on by default: without it a mutant that shrinks a buffer by one byte writes
into pool slack and survives.

nginx clears the environment of its workers, so the harness forwards Mull's
mutant switches (variables named `cxx_<operator>:<file>:...`) with `env`
directives; mutants in worker code are therefore active.

A surviving mutant needs either a new test or a reason why no test can kill
it (equivalent mutant, or a branch that only runs on allocation failure).

## Layout

```text
tests/
  docker-compose.yml   ldap + tests services
  ldap/                OpenLDAP image; seed.ldif holds the directory fixtures
    tls/               test CA and certificates (generate.sh), test-only keys
  runner/              toolchain image; run-tests.sh builds nginx and runs pytest
  mutation/            clang + Mull image; run-mutation.sh for make mutate
  suite/
    harness.py         Nginx: per-test prefix, config, start/stop, crash detection
    conftest.py        `nginx` fixture, ldap_server() / protected_location() helpers
    ldapdata.py        DNs and credentials matching seed.ldif
    test_*.py          tests, grouped by behaviour
```

The module source is mounted read-only at `/src`; nginx objects live in the
`build-cache` volume, so editing the module only recompiles one file.

The `ldap` service has fixed addresses (10.213.57.10, fd5b:a1d4:0:1::10) so
that its certificates can carry them as IP SANs. It listens on 389 (ldap),
636 (ldaps with a valid certificate) and on TLS proxies to 389 that present
broken certificates: 6361 subject CN only, 6362 another host name, 6363 an
untrusted CA, 6364 TLS 1.3 only. The ports are named in `suite/ldapdata.py`.
To change a certificate, edit and run `ldap/tls/generate.sh` (the command is
in the script), then `make test-down`.

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
