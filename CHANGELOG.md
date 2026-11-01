# Changelog

All notable changes to this module are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Entries refer to issues of the original repository as kvspb#N
(<https://github.com/kvspb/nginx-auth-ldap/issues/N>).

## [Unreleased]

### Added

- `auth_ldap` takes variables, and a value of `off` turns the check off for
  the request, as `auth_basic` does: a `geo` or `map` variable can exempt
  clients or requests without `if` (kvspb#77, kvspb#238, PR #257). Quotes
  and backslashes in the realm are escaped.

## [1.0.1] - 2026-11-01

### Fixed

- The cache was never used while the host had been up for less than
  `auth_ldap_cache_expiration_time`, for example during the first hour
  after a reboot with an expiration of `1h`: the age limit of an entry
  was computed on a clock that starts at boot and wrapped below zero.

## [1.0.0] - 2026-11-01

The first release since 0.1 (2011) and after a long pause of upstream
development (last upstream change: 2024-04, pull request #255). It fixes the
known crashes and security defects, those found by a security audit of the
whole module, makes configuration errors visible and adds an integration
test suite with continuous integration.

### Upgrading from 0.x

Run `nginx -t` with the new module before you reload: configurations that
were silently accepted before may now be rejected (see "Changed"). Then
check these changes in behaviour:

- `referral on` (the old default) no longer follows referrals; the directive
  is accepted and ignored. A search that the server answers with a referral
  is answered with `503` and the referral is logged. Point `url` at a server
  that holds the entries (for Active Directory, usually the Global Catalog
  on port 3268).
- With `ssl_ca_file` or `ssl_ca_dir`, only those CAs are trusted; the system
  store is used only when neither is set. With `ssl_check_cert on`, the
  certificate must name the host in its subjectAltName; the subject CN is
  not used. A url with a host name needs that name as a DNS subjectAltName:
  an IP subjectAltName of the address it resolves to no longer matches.
- TLS 1.0 and 1.1 are no longer offered: an LDAP server that speaks
  nothing newer cannot be reached over `ldaps://` or StartTLS.
- A login whose user search finds more than one entry is denied. Make the
  base DN and filter of the `url` select one entry per login.
- When the LDAP servers cannot decide (they do not answer in time, the
  connection breaks, or they answer busy, unavailable, over a limit, other
  or with a referral), the client gets `503 Service Unavailable` instead of
  `401` or a closed connection, and nothing is cached.
- The module runs after the other access modules (`allow`/`deny`,
  `auth_basic`, `auth_request`). With nginx `satisfy all`, a request they
  deny is no longer sent to LDAP; with `satisfy any`, one they admit is not
  either.
- `require group` searches the group entry itself (scope base) instead of
  one level below its parent, so the group DN in the configuration must be
  the exact DN of the group entry.
- `request_timeout` applies to each server in turn: when it expires the
  request goes on to the next server, so the longest wait is the sum of the
  timeouts of all servers in `auth_ldap_servers`.
- `max_down_retries` now limits immediate reconnects of a connection that
  broke under a request; after that it waits for `reconnect_timeout`. An
  idle connection closed by the server is always reconnected at once.

### Security

Found by the security audit and code review of this release:

- A request that timed out returned its connection to the pool with an
  operation in flight: a pending user bind could bind the connection as that
  user, and the next request ran with the user's rights.
- A run of the phase engine while a bind was in flight took the answer of
  the earlier search for the bind result: a wrong password was allowed and
  could be cached.
- `require valid_user "<dn template>"` put the raw login into the DN: a NUL
  or DN metacharacters in the login bound another entry. The login is
  escaped as an RFC 4514 value; a login with a NUL is denied.
- A login whose search matched several entries was bound against the first
  one, and its DN could leak into the search of the next server.
- A variable copied from the login by `set` or `map` and used in a
  `require valid_user` template was not escaped: a login with a comma bound
  another entry. The built DN must now have the RDNs of the template.
- `require group` put part of the group DN into the filter unescaped; with a
  request variable in the group DN a member of any group could pass.
- The cache key ignored what the `require` templates expand to and hashed
  raw server memory, so an ALLOW could be reused for another expansion.
- Referrals were followed with blocking connects to any host the answer
  named, stalling the worker.
- `ssl_ca_file` and `ssl_ca_dir` added to the system trust store instead of
  replacing it.

Known before this release:

- Escape the login name and the user DN in every LDAP search filter
  (RFC 4515). A client could inject filter syntax through the login, and
  legitimate names with `*`, `(`, `)` or `\` failed (CVE-2020-14013,
  kvspb#618, kvspb#180, kvspb#224).
- With `satisfy all`, the DN found for one required group no longer counts
  as a match for the following groups: a member of the first group passed
  all of them (kvspb#194, kvspb#225, kvspb#240).
- With several servers in `auth_ldap_servers`, cached outcomes are looked up
  and stored per server. A cached DENY no longer leaks to the next server,
  and outcomes are no longer stored under the wrong server (kvspb#245,
  kvspb#228, kvspb#201).
- ldaps certificate verification (`ssl_check_cert on`):
  - a host name mismatch no longer crashes the worker (kvspb#236); a host
    name is matched against DNS subjectAltNames only and an address against
    IP subjectAltNames only;
  - the subject CN is no longer used as a host name (RFC 9525, kvspb#254);
  - every `ldap_server` has its own SSL context, so the `ssl_ca_file` or
    `ssl_ca_dir` of one server is not trusted by the others (kvspb#258);
  - only a result of 1 from `X509_check_host()` and `X509_check_ip()` is a
    match; a missing peer certificate is rejected.
- When the rebind as `binddn` after a user bind fails, the LDAP connection
  is closed instead of serving the next requests with that user's rights.

### Fixed

- nginx >= 1.23: terminate the `WWW-Authenticate` header list; the worker
  crashed when sending 401 (kvspb#249).
- `require valid_user "<dn template>"`: the built DN is NUL-terminated; the
  bind used whatever followed in memory.
- Worker crashes in the connection pool (kvspb#62, kvspb#99, kvspb#104,
  kvspb#118, kvspb#132):
  - a request whose LDAP connection is closed under it is released at once
    and fails over or answers 503, instead of returning the connection to
    the pool a second time after `request_timeout`;
  - a waiting request is never removed from the queue twice.
- A worker hung for good when an LDAP connection reset by the server was
  used before its reset was read: the sockbuf close callback unbound the
  same LDAP handle again from inside OpenLDAP. Such a request now gets 503
  instead of 401, and the dead connection is closed instead of being
  handed to the next request.
- Memory: the parsed `url` of every `ldap_server` leaked on each reload,
  and every ldaps or StartTLS reconnect kept a little memory until the
  worker exited.
- The cache used only seven of the eight entries of a bucket: the eighth
  was never chosen for a new outcome.
- An idle LDAP connection closed by the server or a firewall (Active
  Directory does after 15 minutes) is opened again at once and logged at
  the `info` level. Requests no longer get 503 until `reconnect_timeout`
  has passed, and the error log is no longer filled with
  `ldap_result() failed` (kvspb#136, kvspb#222, kvspb#51).
- A worker shutting down gracefully (`nginx -s quit`, the old worker of
  a reload) kept reconnecting to an LDAP server that was down and never
  exited, and one that exited reported its LDAP sockets as left open.
- SSI includes and other subrequests of a request that was checked over
  LDAP were not run until the client sent something more: the response
  stalled.
- When connect() completed at once (a loopback connect on Solaris or the
  BSDs) with the select or poll event method, the LDAP connection was never
  set up and the server never became usable (PR #617).
- A connection closed because its request timed out (or its rebind
  failed) is connected again at once instead of after
  `reconnect_timeout`; the next requests no longer wait for it and time
  out as well.
- With `max_down_retries`, a dropped LDAP connection is reconnected once,
  through the reconnect timer; the old code used a freed event.
- A request freed while it waited for LDAP (worker_shutdown_timeout,
  HTTP/2 stream teardown, another module) left dangling pointers in the
  queue and on its connection.
- An `ldap_server` block without `url` passed `nginx -t`, then every worker
  died with SIGFPE.
- `auth_ldap_servers` kept pointers into the array of servers, which moved
  when more `ldap_server` blocks followed: crash on the first request.
- `max_down_retries` never limited anything: a server that closed new
  connections at once caused a busy reconnect loop.
- Failover between servers (kvspb#115, kvspb#198, kvspb#33, kvspb#34): a
  request goes on to the next server in `auth_ldap_servers` when its
  `request_timeout` expires, and skips at once a server that has no
  connection bound as `binddn` (unreachable, or rejecting `binddn`), unless
  it is the last one. Before, an unreachable first server made every request
  wait for its `request_timeout` and fail, and the other servers were never
  tried.
- An LDAP error that says nothing about the credentials no longer denies
  the user. A connection that broke during the user bind or a search, or a
  server that answered busy, unavailable, time or admin limit exceeded, or
  other, gave `401` and, with the cache on, cached that DENY: a user with the
  right password was locked out for `auth_ldap_cache_expiration_time`. Such
  a result is not cached, the next server is tried, and when no server
  allows, the answer is `503 Service Unavailable`.
- A timed-out authentication is answered with `503 Service Unavailable`
  instead of closing the client connection without a response; keep-alive
  connections stay usable (kvspb#115).
- `require user` compares DNs as DNs: case and spacing after commas no
  longer matter (kvspb#3).
- `ldap_server` urls with an IPv6 address (`ldap://[fd00::1]:389/...`) work.
- `ldaps://` and StartTLS offer TLS 1.2 and 1.3 only: no longer SSL 2.0,
  SSL 3.0, TLS 1.0 or TLS 1.1 (RFC 8996).

### Changed

- `./configure` checks for the OpenLDAP library, also under `/usr/local`,
  `/usr/pkg`, `/opt/local` and Homebrew, and stops with a clear error when
  it is missing, instead of failing the compile; `-llber` is linked on
  every platform.
- A user search answered with a referral gets `503` instead of `401`, and
  the log names the referral and suggests the Global Catalog of Active
  Directory; so does the log of a user not found next to search
  references (kvspb#82, kvspb#111, kvspb#113, kvspb#204).
- The module runs after the other access modules (`allow`/`deny`,
  `auth_basic`, `auth_request`) instead of before them. Under `satisfy any`
  a client they admit costs no LDAP request, and `auth_basic` with a local
  password file admits its users while the directory is down, where the
  module answered 503 first (kvspb#108, kvspb#256, kvspb#7).
- `nginx -t` no longer prints notices for `require` and `satisfy` lines,
  and its messages about the `url` name the `ldap_server` instead of an
  `auth_ldap_url` directive that does not exist (kvspb#215, kvspb#32).
- These fail the configuration check: two `ldap_server` blocks with the
  same name (the first one was used), a second `url` in a block (it
  replaced the first), and `auth_ldap_servers` without a name.
- `auth_ldap_cache_size` is honoured above 8872 entries; larger values were
  cut to that without a word.
- Configuration errors are reported by `nginx -t` instead of being ignored
  or crashing it (kvspb#69, kvspb#87, kvspb#187):
  - an unknown directive inside `ldap_server`;
  - a value other than `on` or `off` for `group_attribute_is_dn` and
    `ssl_check_cert`;
  - a `max_down_retries` value that is not a number;
  - `require` with an unknown kind or a wrong number of arguments;
  - a missing or extra value of any single-value directive;
  - an url without host, with a port outside 1-65535, or with a filter that
    is not one parenthesized filter;
  - an `ssl_ca_file` or `ssl_ca_dir` that cannot be loaded (checked at
    startup instead of at the first handshake).
- The source is split into files by subsystem under `src/`, and refactored
  for less code and fewer special cases; OpenSSL before 1.1 is no longer
  supported.
- `referral on|off` is accepted and ignored (see "Upgrading from 0.x").
- `auth_ldap_servers_size` only sets the initial capacity of the list of
  servers; any number of `ldap_server` blocks works.
- The README is rewritten from the code; every nginx example in it and
  `example.conf` is checked with `nginx -t` by the test suite.

### Added

- The Basic challenge carries `charset="UTF-8"` (RFC 7617), so that
  browsers send a login or password that is not ASCII in UTF-8, as the
  directory stores it (kvspb#145).
- SNI: the host name of an `ldaps://` url, or one with `starttls on`, is
  sent in the TLS handshake, so that a server or proxy with several
  certificates on one address can present the right one.
- `so_keepalive` in `ldap_server`: TCP keepalive timings for the LDAP
  connections, by default a first probe after 60 seconds idle, so that a
  connection a firewall or NAT forgot is found and opened again before a
  request waits on it (kvspb#51).
- StartTLS on `ldap://` urls with `starttls on` (kvspb#44, kvspb#175).
  Nothing is sent in clear before the TLS handshake, and a server that
  refuses StartTLS is never sent a bind: there is no fallback to plain LDAP.
  `ssl_check_cert`, `ssl_ca_file` and `ssl_ca_dir` apply as for `ldaps://`.
- Integration test suite (Docker Compose, OpenLDAP, pytest) with ldaps,
  AddressSanitizer and debug builds, a dynamic module, Alpine Linux (musl)
  and OpenSSL 1.1.1 builds, coverage report and diff-based mutation
  testing: `make test`, `make test-matrix`, `make test-builds`,
  `make coverage`, `make mutate`. See `tests/README.md`.
- GitHub Actions for pull requests and the main branches: lint, the suite on
  nginx 1.22.1, 1.30.6 and 1.31.8, AddressSanitizer, debug, dynamic, Alpine
  and OpenSSL 1.1.1 builds, and mutation testing of the changed lines.

## [0.1] - 2011-11-16

First tagged version by Valery Komarov. Later upstream changes until 2024
were not released under a version number.

[Unreleased]: https://github.com/kvspb/nginx-auth-ldap/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/kvspb/nginx-auth-ldap/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/kvspb/nginx-auth-ldap/compare/v0.1...v1.0.0
[0.1]: https://github.com/kvspb/nginx-auth-ldap/releases/tag/v0.1
