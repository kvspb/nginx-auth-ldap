# LDAP authentication module for nginx

`ngx_http_auth_ldap_module` protects nginx locations with HTTP Basic
authentication and checks the credentials against one or more LDAP servers.
It finds the user's entry with a search (or builds its DN from a template),
checks optional user and group rules, and verifies the password by binding
as that entry. All LDAP traffic is asynchronous, runs over a pool of
persistent connections per worker, and never blocks the nginx event loop.

- [How a request is checked](#how-a-request-is-checked)
- [Build and install](#build-and-install)
- [Quick start](#quick-start)
- [Directive reference](#directive-reference)
- [Examples](#examples)
- [Behaviour notes](#behaviour-notes)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes)
- [Testing](#testing)
- [Changes](#changes)
- [Credits and license](#credits-and-license)

## How a request is checked

A location is protected when it has [`auth_ldap`](#auth_ldap) with a realm
and [`auth_ldap_servers`](#auth_ldap_servers) with the names of one or more
[`ldap_server`](#ldap_server) blocks. For each request the module:

1. Reads the `Authorization: Basic` header. Without one, or with an empty
   password, it answers `401 Unauthorized` with
   `WWW-Authenticate: Basic realm="...", charset="UTF-8"` and does not
   contact LDAP.
2. Tries the servers of the location in the order they are listed. For each
   server:
   1. **Cache.** With [`auth_ldap_cache_enabled on`](#auth_ldap_cache_enabled),
      an allow cached by any server of the location admits the user at once.
      A cached deny for this server skips to the next server.
   2. **Search.** On a pooled connection, which is bound as
      [`binddn`](#binddn) (or anonymously), the module searches below the
      base DN of the [`url`](#url) for
      `(&<url filter>(<login attribute>=<login>))`, with the login escaped.
      The search must find exactly one entry; its DN is the user DN. With
      [`require valid_user <template>`](#require) there is no search: the
      template gives the user DN.
   3. **`require user`.** Each [`require user`](#require) DN is compared with
      the user DN as a DN.
   4. **`require group`.** For each [`require group`](#require) DN the module
      reads the group entry with the filter `(<group_attribute>=<value>)`,
      where the value is the user DN with
      [`group_attribute_is_dn on`](#group_attribute_is_dn) or the login
      otherwise. The group matches when its entry is returned.
   5. **Decision.** With [`satisfy any`](#satisfy) (the default) one matching
      `require user` or `require group` rule is enough; with `satisfy all`
      every rule must match. A server without such rules accepts every user
      it finds.
   6. **Bind.** The module binds as the user DN with the password. Even when
      the rules matched, a wrong password denies the user.
   7. **Rebind.** The connection binds as `binddn` again before it serves the
      next request.
3. Allows the request as soon as one server allows it. A server that cannot
   decide is left for the next one: it has no connection bound as `binddn`
   (unless it is the last server), it does not finish within its
   [`request_timeout`](#request_timeout), the connection broke, or it
   answered busy, unavailable or over a limit. When every server denies the
   user, the answer is `401`; when a server could not decide and no later
   server allows, it is `503 Service Unavailable`, as the credentials may be
   right.

Each nginx worker opens [`connections`](#connections) connections to every
`ldap_server` when it starts, keeps them open, and reconnects them after
[`reconnect_timeout`](#reconnect_timeout) when they fail. A request that
finds every connection of a server busy waits for one.

## Build and install

Requirements:

- nginx 1.22 or newer, built from source.
- The OpenLDAP client library and its headers (`libldap`, `liblber`): the
  module uses OpenLDAP-specific calls, so other LDAP SDKs do not work.
  Debian and Ubuntu: `libldap-dev` (`libldap2-dev` on older releases);
  Fedora, RHEL: `openldap-devel`; Alpine: `openldap-dev`; FreeBSD:
  `net/openldap26-client`.
- OpenSSL 1.1 or 3 and its headers, for `ldaps://` and certificate checks.
  nginx must be built with OpenSSL (for example with
  `--with-http_ssl_module`); otherwise `ldaps://` URLs are rejected.

Get the source:

```sh
git clone https://github.com/kvspb/nginx-auth-ldap.git
```

### Static module

Build it into the nginx binary from the nginx source directory:

```sh
./configure --with-http_ssl_module --add-module=/path/to/nginx-auth-ldap
make
make install
```

### Dynamic module

Build it as a loadable module. It must be built against the same nginx
version as the binary that loads it, with compatible configure arguments
(`--with-compat`, or the arguments of that binary shown by `nginx -V`):

```sh
./configure --with-compat --with-http_ssl_module \
    --add-dynamic-module=/path/to/nginx-auth-ldap
make modules
cp objs/ngx_http_auth_ldap_module.so /usr/lib/nginx/modules/
```

Load it at the top of `nginx.conf`, in the main context:

```nginx
load_module modules/ngx_http_auth_ldap_module.so;

events {
}

http {
    ldap_server directory {
        url "ldap://ldap.example.com/ou=people,dc=example,dc=com?uid?sub?(objectClass=inetOrgPerson)";
    }
}
```

The path is relative to the nginx prefix; use the directory where your
distribution keeps modules.

## Quick start

A complete `nginx.conf` that admits every user of `ou=people` who gives the
right password:

```nginx
events {
}

http {
    ldap_server directory {
        url "ldap://ldap.example.com/ou=people,dc=example,dc=com?uid?sub?(objectClass=inetOrgPerson)";
        binddn "cn=nginx,ou=services,dc=example,dc=com";
        binddn_passwd "service-account-password";
        require valid_user;
    }

    server {
        listen 80;

        location / {
            auth_ldap "Restricted";
            auth_ldap_servers directory;
            root /var/www/html;
        }
    }
}
```

Check it with `nginx -t`, reload, and try it:

```sh
curl -i -u alice http://localhost/
```

## Directive reference

Time values use the nginx units (`ms`, `s`, `m`, `h`, ...); a number
without a unit is seconds.

### http level

#### ldap_server

```text
Syntax:  ldap_server name { ... }
Default: -
Context: http
```

Defines an LDAP server under a name that [`auth_ldap_servers`](#auth_ldap_servers)
refers to. The block takes the directives listed under
[ldap_server block](#ldap_server-block); [`url`](#url) is required. A block
must appear before every `auth_ldap_servers` that names it.

#### auth_ldap_cache_enabled

```text
Syntax:  auth_ldap_cache_enabled on | off;
Default: auth_ldap_cache_enabled off;
Context: http
```

Caches the outcome of each check in the memory of each worker. A cache entry
is keyed on the login, the password, the server and every `require` value as
the request expands it. Allows and denies are cached; errors and timeouts are
not. See [the cache notes](#cache).

#### auth_ldap_cache_expiration_time

```text
Syntax:  auth_ldap_cache_expiration_time time;
Default: auth_ldap_cache_expiration_time 10s;
Context: http
```

How long a cached outcome is used. At least `1s`; a smaller value fails the
configuration check. Checked only when the cache is enabled.

#### auth_ldap_cache_size

```text
Syntax:  auth_ldap_cache_size number;
Default: auth_ldap_cache_size 100;
Context: http
```

Number of cache entries per worker, at least 100. Entries are kept in
buckets of 8, so the number is rounded up to a multiple of 8; each takes
32 bytes. When a bucket is full the oldest entry is replaced.

#### auth_ldap_servers_size

```text
Syntax:  auth_ldap_servers_size number;
Default: auth_ldap_servers_size 7;
Context: http
```

Number of `ldap_server` blocks to allocate room for at first, at least 1.
It is not a limit: more blocks can be defined. It only has an effect before the first
`ldap_server` block. There is rarely a reason to set it.

### location level

#### auth_ldap

```text
Syntax:  auth_ldap realm | off;
Default: auth_ldap off;
Context: http, server, location, limit_except
```

Turns LDAP authentication on with the given realm, which is sent in
`WWW-Authenticate: Basic realm="realm", charset="UTF-8"`, or off. The
realm is inserted as it is: do not put a double quote in it. The charset
asks the browser to send the login and password in UTF-8 (RFC 7617), as the
directory stores them; a client that sends ISO-8859-1 anyway cannot log in
with a password that is not ASCII. Levels without `auth_ldap` inherit it.
`auth_ldap` without servers rejects every request with `401` and logs
`"auth_ldap" requires one or more "auth_ldap_servers" in the same location`.

#### auth_ldap_servers

```text
Syntax:  auth_ldap_servers name ...;
Default: -
Context: http, server, location, limit_except
```

The `ldap_server` blocks to check, in order. The directive may be repeated;
the names add up in order. A level with its own `auth_ldap_servers` replaces
the list it would inherit. Every name must be defined by an earlier
`ldap_server` block. Without `auth_ldap` the list has no effect.

### ldap_server block

Every directive in the block except `require` takes exactly one value. An
unknown directive or a value of the wrong form fails the configuration check,
and so does a second `url`, a second `require valid_user` template, or a
second `ldap_server` block with the same name.

#### url

```text
Syntax:  url ldap[s]://host[:port]/base_dn?attribute[,...]?scope?filter;
Default: -
```

Where and how to search for users (an RFC 4516 LDAP URL). Required.

- `ldap://` or `ldaps://` (LDAP over TLS). For StartTLS on `ldap://`, see
  `starttls`.
- `host`: a host name, an IPv4 address, or an IPv6 address in brackets, for
  example `ldaps://[2001:db8::10]/...`. A host name is resolved once, when
  nginx reads the configuration; with several addresses each connection
  picks one at random. A name that does not resolve fails the check.
- `port`: defaults to 389 for `ldap://` and 636 for `ldaps://`.
- `base_dn`: the search base.
- `attribute`: the attribute that holds the login, for example `uid` or
  `sAMAccountName`. Required; only the first attribute of a list is used.
- `scope`: `base`, `one` or `sub` (also `onelevel`, `subtree`, `children`).
  The default is `base`, which only finds an entry that is the base DN
  itself: set `sub` or `one`.
- `filter`: an extra filter that every user entry must match, in
  parentheses, for example `(objectClass=inetOrgPerson)` or
  `(&(objectClass=person)(!(loginDisabled=TRUE)))`. It must be one balanced,
  parenthesized filter. Default `(objectClass=*)`.

Quote the value, and percent-encode characters that are special in a URL,
for example a space as `%20` and `?` as `%3F`.

#### binddn

```text
Syntax:  binddn dn;
Default: - (anonymous bind)
```

The DN of the account that the module binds as to search for users and
groups. Use an account that can only read. Without `binddn` the connections
bind anonymously.

#### binddn_passwd

```text
Syntax:  binddn_passwd password;
Default: -
```

The password of `binddn`. It is never logged. Keep it in a file that only
root can read, see [`include`](#include).

#### require

```text
Syntax:  require valid_user;
         require valid_user dn_template;
         require user dn;
         require group dn;
```

- `require valid_user` adds no rule: every user who is found and binds is
  accepted unless other `require` rules say otherwise. It may be left out.
- `require valid_user dn_template` builds the user DN from the template
  instead of searching, for example
  `require valid_user "uid=$remote_user,ou=people,dc=example,dc=com";`.
  `$remote_user` expands to the login escaped as an RDN value (RFC 4514), so
  a login cannot add RDNs or leave the template. A variable copied from the
  login by `set` or `map` is not escaped; the DN built from the template must
  still have the RDNs of the template, or the user is denied. Allowed once
  per block. The
  `url` is still required, with a login attribute, but no search is made
  with it.
- `require user dn` admits the user whose DN equals `dn`. May be repeated.
- `require group dn` admits members of the group `dn`, see
  [`group_attribute`](#group_attribute). May be repeated.

The values may contain nginx variables. They are expanded for each request;
a variable taken from the request lets the client choose the DN that is
required.

#### satisfy

```text
Syntax:  satisfy all | any;
Default: satisfy any;
```

With `any` one `require user` or `require group` rule must match; with `all`
every one must. This is not the nginx core
[`satisfy`](https://nginx.org/en/docs/http/ngx_http_core_module.html#satisfy)
directive, which combines access modules (see
[the example](#combining-with-satisfy-any-and-allowdeny)).

#### group_attribute

```text
Syntax:  group_attribute attribute;
Default: -
```

The attribute of a group entry that lists its members, for example `member`,
`uniqueMember` or `memberUid`. Without it every `require group` rule fails.

#### group_attribute_is_dn

```text
Syntax:  group_attribute_is_dn on | off;
Default: group_attribute_is_dn off;
```

`on`: the group attribute holds member DNs (`member`, `uniqueMember`), so the
user DN is looked for. `off`: it holds logins (`memberUid`), so the login
from the request is looked for.

#### connections

```text
Syntax:  connections number;
Default: connections 1;
```

Number of connections each worker keeps open to the server, at least 1. A
request waits while every connection is busy, so raise it for busy sites.
The server sees `worker_processes` times this number of connections, for
each `ldap_server` that names it, and the old workers of a reload keep
theirs until they exit. A connection serves one request at a time, for
its search, bind and rebind (and group searches), so size it to the
number of uncached requests a worker checks at the same time; with the
cache on, most requests need no connection.

#### so_keepalive

```text
Syntax:  so_keepalive on | off | [idle]:[interval]:[count];
Default: so_keepalive 60s:10s:3;
```

TCP keepalive on the connections to the server. A firewall or NAT that
forgets an idle connection drops its packets without a word, and the next
request on it would wait for `request_timeout`. Keepalive probes find such
a connection while it is idle, and it is opened again. By default the first
probe goes out after 60 seconds without traffic, then every 10 seconds; after
3 unanswered probes the connection is given up. `on` keeps the timings of
the system (on Linux the first probe after 2 hours), `off` sends no probes.
As for the `so_keepalive` parameter of `listen`, a part left empty keeps the
system value, for example `so_keepalive 5m::;`. The timings need a system
that can set them per socket (Linux, FreeBSD); elsewhere only `on` and `off`
are accepted.

#### max_down_retries

```text
Syntax:  max_down_retries number;
Default: max_down_retries 0;
```

When a connection breaks while a request is using it (`ldap_result() failed
(-1: Can't contact LDAP server)`), reconnect at once instead of after
`reconnect_timeout`, up to this many times in a row. The count starts again
after a successful bind as `binddn`.

An idle connection that the server or a firewall closes (Active Directory
does after 15 minutes by default) is always opened again at once, at most
once per `reconnect_timeout`, and only logged at the `info` level:
`Server "..." closed the idle connection`.

#### connect_timeout

```text
Syntax:  connect_timeout time;
Default: connect_timeout 10s;
```

Timeout for opening a connection, including the TLS handshake for
`ldaps://`. Must be greater than 0.

#### bind_timeout

```text
Syntax:  bind_timeout time;
Default: bind_timeout 5s;
```

Timeout for the bind as `binddn` on a new connection. Must be greater than 0.

#### reconnect_timeout

```text
Syntax:  reconnect_timeout time;
Default: reconnect_timeout 10s;
```

How long to wait before a failed or closed connection is opened again. Must
be greater than 0. A connection closed while idle, or closed together with
a request that timed out, is opened again at once instead.

#### request_timeout

```text
Syntax:  request_timeout time;
Default: request_timeout 10s;
```

Time a request may spend on this server, including the wait for a free
connection, the searches and the binds. When it expires the request goes on
to the next server in `auth_ldap_servers`, with that server's
`request_timeout`; after the last server it is answered with
`503 Service Unavailable`. Must be greater than 0.

#### starttls

```text
Syntax:  starttls on | off;
Default: starttls off;
```

For `ldap://`: ask for TLS with the StartTLS extended operation (RFC 4511,
section 4.14) right after connecting, and send the bind as `binddn` and
every search and user bind only over TLS. A server that refuses StartTLS or
does not complete the TLS handshake is treated as unreachable: the module
never falls back to plain LDAP. `ssl_check_cert`, `ssl_ca_file` and
`ssl_ca_dir` apply as for `ldaps://`. With an `ldaps://` url, `starttls on`
fails the configuration check.

#### ssl_check_cert

```text
Syntax:  ssl_check_cert on | off;
Default: ssl_check_cert off;
```

For `ldaps://` and `starttls on`: verify the server certificate. The chain
must lead to a trusted CA, and the certificate must name the host of the
`url`: a host name in a DNS subjectAltName, an address in an IP
subjectAltName. An IP subjectAltName does not match a host name, even one
that resolves to that address, and the subject CN is not used. With `off`
any certificate is accepted, which exposes passwords to a man in the
middle.

#### ssl_ca_file

```text
Syntax:  ssl_ca_file file;
Default: -
```

Trust the CA certificates in this PEM file for `ssl_check_cert`. Use an
absolute path. With `ssl_ca_file` or `ssl_ca_dir` set, only these CAs are
trusted; without both, the default CA store of OpenSSL is used. A file that
cannot be loaded fails the configuration check. Only read for `ldaps://` or
`starttls on`, with `ssl_check_cert on`.

#### ssl_ca_dir

```text
Syntax:  ssl_ca_dir directory;
Default: -
```

Trust the CA certificates in this directory, which needs the hash links made
by `openssl rehash` (or `c_rehash`). Otherwise as `ssl_ca_file`; both may be
set.

#### referral

```text
Syntax:  referral on | off;
Default: -
```

Accepted for compatibility and ignored: referrals are never followed.
Following one made the LDAP library connect to any host a server named with
a blocking connect, outside the nginx event loop. A search answered with a
referral (the base DN is on another server) is answered with `503` and logged
as `Server "..." referred the user search to "..."`. Search references next
to the entries are skipped; when the user is not found, the first one is
logged: `User "..." not found on server "...", which referred to "..."`. With
Active Directory both usually mean that the `url` should point at the Global
Catalog (port 3268).

#### include

```text
Syntax:  include file | mask;
Default: -
```

Reads `ldap_server` directives from another file, for example the bind
credentials. A relative path is relative to the directory of `nginx.conf`.

## Examples

Every example below is a complete `http` block body (or a complete
`nginx.conf`), and the test suite checks each one with `nginx -t`. Host
names, DNs and passwords are placeholders.

### Basic OpenLDAP

```nginx
ldap_server openldap {
    url "ldap://ldap.example.com/ou=people,dc=example,dc=com?uid?sub?(objectClass=inetOrgPerson)";
    binddn "cn=nginx,ou=services,dc=example,dc=com";
    binddn_passwd "service-account-password";
}

server {
    listen 80;

    location /private/ {
        auth_ldap "Private area";
        auth_ldap_servers openldap;
        root /var/www;
    }
}
```

### Active Directory

Search the Global Catalog (port 3268) by `sAMAccountName`. The bind account
may be given as a DN or as a user principal name. `\\` inside double quotes
is one backslash, so `"EXAMPLE\\nginx"` would also work.

```nginx
ldap_server ad {
    url "ldap://dc1.example.com:3268/dc=example,dc=com?sAMAccountName?sub?(&(objectCategory=person)(objectClass=user))";
    binddn "nginx@example.com";
    binddn_passwd "service-account-password";
    group_attribute member;
    group_attribute_is_dn on;
    require group "CN=Web Admins,OU=Groups,DC=example,DC=com";
}

server {
    listen 80;

    location / {
        auth_ldap "Example Corp";
        auth_ldap_servers ad;
        root /var/www/html;
    }
}
```

The Global Catalog only has complete `member` values for universal groups;
to check global or domain local groups, use port 389 of a domain controller.
Nested group membership is not resolved.

### Groups

Groups that list member DNs (`groupOfNames` with `member`, `groupOfUniqueNames`
with `uniqueMember`), here with `satisfy all`: the user must be in both
groups.

```nginx
ldap_server staff {
    url "ldap://ldap.example.com/ou=people,dc=example,dc=com?uid?sub?(objectClass=inetOrgPerson)";
    binddn "cn=nginx,ou=services,dc=example,dc=com";
    binddn_passwd "service-account-password";
    group_attribute member;
    group_attribute_is_dn on;
    satisfy all;
    require group "cn=developers,ou=groups,dc=example,dc=com";
    require group "cn=vpn-users,ou=groups,dc=example,dc=com";
}

server {
    listen 80;

    location / {
        auth_ldap "Developers";
        auth_ldap_servers staff;
        root /var/www/html;
    }
}
```

POSIX groups (`posixGroup` with `memberUid`) list logins: one of the groups
is enough with the default `satisfy any`, and `alice` is admitted by name.

```nginx
ldap_server posix {
    url "ldap://ldap.example.com/ou=people,dc=example,dc=com?uid?sub?(objectClass=posixAccount)";
    binddn "cn=nginx,ou=services,dc=example,dc=com";
    binddn_passwd "service-account-password";
    group_attribute memberUid;
    group_attribute_is_dn off;
    require group "cn=admins,ou=groups,dc=example,dc=com";
    require group "cn=operators,ou=groups,dc=example,dc=com";
    require user "uid=alice,ou=people,dc=example,dc=com";
}

server {
    listen 80;

    location /admin/ {
        auth_ldap "Administration";
        auth_ldap_servers posix;
        root /var/www;
    }
}
```

### ldaps with certificate verification

The bind credentials come from a file that only root can read (the nginx
master process reads the configuration as root):

```nginx
# /etc/nginx/ldap/bind.conf
binddn "cn=nginx,ou=services,dc=example,dc=com";
binddn_passwd "service-account-password";
```

```nginx
ldap_server secure {
    url "ldaps://ldap.example.com/ou=people,dc=example,dc=com?uid?sub?(objectClass=inetOrgPerson)";
    include /etc/nginx/ldap/bind.conf;
    ssl_check_cert on;
    ssl_ca_file /etc/nginx/ldap/ca.pem;
}

ldap_server secure_ipv6 {
    url "ldaps://[2001:db8::10]:636/ou=people,dc=example,dc=com?uid?sub?(objectClass=inetOrgPerson)";
    include /etc/nginx/ldap/bind.conf;
    ssl_check_cert on;
    ssl_ca_dir /etc/nginx/ldap/certs;
}

server {
    listen 80;

    location / {
        auth_ldap "Restricted";
        auth_ldap_servers secure;
        root /var/www/html;
    }

    location /v6/ {
        auth_ldap "Restricted";
        auth_ldap_servers secure_ipv6;
        root /var/www;
    }
}
```

For an address in the `url`, the certificate needs that address as an IP
subjectAltName.

### StartTLS

The same verification on port 389, for servers that offer StartTLS instead
of ldaps:

```nginx
ldap_server starttls {
    url "ldap://ldap.example.com/ou=people,dc=example,dc=com?uid?sub?(objectClass=inetOrgPerson)";
    include /etc/nginx/ldap/bind.conf;
    starttls on;
    ssl_check_cert on;
    ssl_ca_file /etc/nginx/ldap/ca.pem;
}

server {
    listen 80;

    location / {
        auth_ldap "Restricted";
        auth_ldap_servers starttls;
        root /var/www/html;
    }
}
```

### Several servers

The servers are tried in order. A user who is not found, does not match the
rules or gives a wrong password on the first server is checked on the
second. This combines directories, and gives failover between replicas of
one directory:

```nginx
ldap_server primary {
    url "ldap://ldap1.example.com/ou=people,dc=example,dc=com?uid?sub?(objectClass=inetOrgPerson)";
    binddn "cn=nginx,ou=services,dc=example,dc=com";
    binddn_passwd "service-account-password";
    connections 4;
    request_timeout 3s;
}

ldap_server replica {
    url "ldap://ldap2.example.com/ou=people,dc=example,dc=com?uid?sub?(objectClass=inetOrgPerson)";
    binddn "cn=nginx,ou=services,dc=example,dc=com";
    binddn_passwd "service-account-password";
    connections 4;
    request_timeout 3s;
}

server {
    listen 80;

    location / {
        auth_ldap "Restricted";
        auth_ldap_servers primary replica;
        root /var/www/html;
    }
}
```

When the first server is unreachable or rejects `binddn`, a worker has no
connection to it and sends requests to the second server at once. When it
accepts connections but does not answer, each request waits for its
`request_timeout` before the second server is tried: keep it short. While a
server cannot decide and no later server allows, the answer is `503`, not
`401`, even when a later server denies the user: the unavailable server may
know them. As an alternative for a
replicated directory, a single `url` whose host name resolves to every
replica may suit better: each connection picks one of the addresses at
random whenever it connects, and a request uses any connection that is up.

### Cache

```nginx
auth_ldap_cache_enabled on;
auth_ldap_cache_expiration_time 5m;
auth_ldap_cache_size 1000;

ldap_server cached {
    url "ldap://ldap.example.com/ou=people,dc=example,dc=com?uid?sub?(objectClass=inetOrgPerson)";
    binddn "cn=nginx,ou=services,dc=example,dc=com";
    binddn_passwd "service-account-password";
}

server {
    listen 80;

    location / {
        auth_ldap "Restricted";
        auth_ldap_servers cached;
        root /var/www/html;
    }
}
```

### require valid_user with a DN template

No search and no service account: the user DN is built from the login.

```nginx
ldap_server template {
    url "ldap://ldap.example.com/ou=people,dc=example,dc=com?uid?sub";
    require valid_user "uid=$remote_user,ou=people,dc=example,dc=com";
}

server {
    listen 80;

    location / {
        auth_ldap "Restricted";
        auth_ldap_servers template;
        root /var/www/html;
    }
}
```

### Combining with satisfy any and allow/deny

Clients from the office network get in without credentials, everyone else
needs an LDAP login. `/public/` needs nothing.

```nginx
ldap_server corp {
    url "ldap://ldap.example.com/ou=people,dc=example,dc=com?uid?sub?(objectClass=inetOrgPerson)";
    binddn "cn=nginx,ou=services,dc=example,dc=com";
    binddn_passwd "service-account-password";
}

server {
    listen 80;
    root /var/www/html;

    auth_ldap "Corp";
    auth_ldap_servers corp;

    location / {
        satisfy any;
        allow 192.0.2.0/24;
        deny all;
    }

    location /public/ {
        auth_ldap off;
    }
}
```

The module runs after the other access modules of nginx (`allow`/`deny`,
`auth_basic`, `auth_request`): a client they admit under `satisfy any` costs
no LDAP request. With `auth_basic` and a password file next to `auth_ldap`,
users from either source get in, and the local users still do while the
directory cannot be reached:

```nginx
ldap_server corp {
    url "ldap://ldap.example.com/ou=people,dc=example,dc=com?uid?sub?(objectClass=inetOrgPerson)";
    include /etc/nginx/ldap/bind.conf;
}

server {
    listen 8080;
    root /var/www/html;

    location /admin/ {
        satisfy any;
        auth_ldap "Corp";
        auth_ldap_servers corp;
        auth_basic "Corp";
        auth_basic_user_file /etc/nginx/ldap/htpasswd;
    }
}
```

## Behaviour notes

### Responses

| Situation | Response |
| --- | --- |
| No `Authorization` header, not Basic, or empty password | `401` with `WWW-Authenticate`, LDAP is not asked |
| User not found, found twice, rules not met, wrong password, on every server | `401` with `WWW-Authenticate` |
| A server could not decide: the connection broke, or the server answered busy (51), unavailable (52), time or admin limit exceeded (3, 11) or other (80); and no other server allowed | `503`, not cached |
| A server did not finish within its `request_timeout` (unreachable, every connection busy, slow) | `503` |
| Internal error, such as a failed memory allocation | `500` |

Empty passwords are rejected before LDAP is asked: many servers treat a
simple bind with an empty password as an anonymous bind that succeeds
(RFC 4513, section 5.1.2).

Do not use `return` in a protected location: it runs in the rewrite phase,
before the access phase, so it answers without authentication. Serve content
or use `proxy_pass`, `try_files` and the like.

### Filter escaping and DN handling

- The login is escaped (RFC 4515) before it is placed into the user search
  filter, and so are the user DN or login placed into a group filter: `*`,
  `(`, `)`, `\` and NUL cannot change a filter.
- In a `require valid_user` template, `$remote_user` is escaped as an RDN
  value (RFC 4514). A login with a NUL byte is rejected. A DN built from the
  template must have as many RDNs, each with as many attribute-value pairs,
  as the template itself, so that no other variable can add one either.
- `require user` DNs are compared with the user DN as DNs: both are
  normalized by OpenLDAP (spacing, escaping) and compared without regard to
  case, so `UID=alice, OU=People,DC=example,DC=com` matches
  `uid=alice,ou=people,dc=example,dc=com`.
- A `require group` value is used as the base DN of the group search. A value
  that is not a valid DN fails that server's check and is logged.
- The `url` filter comes from the configuration and is used as written; it is
  only checked to be one balanced, parenthesized filter.
- A user search that finds more than one entry is an error, not a match.

### Cache

- The cache lives in each worker; workers do not share it, and a reload
  empties it.
- A changed password or a removed account takes effect when the cached allow
  expires. A user who was denied stays denied until the cached deny expires,
  as long as the password is the same.
- The key holds an MD5 hash of the password, never the password.

### What is logged

Passwords and `binddn_passwd` are never logged. At level `error` the module
logs, with the `http_auth_ldap:` prefix:

- failed user binds, for example `User bind failed (49: Invalid credentials)`
  (without the login);
- user searches that find nothing (`Could not find user DN`) or more than one
  entry (`User search for "<login>" returned more than one entry`);
- a group that the user is not a member of
  (`ldap_search_ext() returned NULL result`), which is normal with
  `satisfy any`;
- connection, bind, TLS and certificate failures, and timeouts
  (`Authentication timed out`).

nginx built with `--with-debug` and `error_log ... debug` also logs the
login, the search filters and the DNs.

### Configuration errors

`nginx -t` reports configuration errors with the `http_auth_ldap:` prefix
and refuses the configuration, for example:

- `no "url" in ldap_server "<name>"`;
- `unknown directive "<name>" in ldap_server`;
- `invalid number of arguments in "<directive>"`;
- `No user attribute specified in auth_ldap_url.`,
  `No host specified in auth_ldap_url.`, `Invalid port ...`,
  `Invalid filter "..." in auth_ldap_url.`;
- `host not found in LDAP hostname "<host>"`;
- `invalid value "..." for require, it must be "valid_user", "user" or "group"`;
- `Server "<name>" has not been defined`, and `Using "auth_ldap_servers" when
  no "ldap_server" has been previously defined` when the order is wrong;
- `cannot load CA certificates from "<path>"`;
- `auth_ldap_cache_size cannot be smaller than 100 entries.`,
  `auth_ldap_cache_expiration_time cannot be smaller than 1000 ms.`

`nginx -t` also prints notices such as `http_auth_ldap: parse_require`; they
are harmless.

## Troubleshooting

Reproduce the module's search with `ldapsearch` from the nginx host:

```sh
ldapsearch -H ldap://ldap.example.com -D "cn=nginx,ou=services,dc=example,dc=com" -W \
    -b "ou=people,dc=example,dc=com" -s sub "(&(objectClass=inetOrgPerson)(uid=alice))" dn
```

| Log message | Likely cause |
| --- | --- |
| `Could not find user DN` | Wrong base DN, scope, login attribute or filter. The scope defaults to `base`: add `?sub` to the `url`. |
| `referred the user search to "..."`, `not found on server "...", which referred to "..."` | The entry is on another server, for example in another Active Directory domain: point the `url` at the Global Catalog (port 3268). |
| `User search for "..." returned more than one entry` | The login is not unique below the base DN: narrow the base or the filter. |
| `User bind failed (49: Invalid credentials)` | Wrong password, or a locked or expired account. |
| `Initial bind failed (49: Invalid credentials ...)` | Wrong `binddn` or `binddn_passwd`. The connection never becomes ready, so requests get `503`. |
| `Could not connect`, `Unable to connect to LDAP server` | Host or port unreachable; the connection is retried every `reconnect_timeout`. |
| `Request timed out (state=...)` | The server accepted the connection but did not answer in time. |
| `Authentication timed out on server "..."` | The request hit that server's `request_timeout` and goes on to the next server; see the messages before it. |
| `Server "..." has no connection, trying the next server` | No connection to that server is bound as `binddn`: it is unreachable or rejects `binddn` (look for `Could not connect` or `Initial bind failed`). |
| `ldap_result() failed (-1: Can't contact LDAP server)` | A connection broke while a request was using it; the request is answered with 503. See `max_down_retries`. |
| `SSL handshake failed` | Not a TLS port, no common TLS version or cipher, or TLS on a plain `ldap://` port. |
| `Remote side presented invalid SSL certificate: error ...` | The chain does not lead to a CA in `ssl_ca_file` / `ssl_ca_dir` or the system store. |
| `... does not match address "..." ...` | The certificate does not name the host of the `url` in its subjectAltName: a host name needs a DNS entry, an address an IP entry. |
| `Incorrect group DN` | A `require group` value is not a valid DN. |
| `"auth_ldap" requires one or more "auth_ldap_servers"` | `auth_ldap` without `auth_ldap_servers` at the same or an outer level. |

If every group check fails, check that `group_attribute` is set, that
`group_attribute_is_dn` fits the attribute, and that `binddn` may read the
group entries.

## Security notes

- `ldap://` sends passwords in clear text. Use `ldaps://` with
  `ssl_check_cert on`; `ssl_check_cert` is off by default.
- Basic authentication sends the password with every request: serve
  protected locations over HTTPS.
- Bind as a service account that can only read the entries it needs, and
  keep `binddn_passwd` in an included file readable only by root.
- Logins are escaped in filters and DN templates; the `url` filter and the
  `require` values come from the configuration and are trusted. Do not put
  request variables into `require` values unless the client may choose them.
- Referrals are never followed.
- With the cache, revoking access takes up to
  `auth_ldap_cache_expiration_time`.
- Several servers in one location are alternatives: the user is admitted by
  the first one that allows, so each must be trusted as much as the others.

## Testing

The integration suite builds nginx with this module and sends real requests
against a real OpenLDAP server in Docker Compose; it needs only Docker and
`make`. See [tests/README.md](tests/README.md).

```sh
make test                                 # nginx 1.30.6
make test PYTEST_ARGS="-q -k groups"      # pytest arguments
make test NGINX_VERSION=1.22.1            # another nginx release
make test-matrix                          # 1.22.1, 1.30.6 and 1.31.8
SANITIZE=1 make test                      # AddressSanitizer build
NGINX_DEBUG=1 make test                   # --with-debug build
make coverage                             # report in tests/reports/coverage/
make mutate BASE=<git ref>                # mutation testing of the changed lines
make test-down                            # stop the LDAP server, drop the build cache
```

GitHub Actions runs the same checks on every pull request
(`.github/workflows/tests.yml`).

## Changes

See [CHANGELOG.md](CHANGELOG.md), including the notes on upgrading from
earlier versions.

## Credits and license

Written by Valery Komarov, with contributions by Jiri Hruska, Victor Hahn
Castell and many others, upstream at
[kvspb/nginx-auth-ldap](https://github.com/kvspb/nginx-auth-ldap).

Copyright (C) 2011-2026 Valery Komarov, (C) 2013 Jiri Hruska,
(C) 2015-2016 Victor Hahn Castell. Distributed under the two-clause BSD
license, see [LICENSE](LICENSE).
