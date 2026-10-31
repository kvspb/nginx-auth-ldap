#!/bin/sh
# Seed the directory on first start, start the TLS test proxies, then run
# slapd in the foreground.
set -eu

data_dir=/var/lib/openldap/openldap-data
tls=/etc/openldap/tls

mkdir -p /run/openldap "$data_dir"

if [ ! -f "$data_dir/data.mdb" ]; then
    slapadd -f /etc/openldap/slapd.conf -l /etc/openldap/seed.ldif
fi

# proxy <port> <certificate> [socat ssl options]: TLS on <port>, plain LDAP
# behind it. Each one presents a certificate the client must reject, or
# speaks only a protocol version the client must support.
proxy() {
    port=$1 cert=$2
    shift 2
    socat "OPENSSL-LISTEN:$port,pf=ip6,ipv6only=0,reuseaddr,fork,verify=0,cert=$tls/$cert.crt,key=$tls/$cert.key$*" \
        TCP:127.0.0.1:389 &
}

proxy 6361 cn-only
proxy 6362 wrong-host
proxy 6363 untrusted
proxy 6364 server ",openssl-min-proto-version=TLS1.3"

# -d 256 logs every operation (connections, binds, searches) to stderr,
# which is what you want to see in "docker compose logs ldap".
exec slapd -f /etc/openldap/slapd.conf -h "ldap:/// ldaps:///" -d "${SLAPD_LOG_LEVEL:-256}"
