#!/bin/sh
# Regenerate the test PKI used by the ldaps tests. The output is committed;
# run this only to change it:
#
#   docker run --rm -v "$PWD/tests/ldap/tls:/tls" -w /tls alpine:3.22 \
#       sh -c 'apk add --no-cache openssl >/dev/null && sh generate.sh'
#
# Test-only keys for a disposable container. Never use them anywhere else.
# The IP addresses are fixed in tests/docker-compose.yml (ldap service).
set -eu

days=36500
ldap_ipv4=10.213.57.10
ldap_ipv6=fd5b:a1d4:0:1::10

ca() {
    openssl req -x509 -newkey rsa:2048 -nodes -days "$days" \
        -keyout "$1.key" -out "$1.crt" -subj "/CN=$2" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}

# leaf <name> <ca> <subject> [subjectAltName]
leaf() {
    ext="basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth"
    if [ -n "${4:-}" ]; then
        ext="$ext
subjectAltName=$4"
    fi
    openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "$3" 2>/dev/null
    printf '%s\n' "$ext" >"$1.ext"
    openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial \
        -days "$days" -extfile "$1.ext" -out "$1.crt" 2>/dev/null
    rm -f "$1.csr" "$1.ext"
}

rm -f ./*.crt ./*.key ./*.srl

ca ca "nginx-auth-ldap test CA"
ca other-ca "nginx-auth-ldap other test CA"

# What a correctly configured server presents.
leaf server ca "/CN=ldap" "DNS:ldap,IP:$ldap_ipv4,IP:$ldap_ipv6"
# Host name only in the subject CN, no subjectAltName (RFC 9525: not valid).
leaf cn-only ca "/CN=ldap"
# Valid chain, but issued for another host.
leaf wrong-host ca "/CN=other.example" "DNS:other.example"
# Right host, but issued by a CA the client does not trust.
leaf untrusted other-ca "/CN=ldap" "DNS:ldap,IP:$ldap_ipv4,IP:$ldap_ipv6"

# The CA keys are not needed once the certificates exist.
rm -f ca.key other-ca.key ./*.srl
chmod 644 ./*.crt ./*.key
