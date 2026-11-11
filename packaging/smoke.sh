#!/bin/sh
# Installs a built package into a clean container of its distribution,
# with the nginx of that distribution, and checks that the module loads
# and authenticates against the LDAP server of the test environment over
# ldap:// and ldaps:// (see "make package-smoke"). Without packages in
# /dist it checks the nginx of the container as it is, such as the Docker
# image of packaging/docker ("make image-smoke").
#
#   /dist      the package files for this distribution (.deb or .rpm)
#   /src       the source tree, read-only, for the test CA
#   LDAP_HOST  the LDAP server (default: ldap)
set -eu

: "${LDAP_HOST:=ldap}"

fail() { echo "smoke: FAIL: $*" >&2; exit 1; }

if ls /dist/*.deb >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # The package pulls nginx in through its nginx-abi dependency.
    apt-get install -y -qq --no-install-recommends curl /dist/*.deb >/dev/null
    test -e /etc/nginx/modules-enabled/50-mod-http-auth-ldap.conf \
        || fail "the module is not enabled in /etc/nginx/modules-enabled"
    rm -f /etc/nginx/sites-enabled/default
elif ls /dist/*.rpm >/dev/null 2>&1; then
    dnf -q -y install curl /dist/*.rpm
else
    echo "smoke: no package in /dist, checking the installed nginx"
fi

base="ou=people,dc=example,dc=org?uid?sub?(objectClass=inetOrgPerson)"
cat >/etc/nginx/conf.d/smoke.conf <<EOF
ldap_server plain {
    url "ldap://${LDAP_HOST}/${base}";
    binddn "cn=nginx,ou=services,dc=example,dc=org";
    binddn_passwd "nginx-secret";
    require valid_user;
}
ldap_server tls {
    url "ldaps://${LDAP_HOST}/${base}";
    binddn "cn=nginx,ou=services,dc=example,dc=org";
    binddn_passwd "nginx-secret";
    ssl_check_cert on;
    ssl_ca_file /src/tests/ldap/tls/ca.crt;
    require valid_user;
}
server {
    listen 127.0.0.1:8080;
    root /tmp/smoke;
    location /plain/ { auth_ldap "smoke"; auth_ldap_servers plain; }
    location /tls/ { auth_ldap "smoke"; auth_ldap_servers tls; }
}
EOF
mkdir -p /tmp/smoke/plain /tmp/smoke/tls
echo ok >/tmp/smoke/plain/ok
echo ok >/tmp/smoke/tls/ok

nginx -t
nginx

status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
for location in plain tls; do
    url="http://127.0.0.1:8080/${location}/ok"
    for check in "200 alice:alice-secret" "401 alice:wrong" "401 nobody:alice-secret"; do
        want=${check%% *}
        got=$(status -u "${check#* }" "${url}")
        [ "${got}" = "${want}" ] \
            || fail "${location} as ${check#* }: ${got}, expected ${want}"
    done
    got=$(status "${url}")
    [ "${got}" = 401 ] || fail "${location} without credentials: ${got}"
done

nginx -s quit
# shellcheck source=/dev/null
. /etc/os-release
echo "smoke: ${PRETTY_NAME}, $(nginx -v 2>&1): ok"
