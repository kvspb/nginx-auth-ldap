#!/bin/sh
# Seed the directory on first start, then run slapd in the foreground.
set -eu

data_dir=/var/lib/openldap/openldap-data

mkdir -p /run/openldap "$data_dir"

if [ ! -f "$data_dir/data.mdb" ]; then
    slapadd -f /etc/openldap/slapd.conf -l /etc/openldap/seed.ldif
fi

# -d 256 logs every operation (connections, binds, searches) to stderr,
# which is what you want to see in "docker compose logs ldap".
exec slapd -f /etc/openldap/slapd.conf -h "ldap:///" -d "${SLAPD_LOG_LEVEL:-256}"
