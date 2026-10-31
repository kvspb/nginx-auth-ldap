# Minimal OpenLDAP server seeded with the fixtures used by the test suite.
FROM alpine:3.22

RUN apk add --no-cache openldap openldap-back-mdb openldap-clients socat

COPY slapd.conf /etc/openldap/slapd.conf
COPY seed.ldif /etc/openldap/seed.ldif
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY tls/*.crt tls/*.key /etc/openldap/tls/

# 389 ldap, 636 ldaps with a valid certificate; 6361-6364 are TLS proxies
# to 389 with broken certificates or settings (see entrypoint.sh).
EXPOSE 389 636 6361 6362 6363 6364

HEALTHCHECK --interval=1s --timeout=2s --retries=30 \
    CMD ldapsearch -x -H ldap://127.0.0.1 -b dc=example,dc=org -s base >/dev/null \
        && LDAPTLS_CACERT=/etc/openldap/tls/ca.crt \
           ldapsearch -x -H ldaps://ldap -b dc=example,dc=org -s base >/dev/null \
        || exit 1

ENTRYPOINT ["/bin/sh", "/usr/local/bin/entrypoint.sh"]
