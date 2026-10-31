# Minimal OpenLDAP server seeded with the fixtures used by the test suite.
FROM alpine:3.22

RUN apk add --no-cache openldap openldap-back-mdb openldap-clients

COPY slapd.conf /etc/openldap/slapd.conf
COPY seed.ldif /etc/openldap/seed.ldif
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

EXPOSE 389

HEALTHCHECK --interval=1s --timeout=2s --retries=30 \
    CMD ldapsearch -x -H ldap://127.0.0.1 -b dc=example,dc=org -s base >/dev/null || exit 1

ENTRYPOINT ["/bin/sh", "/usr/local/bin/entrypoint.sh"]
