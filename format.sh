#!/bin/sh

FILE=ngx_http_auth_ldap_module.c

astyle --options=.astyle ${FILE} || (echo 'astyle failed'; exit 1);
dos2unix --quiet ${FILE} || (echo 'dos2unix failed'; exit 2);
