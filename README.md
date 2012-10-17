# How to install

## FreeBSD

```bash
cd ~ && git clone https://github.com/kvspb/nginx-auth-ldap.git
cp -R /usr/ports/www/nginx ~/nginx-ldap
```

edit ~/nginx-ldap/Makefile add CONFIGURE_ARGS --add-module=path_to_http_auth_ldap_module

```bash
HAS_CONFIGURE= yes
CONFIGURE_ARGS+=--prefix=${ETCDIR} \
....
--user=${WWWOWN} --group=${WWWGRP} \
--add-module=path_to_http_auth_ldap_module
```

install modified port

```bash
cd ~/nginx-ldap
make install clean
```

## Linux

```bash
cd ~ && git clone https://github.com/kvspb/nginx-auth-ldap.git   
```

in nginx source folder

```bash
./configure --add-module=path_to_http_auth_ldap_module
make install
```
