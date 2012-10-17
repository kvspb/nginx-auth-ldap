# How to install

## FreeBSD

```bash
cd /usr/ports/www/nginx && make config install clean
```

Check HTTP_AUTH_LDAP options


```
[*] HTTP_AUTH_LDAP        3rd party http_auth_ldap module 
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
