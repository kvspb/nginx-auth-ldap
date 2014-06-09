# LDAP Authentication module for nginx
LDAP module for nginx which supports authentication against multiple LDAP servers.

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

# Example configuration
Define list of your LDAP servers with required user/group requirements:

```bash
    http {
      ldap_server test1 {
        url ldap://192.168.0.1:3268/DC=test,DC=local?sAMAccountName?sub?(objectClass=person);
        binddn "TEST\\LDAPUSER";
        binddn_passwd LDAPPASSWORD;
        group_attribute uniquemember;
        group_attribute_is_dn on;
        require valid_user;
      }

      ldap_server test2 {
        url ldap://192.168.0.2:3268/DC=test,DC=local?sAMAccountName?sub?(objectClass=person);
        binddn "TEST\\LDAPUSER";
        binddn_passwd LDAPPASSWORD;
        group_attribute uniquemember;
        group_attribute_is_dn on;
        require valid_user;
      }
    }
```

And add required servers in correct order into your location/server directive:
```bash
    server {
        listen       8000;
        server_name  localhost;

        auth_ldap "Forbidden";
        auth_ldap_servers test1;
		auth_ldap_servers test2;

        location / {
            root   html;
            index  index.html index.htm;
        }

    }
```
