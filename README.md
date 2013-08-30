# About this repository

This is a fork of the original nginx LDAP HTTP authentication module with the following improvements:
+ Uses asynchronous LDAP operations through nginx's event-driven framework
+ Creates configurable number of persistent connections to each server per each worker
+ Supports configurable cache per worker process for improved performance of consecutive requests
+ Transfers only the DN when searching, not the whole entry (several KB)
+ Allows only one LDAP (bind) operation per request when the whole user DN can be composed using variables
+ Has cleaner code and debug log messages
+ Contains other minor bug fixes

I made these changes for a project of a company I don't work for anymore and I am no longer able or willing to continue developing or maintaining the code, because I have no use for it. The project goes on (and naturally will be the next big thing!!1), but I don't know how or whether at all will my successor publish further additions or fixes. So anybody interested is welcome to fork the repository and make it into a proper stable and respected nginx module, finally.

A brief TODO list, just off the top of my head:
+ Test, test, test everything and test it thoroughly. An automated test suite might be a good idea.
+ Configurable timeouts of various events, currently hardcoded
+ Some global code review after the quick and dirty development
+ Better documentation

Good luck!

---

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
