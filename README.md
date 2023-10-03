# LDAP Authentication module for Nginx
LDAP module for Nginx which supports authentication against multiple LDAP servers.

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

Clone this repo or download the ZIP archive.

Install `libssl` and `libldap2` headers (on Debian/Ubuntu: `apt install libssl-dev libldap2-dev`).

You can build this module as an SO, statically compile it into the main `nginx` binary or, if using Debian/Ubuntu, build
and install the deb package.

### Build as an SO

- Obtain the Nginx source (on Debian/Ubuntu this can be done with `apt-get source nginx`)
- cd /path/to/nginx/source
```sh
./configure `nginx -V` --with-compat --add-dynamic-module=/path/to/nginx-auth-ldap/source
cp objs/ngx_http_auth_ldap_module.so /usr/share/nginx/modules/ngx_http_auth_ldap_module.so
```
- Add the below config to Nginx so that it loads the module:
```nginx
load_module modules/ngx_http_auth_ldap_module.so;
```

### Build & install the deb package

```sh
sudo apt install build-essential dpkg-dev libssl-dev libldap2-dev
cd /path/to/nginx-auth-ldap/source
dpkg-buildpackage -b -uc
sudo dpkg -i ../libnginx-mod-http-auth-ldap_1.0.0-1_amd64.deb
```

### Statically link into Nginx

```sh
cd /path/to/nginx/source
./configure --add-module=path_to_http_auth_ldap_module
make install
```

# Example configuration
Define list of your LDAP servers with required user/group requirements:

```nginx
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
```nginx
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

# Available config parameters

## url
expected value: string

Available URL schemes: ldap://, ldaps://

## binddn
expected value: string

## binddn_passwd
expected value: string

## group_attribute
expected value: string

## group_attribute_is_dn
expected value: on or off, default off

## require
expected value: valid_user, user, group

## satisfy
expected value: all, any

## max_down_retries
expected value: a number, default 0

Retry count for attempting to reconnect to an LDAP server if it is considered
"DOWN".  This may happen if a KEEP-ALIVE connection to an LDAP server times 
out or is terminated by the server end after some amount of time.  

This can usually help with the following error:

```
http_auth_ldap: ldap_result() failed (-1: Can't contact LDAP server)
```

## connections
expected value: a number greater than 0

## ssl_check_cert
expected value: on or off, default off

Verify the remote certificate for LDAPs connections. If disabled, any remote certificate will be
accepted which exposes you to possible man-in-the-middle attacks. Note that the server's
certificate will need to be signed by a proper CA trusted by your system if this is enabled.
See below how to trust CAs without installing them system-wide.

This options needs OpenSSL >= 1.0.2; it is unavailable if compiled with older versions.

## ssl_ca_file
expected value: file path

Trust the CA certificate in this file (see ssl_check_cert above).

## ssl_ca_dir
expected value: directory path

Trust all CA certificates in this directory (see ssl_check_cert above).

Note that you need to provide hash-based symlinks in the directory for this to work;
you'll basically need to run OpenSSL's c_rehash command in this directory.

## referral
expected value: on, off

LDAP library default is on. This option disables usage of referral messages from
LDAP server. Useful for authenticating against read only AD server without access
to read write.

