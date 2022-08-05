# LDAP Authentication module for nginx
LDAP module for nginx which supports authentication against multiple LDAP servers.

## Project history

This project is a clone of [nginx-auth-ldap](https://github.com/kvspb/nginx-auth-ldap)  original module from [kvspb](https://github.com/kvspb).

The reasons for this fork are:

* The original project seems abondonned (no commit since 2 years)
* Inherit from other contributors fixes/features
  * [Pull request #237](https://github.com/kvspb/nginx-auth-ldap/pull/237) from [mmguero-dev](https://github.com/mmguero-dev/nginx-auth-ldap)
* Add new features
  * Add the use of `resolver` to resolve hostname of the LDAP server
  * Support LDAP attributes fecthing during search

## How to install

### FreeBSD

```bash
cd /usr/ports/www/nginx && make config install clean
```

Check HTTP_AUTH_LDAP options


```
[*] HTTP_AUTH_LDAP        3rd party http_auth_ldap module
```

### Linux

```bash
cd ~ && git clone https://github.com/Ericbla/nginx-auth-ldap.git   
```

in nginx source folder

```bash
./configure --add-module=path_to_http_auth_ldap_module
make install
```

## Example configuration

Define list of your LDAP servers with required user/group requirements:

```bash
    http {
      auth_ldap_resolver 8.8.8.8;

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

## Available config parameters

### auth_ldap_cache_enabled

* Syntax: auth_ldap_cache_enabled on | off;
* Default: auth_ldap_cache_enabled off;
* Context: http

### auth_ldap_cache_expiration_time

* Syntax: auth_ldap_cache_expiration_time time;
* Default: auth_ldap_cache_expiration_time 10000;
* Context: http

Cache expiration time (in ms).

### auth_ldap_cache_size

* Syntax: auth_ldap_cache_size size;
* Default: auth_ldap_cache_size 100;
* Context: http

Number of cached LDAP authentications (min 100)

### auth_ldap_servers_size

* Syntax: auth_ldap_servers_size size;
* Syntax: auth_ldap_servers_size 7;
* Context: http

Maximum number of `ldap_server` elements to support

### auth_ldap

* Syntax: auth_ldap off | _realm_;
* Default: --
* Context: http, server, loc, limit_expect

Set the _realm_ to be used with the `WWW-Authenticate` response header when authentication failed or is missing.

### auth_ldap_servers

* Syntax: auth_ldap_servers _name_;
* Default: --
* Context: http, server, loc, limit_expect

Select the server _name_ to work with user authentication

### auth_ldap_resolver

* Syntax: auth_ldap_resolver _address_ ... [valid=time] [ipv4=on|off] [ipv6=on|off] [status_zone=zone];
* Default: --
* Context: http

The resolver to use as a fallback when the system hostname resolution
(gethostbyname()) can't resolve the LDAP server hostname.
See the `resolver` directive of the **ngx_http_core_module**

### auth_ldap_resolver_timeout

* Syntax: auth_ldap_resolver_timeout time;
* Default: auth_ldap_resolver_timeout 10000;
* Context: http

Resolver requests timeout (in ms).

### ldap_server

* Syntax: ldap_server _name_ { ... }
* Default: none
* Context: http

## Configuration parameters for the `ldap_server` block

### url

* Syntax: url _url_;
* Default: --
* Context: `ldap_server` block

url format: ldap[s]://host[:port]/dn?attrs?scope?filter[?exts]

### binddn

* Syntax: binddn _dn_;
* Default: --
* Context: `ldap_server` block

### binddn_passwd

* Syntax: binddn_passwd _password_;
* Default: --
* Context: `ldap_server` block

### group_attribute

* Syntax: group attr;
* Default: --
* Context: `ldap_server` block

### group_attribute_is_dn

* Syntax: group_attribute_is_dn on | off;
* Default: group_attribute_is_dn off;
* Context: `ldap_server` block

Tell to search for full DN in member object.

### require

* Syntax: require valid_user | user | group;
* Default: --;
* Context: `ldap_server` block


### satisfy

* Syntax: satisfy all | any;
* Default: --;
* Context: `ldap_server` block

### max_down_retries

* Syntax: max_down_retries _number_;
* Default: max_down_retries 0;
* Context: `ldap_server` block

Retry count for attempting to reconnect to an LDAP server if it is considered
"DOWN".  This may happen if a KEEP-ALIVE connection to an LDAP server times 
out or is terminated by the server end after some amount of time.  

This can usually help with the following error:

```text
http_auth_ldap: ldap_result() failed (-1: Can't contact LDAP server)
```


### ssl_check_cert

* Syntax: ssl_check_cert on | chain | off;
* Default: ssl_check_cert off;
* Context: `ldap_server` block

Verify the remote certificate for LDAPs connections. If disabled, any remote certificate will be
accepted which exposes you to possible man-in-the-middle attacks. Note that the server's
certificate will need to be signed by a proper CA trusted by your system if this is enabled.
See below how to trust CAs without installing them system-wide.

This options needs OpenSSL >= 1.0.2; it is unavailable if compiled with older versions.

When `chain` is given, verify cert chain but not hostname/IP in SAN

### ssl_ca_file

* Syntax: ssl_ca_file _file-path_;
* Default: --;
* Context: `ldap_server` block

Trust the CA certificate in this file (see ssl_check_cert above).

### ssl_ca_dir

* Syntax: ssl_ca_file _dir-path_;
* Default: --;
* Context: `ldap_server` block

Trust all CA certificates in this directory (see ssl_check_cert above).

Note that you need to provide hash-based symlinks in the directory for this to work;
you'll basically need to run OpenSSL's c_rehash command in this directory.

### referral

* Syntax: referral on | off;
* Default: referral on;
* Context: `ldap_server` block

LDAP library default is on. This option disables usage of referral messages from
LDAP server. Usefull for authenticating against read only AD server without access
to read write.

### attribute_header_prefix

* Syntax: attribute_header_prefix _string_;
* Default: attribute_header_prefix X-LDAP-ATTRS-;
* Context: `ldap_server` block

The prefix for the HEADER names used to carry the feteched attributes (default: "X-LDAP-ATTRS-")

### search_attribute

* Syntax: search_attribute _attr_;
* Default: --
* Context: `ldap_server` block

Add this LDAP attribute description for the search (require valid-user or require user). The attribute value will be return as a HTTP header (<attribute_header_prefix><search_attribute>) in the authentication response.

_Note_: This parameter can be repeated several times when several attributes need to be fetched
