/**
 * Copyright (C) 2011-2026 Valery Komarov <komarov@valerka.net>
 * Copyright (C) 2013 Jiri Hruska <jirka@fud.cz>
 * Copyright (C) 2015-2016 Victor Hahn Castell <victor.hahn@flexoptix.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* ldap_server block and directive parsing. */

#include "ngx_http_auth_ldap.h"

static char * ngx_http_auth_ldap_ldap_server(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
static char * ngx_http_auth_ldap_parse_url(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static void ngx_http_auth_ldap_free_urldesc(void *data);
static char * ngx_http_auth_ldap_parse_require(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static char * ngx_http_auth_ldap_parse_satisfy(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static char * ngx_http_auth_ldap_parse_referral(ngx_conf_t *cf);
static char * ngx_http_auth_ldap_parse_flag(ngx_conf_t *cf, ngx_flag_t *flag);
static char * ngx_http_auth_ldap_parse_keepalive(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static ngx_int_t ngx_http_auth_ldap_template_shape(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server, ngx_str_t *template);
static ngx_int_t ngx_http_auth_ldap_check_filter(const char *filter);
#if (NGX_OPENSSL)
static char * ngx_http_auth_ldap_create_ssl(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static char * ngx_http_auth_ldap_load_ca(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
#endif

/* ldap_server directives that take exactly one value; "require" is checked
 * in ngx_http_auth_ldap_parse_require(). */
static const char *ngx_http_auth_ldap_single_value_directives[] = {
    "url", "binddn", "binddn_passwd", "group_attribute",
    "group_attribute_is_dn", "satisfy", "referral", "max_down_retries",
    "connections", "so_keepalive", "starttls", "ssl_check_cert", "ssl_ca_dir", "ssl_ca_file",
    "connect_timeout", "reconnect_timeout", "bind_timeout",
    "request_timeout", "include", NULL
};

/* Messages for the errors of ldap_url_parse(). */
static const struct {
    int          code;
    const char  *text;
} ngx_http_auth_ldap_url_errors[] = {
    { LDAP_URL_ERR_MEM, "Cannot allocate memory space." },
    { LDAP_URL_ERR_PARAM, "Invalid parameter." },
    { LDAP_URL_ERR_BADSCHEME, "URL doesnt begin with \"ldap[s]://\"." },
    { LDAP_URL_ERR_BADENCLOSURE, "URL is missing trailing \">\"." },
    { LDAP_URL_ERR_BADURL, "Invalid URL." },
    { LDAP_URL_ERR_BADHOST, "Host port is invalid." },
    { LDAP_URL_ERR_BADATTRS, "Invalid or missing attributes." },
    { LDAP_URL_ERR_BADSCOPE, "Invalid or missing scope string." },
    { LDAP_URL_ERR_BADFILTER, "Invalid or missing filter." },
    { LDAP_URL_ERR_BADEXTS, "Invalid or missing extensions." },
    { 0, NULL }
};

/*** Configuration and initialization ***/

/**
 * Reads ldap_server block and sets ngx_http_auth_ldap_ldap_server as a handler of each conf value
 */
char *
ngx_http_auth_ldap_ldap_server_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                           *rv;
    ngx_str_t                      *value, name;
    ngx_conf_t                     save;
    ngx_http_auth_ldap_server_t    *server, **slot;
    ngx_http_auth_ldap_main_conf_t *cnf = conf;
    ngx_uint_t                     i;

    value = cf->args->elts;

    name = value[1];

    if (ngx_strlen(name.data) == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Missing server name in ldap_server");
        return NGX_CONF_ERROR;
    }

    if (cnf->servers == NULL) {
        if (cnf->servers_size == NGX_CONF_UNSET) {
            cnf->servers_size = NGX_HTTP_AUTH_LDAP_MAX_SERVERS_SIZE;
        }
        cnf->servers = ngx_array_create(cf->pool, cnf->servers_size,
                                        sizeof(ngx_http_auth_ldap_server_t *));
        if (cnf->servers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 0; i < cnf->servers->nelts; i++) {
        server = ((ngx_http_auth_ldap_server_t **) cnf->servers->elts)[i];
        if (server->alias.len == name.len
            && ngx_strncmp(server->alias.data, name.data, name.len) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "http_auth_ldap: duplicate ldap_server \"%V\"", &name);
            return NGX_CONF_ERROR;
        }
    }

    /*
     * Each server is allocated on its own: auth_ldap_servers keeps pointers
     * to it, which must stay valid when the array grows and moves.
     */
    server = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_ldap_server_t));
    if (server == NULL) {
        return NGX_CONF_ERROR;
    }

    slot = ngx_array_push(cnf->servers);
    if (slot == NULL) {
        return NGX_CONF_ERROR;
    }

    *slot = server;
    server->connect_timeout = 10000;
    server->reconnect_timeout = 10000;
    server->bind_timeout = 5000;
    server->request_timeout = 10000;
    /* Find connections a firewall forgot long before the kernel would. */
    server->so_keepalive = 1;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    server->keepidle = 60;
    server->keepintvl = 10;
    server->keepcnt = 3;
#endif
    server->alias = name;

    save = *cf;
    cf->handler = ngx_http_auth_ldap_ldap_server;
    cf->handler_conf = conf;
    rv = ngx_conf_parse(cf, NULL);
    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (server->ludpp == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "http_auth_ldap: no \"url\" in ldap_server \"%V\"",
                           &server->alias);
        return NGX_CONF_ERROR;
    }

    if (server->starttls) {
        if (ngx_strcmp(server->ludpp->lud_scheme, "ldap") != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "http_auth_ldap: \"starttls\" needs an ldap:// url in ldap_server \"%V\"",
                &server->alias);
            return NGX_CONF_ERROR;
        }
#if (NGX_OPENSSL)
        rv = ngx_http_auth_ldap_create_ssl(cf, server);
        if (rv != NGX_CONF_OK) {
            return rv;
        }
#else
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "http_auth_ldap: \"starttls\" needs nginx built with OpenSSL");
        return NGX_CONF_ERROR;
#endif
    }

#if (NGX_OPENSSL)
    return ngx_http_auth_ldap_load_ca(cf, server);
#else
    return NGX_CONF_OK;
#endif
}

#if (NGX_OPENSSL)
/**
 * Create the SSL context of a server for ldaps:// or StartTLS, once.
 */
static char *
ngx_http_auth_ldap_create_ssl(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server)
{
    /* SSL 2.0 and 3.0 are broken (RFC 6176, RFC 7568). */
    ngx_uint_t protos = NGX_SSL_TLSv1 | NGX_SSL_TLSv1_1 | NGX_SSL_TLSv1_2
#ifdef NGX_SSL_TLSv1_3
        | NGX_SSL_TLSv1_3
#endif
        ;
    ngx_pool_cleanup_t *cln;

    if (server->ssl.ctx != NULL) {
        return NGX_CONF_OK;
    }

    /* One context per server: CA locations must not add up (kvspb#258). */
    server->ssl.log = cf->log;
    if (ngx_ssl_create(&server->ssl, protos, NULL) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        ngx_ssl_cleanup_ctx(&server->ssl);
        return NGX_CONF_ERROR;
    }
    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = &server->ssl;

    return NGX_CONF_OK;
}
#endif

#if (NGX_OPENSSL)
/**
 * Load the CA certificates of an ldaps server with ssl_check_cert on into
 * its own SSL context, once, after the whole ldap_server block is read.
 */
static char *
ngx_http_auth_ldap_load_ca(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server)
{
    ngx_str_t  *location;

    if (server->ssl.ctx == NULL || !server->ssl_check_cert) {
        return NGX_CONF_OK;
    }

    if (server->ssl_ca_file.data != NULL || server->ssl_ca_dir.data != NULL) {
        if (SSL_CTX_load_verify_locations(server->ssl.ctx,
                (char *) server->ssl_ca_file.data, (char *) server->ssl_ca_dir.data) != 1)
        {
            location = server->ssl_ca_file.data != NULL ? &server->ssl_ca_file : &server->ssl_ca_dir;
            ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                "http_auth_ldap: cannot load CA certificates from \"%V\"", location);
            return NGX_CONF_ERROR;
        }

        return NGX_CONF_OK;
    }

    if (SSL_CTX_set_default_verify_paths(server->ssl.ctx) != 1) {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
            "http_auth_ldap: cannot use the default CA certificate locations");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
#endif

#define CONF_MSEC_VALUE(cf,value,server,x) \
if (ngx_strcmp(value[0].data, #x) == 0) { \
        ngx_msec_t _i = ngx_parse_time(&value[1], 0); \
        if (_i == (ngx_msec_t) NGX_ERROR || _i == 0) { \
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: '" #x "' value has to be a valid time unit greater than 0"); \
            return NGX_CONF_ERROR; \
        } \
        server->x = _i; \
    }
/**
 * Called for every variable inside ldap_server block
 */
static char *
ngx_http_auth_ldap_ldap_server(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_str_t                      *value;
    ngx_http_auth_ldap_server_t    *server;
    ngx_http_auth_ldap_main_conf_t *cnf = conf;
    ngx_int_t                      i;
    const char                     **name;

    /* It should be safe to just use latest server from array */
    server = ((ngx_http_auth_ldap_server_t **) cnf->servers->elts)[cnf->servers->nelts - 1];

    value = cf->args->elts;

    for (name = ngx_http_auth_ldap_single_value_directives; *name != NULL; name++) {
        if (ngx_strcmp(value[0].data, *name) == 0 && cf->args->nelts != 2) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "http_auth_ldap: invalid number of arguments in \"%V\"", &value[0]);
            return NGX_CONF_ERROR;
        }
    }

    /* TODO: Add more validation */
    if (ngx_strcmp(value[0].data, "url") == 0) {
        return ngx_http_auth_ldap_parse_url(cf, server);
    } else if (ngx_strcmp(value[0].data, "binddn") == 0) {
        server->bind_dn = value[1];
    } else if (ngx_strcmp(value[0].data, "binddn_passwd") == 0) {
        server->bind_dn_passwd = value[1];
    } else if (ngx_strcmp(value[0].data, "group_attribute") == 0) {
        server->group_attribute = value[1];
    } else if (ngx_strcmp(value[0].data, "group_attribute_is_dn") == 0) {
        return ngx_http_auth_ldap_parse_flag(cf, &server->group_attribute_dn);
    } else if (ngx_strcmp(value[0].data, "require") == 0) {
        return ngx_http_auth_ldap_parse_require(cf, server);
    } else if (ngx_strcmp(value[0].data, "satisfy") == 0) {
        return ngx_http_auth_ldap_parse_satisfy(cf, server);
    } else if (ngx_strcmp(value[0].data, "referral") == 0) {
        return ngx_http_auth_ldap_parse_referral(cf);
    } else if (ngx_strcmp(value[0].data, "max_down_retries") == 0) {
        i = ngx_atoi(value[1].data, value[1].len);
        if (i == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: 'max_down_retries' value must be an integer");
            return NGX_CONF_ERROR;
        }
        server->max_down_retries = i;
    } else if (ngx_strcmp(value[0].data, "connections") == 0) {
        i = ngx_atoi(value[1].data, value[1].len);
        if (i == NGX_ERROR || i == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: 'connections' value has to be a number greater than 0");
            return NGX_CONF_ERROR;
        }
        server->connections = i;
    } else if (ngx_strcmp(value[0].data, "so_keepalive") == 0) {
        return ngx_http_auth_ldap_parse_keepalive(cf, server);
    } else if (ngx_strcmp(value[0].data, "starttls") == 0) {
        return ngx_http_auth_ldap_parse_flag(cf, &server->starttls);
    } else if (ngx_strcmp(value[0].data, "ssl_check_cert") == 0) {
        return ngx_http_auth_ldap_parse_flag(cf, &server->ssl_check_cert);
    } else if (ngx_strcmp(value[0].data, "ssl_ca_dir") == 0) {
      server->ssl_ca_dir = value[1];
    } else if (ngx_strcmp(value[0].data, "ssl_ca_file") == 0) {
      server->ssl_ca_file = value[1];
    }
    else CONF_MSEC_VALUE(cf,value,server,connect_timeout)
    else CONF_MSEC_VALUE(cf,value,server,reconnect_timeout)
    else CONF_MSEC_VALUE(cf,value,server,bind_timeout)
    else CONF_MSEC_VALUE(cf,value,server,request_timeout)
    else if (ngx_strcmp(value[0].data, "include") == 0) {
        return ngx_conf_include(cf, dummy, conf);
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "http_auth_ldap: unknown directive \"%V\" in ldap_server", &value[0]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/**
 * Parse an "on" | "off" value of the directive in cf->args
 */
static char *
ngx_http_auth_ldap_parse_flag(ngx_conf_t *cf, ngx_flag_t *flag)
{
    ngx_str_t *value;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "on") == 0) {
        *flag = 1;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        *flag = 0;
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "http_auth_ldap: invalid value \"%V\" for %V, it must be \"on\" or \"off\"",
        &value[1], &value[0]);
    return NGX_CONF_ERROR;
}

/*
 * so_keepalive on | off | [idle]:[interval]:[count], as the parameter of
 * the listen directive: "on" keeps the system timings.
 */
static char *
ngx_http_auth_ldap_parse_keepalive(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server)
{
    ngx_str_t *value, s;
    u_char *p, *end;
    ngx_int_t n[3];
    ngx_uint_t i;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "on") == 0 || ngx_strcmp(value[1].data, "off") == 0) {
        server->keepidle = 0;
        server->keepintvl = 0;
        server->keepcnt = 0;
        return ngx_http_auth_ldap_parse_flag(cf, &server->so_keepalive);
    }

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    p = value[1].data;
    end = value[1].data + value[1].len;

    for (i = 0; i < 3; i++) {
        s.data = p;
        while (p < end && *p != ':') {
            p++;
        }
        s.len = p - s.data;

        if (s.len == 0) {
            n[i] = 0;
        } else if (i < 2) {
            n[i] = ngx_parse_time(&s, 1);
        } else {
            n[i] = ngx_atoi(s.data, s.len);
        }
        if (n[i] == NGX_ERROR || (s.len != 0 && n[i] == 0)) {
            goto invalid;
        }

        if (i < 2) {
            if (p == end) {
                goto invalid;
            }
            p++;
        }
    }

    if (p != end || (n[0] == 0 && n[1] == 0 && n[2] == 0)) {
        goto invalid;
    }

    server->so_keepalive = 1;
    server->keepidle = n[0];
    server->keepintvl = n[1];
    server->keepcnt = n[2];
    return NGX_CONF_OK;

invalid:
#endif

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "http_auth_ldap: invalid value \"%V\" for so_keepalive, it must be \"on\", \"off\""
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
        " or [idle]:[interval]:[count]"
#endif
        , &value[1]);
    return NGX_CONF_ERROR;
}

/**
 * Parse auth_ldap directive
 */
char *
ngx_http_auth_ldap(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    ngx_http_auth_ldap_loc_conf_t *cnf = conf;
    u_char *p;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        ngx_str_set(&cnf->realm, "");
        return NGX_CONF_OK;
    }

    cnf->realm.len = sizeof("Basic realm=\"") - 1 + value[1].len + 1;
    cnf->realm.data = ngx_pcalloc(cf->pool, cnf->realm.len);
    if (cnf->realm.data == NULL) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(cnf->realm.data, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, value[1].data, value[1].len);
    *p = '"';

    return NGX_CONF_OK;
}

/**
 * Parse auth_ldap_servers directive
 */
char *
ngx_http_auth_ldap_servers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_ldap_loc_conf_t *cnf;
    ngx_http_auth_ldap_main_conf_t *mconf;
    ngx_http_auth_ldap_server_t *server, *s, **target;
    ngx_str_t *value;
    ngx_uint_t i, j;

    cnf = conf;
    mconf = ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_ldap_module);

    for (i = 1; i < cf->args->nelts; i++) {
        value = &((ngx_str_t *) cf->args->elts)[i];
        server = NULL;

        if (mconf->servers == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Using \"auth_ldap_servers\" when no \"ldap_server\" has been previously defined"
                               " (make sure that \"auth_ldap_servers\" goes after \"ldap_server\"s in your configuration file)", value);
            return NGX_CONF_ERROR;
        }

        for (j = 0; j < mconf->servers->nelts; j++) {
            s = ((ngx_http_auth_ldap_server_t **) mconf->servers->elts)[j];
            if (s->alias.len == value->len && ngx_memcmp(s->alias.data, value->data, s->alias.len) == 0) {
                server = s;
                break;
            }
        }

        if (server == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Server \"%V\" has not been defined", value);
            return NGX_CONF_ERROR;
        }


        if (cnf->servers == NGX_CONF_UNSET_PTR) {
            cnf->servers = ngx_array_create(cf->pool, 4, sizeof(ngx_http_auth_ldap_server_t *));
            if (cnf->servers == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        target = (ngx_http_auth_ldap_server_t **) ngx_array_push(cnf->servers);
        if (target == NULL) {
            return NGX_CONF_ERROR;
        }

        *target = server;
    }

    return NGX_CONF_OK;
}

/**
 * Parse URL conf parameter
 */
static void
ngx_http_auth_ldap_free_urldesc(void *data)
{
    ldap_free_urldesc((LDAPURLDesc *) data);
}

static char *
ngx_http_auth_ldap_parse_url(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server)
{
    ngx_pool_cleanup_t *cln;
    ngx_str_t *value;
    ngx_str_t host;
    ngx_flag_t ipv6;
    u_char *p;
    ngx_uint_t i;
    int rc;

    value = cf->args->elts;

    if (server->ludpp != NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: \"url\" is duplicate");
        return NGX_CONF_ERROR;
    }

    rc = ldap_url_parse((const char *) value[1].data, &server->ludpp);
    if (rc == LDAP_SUCCESS) {
        /* libldap allocates it with malloc(): free it with the configuration. */
        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            ldap_free_urldesc(server->ludpp);
            server->ludpp = NULL;
            return NGX_CONF_ERROR;
        }
        cln->handler = ngx_http_auth_ldap_free_urldesc;
        cln->data = server->ludpp;
    }
    if (rc != LDAP_SUCCESS) {
        for (i = 0; ngx_http_auth_ldap_url_errors[i].text != NULL; i++) {
            if (ngx_http_auth_ldap_url_errors[i].code == rc) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: %s",
                                   ngx_http_auth_ldap_url_errors[i].text);
                break;
            }
        }
        return NGX_CONF_ERROR;
    }

    if (server->ludpp->lud_attrs == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: No user attribute specified in auth_ldap_url.");
        return NGX_CONF_ERROR;
    }

    if (server->ludpp->lud_host == NULL || server->ludpp->lud_host[0] == '\0') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "http_auth_ldap: No host specified in auth_ldap_url.");
        return NGX_CONF_ERROR;
    }

    if (server->ludpp->lud_port < 1 || server->ludpp->lud_port > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "http_auth_ldap: Invalid port %d in auth_ldap_url.", server->ludpp->lud_port);
        return NGX_CONF_ERROR;
    }

    if (server->ludpp->lud_filter != NULL
        && ngx_http_auth_ldap_check_filter(server->ludpp->lud_filter) != NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "http_auth_ldap: Invalid filter \"%s\" in auth_ldap_url.", server->ludpp->lud_filter);
        return NGX_CONF_ERROR;
    }

    /*
     * ldap_url_parse() strips the brackets of an IPv6 address; put them
     * back for ldap_init_fd() and ngx_parse_url(), which read the part
     * after the last ':' as the port otherwise.
     */
    host.len = ngx_strlen(server->ludpp->lud_host);
    ipv6 = (ngx_strlchr((u_char *) server->ludpp->lud_host,
                        (u_char *) server->ludpp->lud_host + host.len, ':') != NULL);

    host.data = ngx_pnalloc(cf->pool, host.len + 2);
    if (host.data == NULL) {
        return NGX_CONF_ERROR;
    }
    host.len = ngx_sprintf(host.data, ipv6 ? "[%s]" : "%s", server->ludpp->lud_host) - host.data;

    server->url.data = ngx_pnalloc(cf->pool, ngx_strlen(server->ludpp->lud_scheme) + sizeof("://") - 1 +
        host.len + sizeof(":65535"));
    if (server->url.data == NULL) {
        return NGX_CONF_ERROR;
    }
    p = ngx_sprintf(server->url.data, "%s://%V:%d%Z", server->ludpp->lud_scheme, &host,
        server->ludpp->lud_port);
    server->url.len = p - server->url.data - 1;

    ngx_memzero(&server->parsed_url, sizeof(ngx_url_t));
    server->parsed_url.url = host;
    server->parsed_url.default_port = server->ludpp->lud_port;
    if (ngx_parse_url(cf->pool, &server->parsed_url) != NGX_OK) {
        if (server->parsed_url.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: %s in LDAP hostname \"%V\"",
                server->parsed_url.err, &server->parsed_url.url);
        }
        return NGX_CONF_ERROR;
    }

    if (ngx_strcmp(server->ludpp->lud_scheme, "ldap") == 0) {
        return NGX_CONF_OK;
#if (NGX_OPENSSL)
    } else if (ngx_strcmp(server->ludpp->lud_scheme, "ldaps") == 0) {
        return ngx_http_auth_ldap_create_ssl(cf, server);
#endif
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Protocol \"%s://\" is not supported.",
            server->ludpp->lud_scheme);
        return NGX_CONF_ERROR;
    }
}

/**
 * Check that the URL filter is one parenthesized filter with balanced
 * parentheses: it is placed into "(&<filter>(<attr>=<login>))" verbatim.
 * Parentheses inside values are escaped as \28 and \29 (RFC 4515).
 */
static ngx_int_t
ngx_http_auth_ldap_check_filter(const char *filter)
{
    const char  *p;
    ngx_uint_t   depth;

    if (filter[0] != '(') {
        return NGX_ERROR;
    }

    depth = 0;

    for (p = filter; *p != '\0'; p++) {
        if (*p == '(') {
            if (p[1] == ')') {
                return NGX_ERROR;
            }
            depth++;

        } else if (*p == ')') {
            if (depth == 0) {
                return NGX_ERROR;
            }
            depth--;
            if (depth == 0 && p[1] != '\0') {
                return NGX_ERROR;
            }
        }
    }

    return depth == 0 ? NGX_OK : NGX_ERROR;
}

/**
 * Parse "require" conf parameter
 */
static char *
ngx_http_auth_ldap_parse_require(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server)
{
    ngx_str_t *value;
    ngx_http_complex_value_t* target = NULL;
    ngx_http_compile_complex_value_t ccv;
    ngx_str_t remote_user = ngx_string("remote_user");
    ngx_int_t index;

    value = cf->args->elts;

    if (cf->args->nelts < 2 || cf->args->nelts > 3) {
        goto invalid_args;
    }

    if (ngx_strcmp(value[1].data, "valid_user") == 0) {
        /* Without a template it adds no rule: a server without user or
         * group rules admits every user who can bind. */
        if (cf->args->nelts < 3) {
            return NGX_CONF_OK;
        }
        if (server->require_valid_user_dn.value.data != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "http_auth_ldap: \"require valid_user\" template is duplicate");
            return NGX_CONF_ERROR;
        }
        /* The template expands $remote_user as an escaped RDN value. */
        index = ngx_http_get_variable_index(cf, &remote_user);
        if (index == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }
        server->remote_user_index = index;
        target = &server->require_valid_user_dn;
    } else if (ngx_strcmp(value[1].data, "user") == 0) {
        if (cf->args->nelts < 3) {
            goto invalid_args;
        }
        if (server->require_user == NULL) {
            server->require_user = ngx_array_create(cf->pool, 4, sizeof(ngx_http_complex_value_t));
            if (server->require_user == NULL) {
                return NGX_CONF_ERROR;
            }
        }
        target = ngx_array_push(server->require_user);
    } else if (ngx_strcmp(value[1].data, "group") == 0) {
        if (cf->args->nelts < 3) {
            goto invalid_args;
        }
        if (server->require_group == NULL) {
            server->require_group = ngx_array_create(cf->pool, 4, sizeof(ngx_http_complex_value_t));
            if (server->require_group == NULL) {
                return NGX_CONF_ERROR;
            }
        }
        target = ngx_array_push(server->require_group);
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "http_auth_ldap: invalid value \"%V\" for require, "
            "it must be \"valid_user\", \"user\" or \"group\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (target == NULL) {
       return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = target;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (target == &server->require_valid_user_dn
        && ngx_http_auth_ldap_template_shape(cf, server, &value[2]) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

invalid_args:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "http_auth_ldap: invalid number of arguments in \"require\"");
    return NGX_CONF_ERROR;
}

/*
 * Record the shape of a "require valid_user" template. '$' is a plain
 * character in a DN string, so the template as written parses into the
 * RDNs a DN built from it must keep, whatever its variables hold: neither
 * $remote_user, escaped by the module, nor a copy of the login made by
 * "set" or "map" may add an RDN or an attribute-value pair (audit V-03).
 * A template that is not a DN as written, such as a whole DN in one
 * variable, is not checked.
 */
static ngx_int_t
ngx_http_auth_ldap_template_shape(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server, ngx_str_t *template)
{
    server->user_dn_shape = ngx_http_auth_ldap_dn_shape(cf->pool, template);
    return NGX_OK;
}

/**
 * Parse "satisfy" conf parameter
 */
static char *
ngx_http_auth_ldap_parse_satisfy(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server)
{
    ngx_str_t *value;
    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "all") == 0) {
        server->satisfy_all = 1;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "any") == 0) {
        server->satisfy_all = 0;
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Incorrect value for auth_ldap_satisfy");
    return NGX_CONF_ERROR;
}

/**
 * Check "referral" conf parameter. Referrals are never chased, whatever it
 * says (see ngx_http_auth_ldap_connection_established()).
 */
static char *
ngx_http_auth_ldap_parse_referral(ngx_conf_t *cf)
{
    ngx_str_t *value;
    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "on") == 0
        || ngx_strcmp(value[1].data, "off") == 0)
    {
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Incorrect value for referral");
    return NGX_CONF_ERROR;
}
