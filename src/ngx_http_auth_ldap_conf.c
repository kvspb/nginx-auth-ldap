/**
 * Copyright (C) 2011-2013 Valery Komarov <komarov@valerka.net>
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
static char * ngx_http_auth_ldap_parse_require(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static char * ngx_http_auth_ldap_parse_satisfy(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static char * ngx_http_auth_ldap_parse_referral(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static char * ngx_http_auth_ldap_parse_flag(ngx_conf_t *cf, ngx_flag_t *flag);

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
    ngx_http_auth_ldap_server_t    *server;
    ngx_http_auth_ldap_main_conf_t *cnf = conf;

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
        cnf->servers = ngx_array_create(cf->pool, cnf->servers_size, sizeof(ngx_http_auth_ldap_server_t));
        if (cnf->servers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    server = ngx_array_push(cnf->servers);
    if (server == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(server, sizeof(*server));
    server->connect_timeout = 10000;
    server->reconnect_timeout = 10000;
    server->bind_timeout = 5000;
    server->request_timeout = 10000;
    server->alias = name;
    server->referral = 1;

    save = *cf;
    cf->handler = ngx_http_auth_ldap_ldap_server;
    cf->handler_conf = conf;
    rv = ngx_conf_parse(cf, NULL);
    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    return NGX_CONF_OK;
}

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
    char                           *rv;
    ngx_str_t                      *value;
    ngx_http_auth_ldap_server_t    *server;
    ngx_http_auth_ldap_main_conf_t *cnf = conf;
    ngx_int_t                      i;

    /* It should be safe to just use latest server from array */
    server = ((ngx_http_auth_ldap_server_t *) cnf->servers->elts + (cnf->servers->nelts - 1));

    value = cf->args->elts;

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
        return ngx_http_auth_ldap_parse_referral(cf, server);
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
    } else if (ngx_strcmp(value[0].data, "ssl_check_cert") == 0) {
      rv = ngx_http_auth_ldap_parse_flag(cf, &server->ssl_check_cert);
      #if OPENSSL_VERSION_NUMBER < 0x10002000
      #if GNUC > 4
      #warning "http_auth_ldap: Compiling with OpenSSL < 1.0.2, certificate verification will be unavailable. OPENSSL_VERSION_NUMBER == " XSTR(OPENSSL_VERSION_NUMBER)
      #endif
      if (rv == NGX_CONF_OK && server->ssl_check_cert) {
        server->ssl_check_cert = 0;
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
          "http_auth_ldap: 'ssl_cert_check': cannot verify remote certificate's domain name because "
          "your version of OpenSSL is too old. "
          "Please install OpenSSL >= 1.02 and recompile nginx.");
      }
      #endif
      return rv;
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
            s = &((ngx_http_auth_ldap_server_t *) mconf->servers->elts)[j];
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
static char *
ngx_http_auth_ldap_parse_url(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server)
{
    ngx_str_t *value;
    u_char *p;

    value = cf->args->elts;

    int rc = ldap_url_parse((const char *) value[1].data, &server->ludpp);
    if (rc != LDAP_SUCCESS) {
        switch (rc) {
            case LDAP_URL_ERR_MEM:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Cannot allocate memory space.");
                break;

            case LDAP_URL_ERR_PARAM:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Invalid parameter.");
                break;

            case LDAP_URL_ERR_BADSCHEME:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: URL doesnt begin with \"ldap[s]://\".");
                break;

            case LDAP_URL_ERR_BADENCLOSURE:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: URL is missing trailing \">\".");
                break;

            case LDAP_URL_ERR_BADURL:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Invalid URL.");
                break;

            case LDAP_URL_ERR_BADHOST:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Host port is invalid.");
                break;

            case LDAP_URL_ERR_BADATTRS:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Invalid or missing attributes.");
                break;

            case LDAP_URL_ERR_BADSCOPE:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Invalid or missing scope string.");
                break;

            case LDAP_URL_ERR_BADFILTER:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Invalid or missing filter.");
                break;

            case LDAP_URL_ERR_BADEXTS:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Invalid or missing extensions.");
                break;
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

    server->url.data = ngx_palloc(cf->pool, ngx_strlen(server->ludpp->lud_scheme) + sizeof("://") - 1 +
        ngx_strlen(server->ludpp->lud_host) + sizeof(":65535"));
    p = ngx_sprintf(server->url.data, "%s://%s:%d%Z", server->ludpp->lud_scheme, server->ludpp->lud_host,
        server->ludpp->lud_port);
    server->url.len = p - server->url.data - 1;

    ngx_memzero(&server->parsed_url, sizeof(ngx_url_t));
    server->parsed_url.url.data = (u_char *) server->ludpp->lud_host;
    server->parsed_url.url.len = ngx_strlen(server->ludpp->lud_host);
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
        ngx_http_auth_ldap_main_conf_t *halmcf =
            ngx_http_conf_get_module_main_conf(cf, ngx_http_auth_ldap_module);
        ngx_uint_t protos = NGX_SSL_SSLv2 | NGX_SSL_SSLv3 |
            NGX_SSL_TLSv1 | NGX_SSL_TLSv1_1 | NGX_SSL_TLSv1_2;
        if (halmcf->ssl.ctx == NULL && ngx_ssl_create(&halmcf->ssl, protos, halmcf) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        return NGX_CONF_OK;
#endif
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Protocol \"%s://\" is not supported.",
            server->ludpp->lud_scheme);
        return NGX_CONF_ERROR;
    }
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

    value = cf->args->elts;
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "http_auth_ldap: parse_require");

    if (ngx_strcmp(value[1].data, "valid_user") == 0) {
        server->require_valid_user = 1;
        if (cf->args->nelts < 3) {
            return NGX_CONF_OK;
        }
        if (server->require_valid_user_dn.value.data != NULL) {
            return "is duplicate";
        }
        target = &server->require_valid_user_dn;
    } else if (ngx_strcmp(value[1].data, "user") == 0) {
        if (server->require_user == NULL) {
            server->require_user = ngx_array_create(cf->pool, 4, sizeof(ngx_http_complex_value_t));
            if (server->require_user == NULL) {
                return NGX_CONF_ERROR;
            }
        }
        target = ngx_array_push(server->require_user);
    } else if (ngx_strcmp(value[1].data, "group") == 0) {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "http_auth_ldap: Setting group");
        if (server->require_group == NULL) {
            server->require_group = ngx_array_create(cf->pool, 4, sizeof(ngx_http_complex_value_t));
            if (server->require_group == NULL) {
                return NGX_CONF_ERROR;
            }
        }
        target = ngx_array_push(server->require_group);
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

    return NGX_CONF_OK;
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
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "http_auth_ldap: Setting satisfy all");
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
 * Parse "referral" conf parameter
 */
static char *
ngx_http_auth_ldap_parse_referral(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server)
{
    ngx_str_t *value;
    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "on") == 0) {
        server->referral = 1;
        return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        server->referral = 0;
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: Incorrect value for referral");
    return NGX_CONF_ERROR;
}
