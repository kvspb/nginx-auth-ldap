/**
 * Copyright (C) 2011-2013 Valery Komarov <komarov@valerka.net>
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

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ldap.h>

typedef struct {
    LDAPURLDesc *ludpp;
    ngx_str_t url;
    ngx_str_t alias;

    ngx_str_t bind_dn;
    ngx_str_t bind_dn_passwd;

    ngx_str_t group_attribute;
    ngx_flag_t group_attribute_dn;

    ngx_array_t *require_group;     /* array of ngx_http_complex_value_t */
    ngx_array_t *require_user;      /* array of ngx_http_complex_value_t */
    ngx_flag_t require_valid_user;
    ngx_flag_t satisfy_all;
} ngx_http_auth_ldap_server_t;

typedef struct {
    ngx_str_t realm;
    ngx_array_t *servers;
} ngx_http_auth_ldap_loc_conf_t;

typedef struct {
    ngx_array_t *servers;     /* array of ngx_http_auth_ldap_server_t */
    ngx_hash_t srv;
} ngx_http_auth_ldap_conf_t;


static void * ngx_http_auth_ldap_create_conf(ngx_conf_t *cf);
static char * ngx_http_auth_ldap_ldap_server_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_auth_ldap_parse_url(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static char * ngx_http_auth_ldap_parse_require(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static char * ngx_http_auth_ldap_parse_satisfy(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static char * ngx_http_auth_ldap_ldap_server(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
static ngx_int_t ngx_http_auth_ldap_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_ldap_init(ngx_conf_t *cf);
static void * ngx_http_auth_ldap_create_loc_conf(ngx_conf_t *);
static char * ngx_http_auth_ldap_merge_loc_conf(ngx_conf_t *, void *, void *);
static ngx_int_t ngx_http_auth_ldap_authenticate_against_server(ngx_http_request_t *r, ngx_http_auth_ldap_server_t *server,
        ngx_http_auth_ldap_loc_conf_t *conf);
static ngx_int_t ngx_http_auth_ldap_set_realm(ngx_http_request_t *r, ngx_str_t *realm);
static ngx_int_t ngx_http_auth_ldap_authenticate(ngx_http_request_t *r, ngx_http_auth_ldap_loc_conf_t *conf,
        ngx_http_auth_ldap_conf_t *mconf);
static char * ngx_http_auth_ldap(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_auth_ldap_commands[] = {
    {
        ngx_string("ldap_server"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1,
        ngx_http_auth_ldap_ldap_server_block,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("auth_ldap"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
        ngx_http_auth_ldap,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("auth_ldap_servers"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_ANY,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_ldap_loc_conf_t, servers),
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_auth_ldap_module_ctx = {
    NULL, /* preconfiguration */
    ngx_http_auth_ldap_init, /* postconfiguration */
    ngx_http_auth_ldap_create_conf, /* create main configuration */
    NULL, /* init main configuration */
    NULL, //ngx_http_auth_ldap_create_server_conf, /* create server configuration */
    NULL, //ngx_http_auth_ldap_merge_server_conf, /* merge server configuration */
    ngx_http_auth_ldap_create_loc_conf, /* create location configuration */
    ngx_http_auth_ldap_merge_loc_conf /* merge location configuration */
};

ngx_module_t ngx_http_auth_ldap_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_ldap_module_ctx, /* module context */
    ngx_http_auth_ldap_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING /**/
};


/**
 * Reads ldap_server block and sets ngx_http_auth_ldap_ldap_server as a handler of each conf value
 */
static char *
ngx_http_auth_ldap_ldap_server_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_str_t                   *value, name;
    ngx_conf_t                  save;
    ngx_http_auth_ldap_server_t server, *s;
    ngx_http_auth_ldap_conf_t   *cnf = conf;

    value = cf->args->elts;

    name = value[1];

    if (ngx_strlen(name.data) == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Error: no name of ldap server specified");
        return NGX_CONF_ERROR;
    }

    server.alias = name;

    if (cnf->servers == NULL) {
        cnf->servers = ngx_array_create(cf->pool, 7, sizeof(ngx_http_auth_ldap_server_t));
        if (cnf->servers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    s = ngx_array_push(cnf->servers);
    if (s == NULL) {
        return NGX_CONF_ERROR;
    }

    *s = server;

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

/**
 * Called for every variable inside ldap_server block
 */
static char *
ngx_http_auth_ldap_ldap_server(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    char                     *rv;
    ngx_str_t                *value;

    ngx_http_auth_ldap_server_t *server;
    ngx_http_auth_ldap_conf_t *cnf = conf;

    // It should be safe to just use latest server from array
    server = ((ngx_http_auth_ldap_server_t*)cnf->servers->elts + (cnf->servers->nelts - 1));

    value = cf->args->elts;

    // TODO: Add more validation
    if (ngx_strcmp(value[0].data, "url") == 0) {
        return ngx_http_auth_ldap_parse_url(cf, server);
    } else if(ngx_strcmp(value[0].data, "binddn") == 0) {
        server->bind_dn = value[1];
    } else if(ngx_strcmp(value[0].data, "binddn_passwd") == 0) {
        server->bind_dn_passwd = value[1];
    } else if(ngx_strcmp(value[0].data, "group_attribute") == 0) {
        server->group_attribute = value[1];
    } else if(ngx_strcmp(value[0].data, "group_attribute_is_dn") == 0 && ngx_strcmp(value[1].data, "on") == 0) {
        server->group_attribute_dn = 1;
    } else if(ngx_strcmp(value[0].data, "require") == 0) {
        return ngx_http_auth_ldap_parse_require(cf, server);
    } else if(ngx_strcmp(value[0].data, "satisfy") == 0) {
        return ngx_http_auth_ldap_parse_satisfy(cf, server);
    }

    rv = NGX_CONF_OK;

    return rv;
}

/**
 * Parse auth_ldap directive
 */
static char *
ngx_http_auth_ldap(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

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
 * Parse URL conf parameter
 */
static char *
ngx_http_auth_ldap_parse_url(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server) {
    ngx_str_t *value;
    u_char *p;
    value = cf->args->elts;

    server->url = *value;

    int rc = ldap_url_parse((const char*) value[1].data, &server->ludpp);
    if (rc != LDAP_SUCCESS) {
        switch (rc) {
            case LDAP_URL_ERR_MEM:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Cannot allocate memory space.");
                break;

            case LDAP_URL_ERR_PARAM:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Invalid parameter.");
                break;

            case LDAP_URL_ERR_BADSCHEME:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: URL doesnt begin with \"ldap[s]://\".");
                break;

            case LDAP_URL_ERR_BADENCLOSURE:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: URL is missing trailing \">\".");
                break;

            case LDAP_URL_ERR_BADURL:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Invalid URL.");
                break;

            case LDAP_URL_ERR_BADHOST:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Host port is invalid.");
                break;

            case LDAP_URL_ERR_BADATTRS:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Invalid or missing attributes.");
                break;

            case LDAP_URL_ERR_BADSCOPE:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Invalid or missing scope string.");
                break;

            case LDAP_URL_ERR_BADFILTER:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Invalid or missing filter.");
                break;

            case LDAP_URL_ERR_BADEXTS:
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Invalid or missing extensions.");
                break;
        }
        return NGX_CONF_ERROR;
    }

    if (server->ludpp->lud_attrs == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: No attrs in auth_ldap_url.");
        return NGX_CONF_ERROR;
    }

    server->url.len = ngx_strlen(server->ludpp->lud_scheme) + ngx_strlen(server->ludpp->lud_host) + 11; // 11 = len("://:/") + len("65535") + len("\0")
    server->url.data = ngx_pcalloc(cf->pool, server->url.len);
    p = ngx_sprintf(server->url.data, "%s://%s:%d/", (const char*) server->ludpp->lud_scheme,
        (const char*) server->ludpp->lud_host, server->ludpp->lud_port);
    *p = 0;

    return NGX_CONF_OK;
}

/**
 * Parse "require" conf parameter
 */
static char *
ngx_http_auth_ldap_parse_require(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server) {

    ngx_str_t *value;
    ngx_http_complex_value_t* rule = NULL;
    ngx_http_compile_complex_value_t ccv;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "valid_user") == 0) {
        server->require_valid_user = 1;
        return NGX_CONF_OK;
    } else if (ngx_strcmp(value[1].data, "user") == 0) {
        if (server->require_user == NULL) {
            server->require_user = ngx_array_create(cf->pool, 4, sizeof(ngx_http_complex_value_t));
            if (server->require_user == NULL) {
                return NGX_CONF_ERROR;
            }
        }
        rule = ngx_array_push(server->require_user);
    } else if (ngx_strcmp(value[1].data, "group") == 0) {
        if (server->require_group == NULL) {
            server->require_group = ngx_array_create(cf->pool, 4, sizeof(ngx_http_complex_value_t));
            if (server->require_group == NULL) {
                return NGX_CONF_ERROR;
            }
        }
        rule = ngx_array_push(server->require_group);
    }

    if (rule == NULL) {
       return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = rule;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/**
 * Parse "satisfy" conf parameter
 */
static char *
ngx_http_auth_ldap_parse_satisfy(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server) {
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

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Incorrect value for auth_ldap_satisfy ");
    return NGX_CONF_ERROR;
}

/**
 * Create main config which will store ldap_servers array
 */
static void *
ngx_http_auth_ldap_create_conf(ngx_conf_t *cf)
{
    ngx_http_auth_ldap_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_ldap_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

/**
 * Create location conf
 */
static void *
ngx_http_auth_ldap_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_auth_ldap_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_ldap_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->servers = NGX_CONF_UNSET_PTR;

    return conf;
}

/**
 * Merge location conf
 */
static char *
ngx_http_auth_ldap_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_auth_ldap_loc_conf_t *prev = parent;
    ngx_http_auth_ldap_loc_conf_t *conf = child;

    if (conf->realm.data == NULL) {
        conf->realm = prev->realm;
    }
    ngx_conf_merge_ptr_value(conf->servers, prev->servers, NULL);

    return NGX_CONF_OK;
}

/**
 * LDAP Authentication handler
 */
static ngx_int_t ngx_http_auth_ldap_handler(ngx_http_request_t *r) {
    int rc;
    ngx_http_auth_ldap_loc_conf_t *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_ldap_module);

    if (alcf->realm.len == 0) {
        return NGX_DECLINED;
    }

    ngx_http_auth_ldap_conf_t  *cnf;

    cnf = ngx_http_get_module_main_conf(r, ngx_http_auth_ldap_module);

    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {
        return ngx_http_auth_ldap_set_realm(r, &alcf->realm);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_auth_ldap_authenticate(r, alcf, cnf);
}

/**
 * Read user credentials from request, set LDAP parameters and call authentication against required servers
 */
static ngx_int_t ngx_http_auth_ldap_authenticate(ngx_http_request_t *r, ngx_http_auth_ldap_loc_conf_t *conf,
        ngx_http_auth_ldap_conf_t *mconf) {

    ngx_http_auth_ldap_server_t *server, *servers;
    servers = mconf->servers->elts;
    int rc;
    ngx_uint_t i, k;
    ngx_str_t *alias;

    int version = LDAP_VERSION3;
    int reqcert = LDAP_OPT_X_TLS_ALLOW;
    struct timeval timeOut = { 10, 0 };
    ngx_flag_t pass = NGX_CONF_UNSET;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP username: %V", &r->headers_in.user);

    if (r->headers_in.passwd.len == 0)
    {
        return ngx_http_auth_ldap_set_realm(r, &conf->realm);
    }

    /// Set LDAP version to 3 and set connection timeout.
    ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, &version);
    ldap_set_option(NULL, LDAP_OPT_NETWORK_TIMEOUT, &timeOut);

    rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &reqcert);
    if (rc != LDAP_OPT_SUCCESS) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "LDAP: unable to set require cert option: %s",
            ldap_err2string(rc));
    }

    // TODO: We might be using hash here, cause this loops is quite ugly, but it is simple and it works
    int found;
    for (k = 0; k < conf->servers->nelts; k++) {
        alias = ((ngx_str_t*)conf->servers->elts + k);
        found = 0;
        for (i = 0; i < mconf->servers->nelts; i++) {
            server = &servers[i];
            if (server->alias.len == alias->len && ngx_strncmp(server->alias.data, alias->data, server->alias.len) == 0) {
                found = 1;
                pass = ngx_http_auth_ldap_authenticate_against_server(r, server, conf);
                if (pass == 1) {
                    return NGX_OK;
                } else if (pass == NGX_HTTP_INTERNAL_SERVER_ERROR) {
                   return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }
        }

        // If requested ldap server is not found, return 500 and write to log
        if (found == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "LDAP: Server \"%s\" is not defined!", alias->data);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return ngx_http_auth_ldap_set_realm(r, &conf->realm);
}

/**
 * Actual authentication against LDAP server
 */
static ngx_int_t ngx_http_auth_ldap_authenticate_against_server(ngx_http_request_t *r, ngx_http_auth_ldap_server_t *server,
        ngx_http_auth_ldap_loc_conf_t *conf) {

    LDAPURLDesc *ludpp = server->ludpp;
    int rc;
    LDAP *ld;
    LDAPMessage *searchResult;
    char *dn;
    u_char *p, *filter;
    ngx_http_complex_value_t *value;
    ngx_uint_t i;
    struct berval bvalue;
    ngx_flag_t pass = NGX_CONF_UNSET;
    struct timeval timeOut = { 10, 0 };

    if (server->ludpp == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: URL: %s", server->url.data);

    rc = ldap_initialize(&ld, (const char*) server->url.data);
    if (rc != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "LDAP: Session initializing failed: %d, %s, (%s)", rc,
            ldap_err2string(rc), (const char*) server->url.data);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: Session initialized", NULL);

    /// Bind to the server
    rc = ldap_simple_bind_s(ld, (const char *) server->bind_dn.data, (const char *) server->bind_dn_passwd.data);
    if (rc != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "LDAP [%s]: ldap_simple_bind_s error: %d, %s", server->url.data, rc,
            ldap_err2string(rc));
        ldap_unbind_s(ld);
        // Do not throw 500 in case connection failure, multiple servers might be used for failover scenario
        return 0;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: Bind successful", NULL);

    /// Create filter for search users by uid
    filter = ngx_pcalloc(
        r->pool,
        (ludpp->lud_filter != NULL ? ngx_strlen(ludpp->lud_filter) : ngx_strlen("(objectClass=*)")) + ngx_strlen("(&(=))")  + ngx_strlen(ludpp->lud_attrs[0])
               + r->headers_in.user.len + 1);

    p = ngx_sprintf(filter, "(&%s(%s=%V))", ludpp->lud_filter != NULL ? ludpp->lud_filter : "(objectClass=*)", ludpp->lud_attrs[0], &r->headers_in.user);
    *p = 0;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: filter %s", (const char*) filter);

    /// Search the directory
    rc = ldap_search_ext_s(ld, ludpp->lud_dn, ludpp->lud_scope, (const char*) filter, NULL, 0, NULL, NULL, &timeOut, 0,
        &searchResult);

    if (rc != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "LDAP: ldap_search_ext_s: %d, %s", rc, ldap_err2string(rc));
        ldap_msgfree(searchResult);
        ldap_unbind_s(ld);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ldap_count_entries(ld, searchResult) > 0) {
    dn = ldap_get_dn(ld, searchResult);
        if (dn != NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: result DN %s", dn);

            /// Check require user
            if (server->require_user != NULL) {
                value = server->require_user->elts;
                for (i = 0; i < server->require_user->nelts; i++) {
                    ngx_str_t val;
                    if (ngx_http_complex_value(r, &value[i], &val) != NGX_OK) {
                        ldap_memfree(dn);
                        ldap_msgfree(searchResult);
                        ldap_unbind_s(ld);
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }

                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: compare with: %V", &val);
                    if (ngx_strncmp(val.data, dn, val.len) == 0) {
                        pass = 1;
                        if (server->satisfy_all == 0) {
                            break;
                        }
                    } else {
                        if (server->satisfy_all == 1) {
                            ldap_memfree(dn);
                            ldap_msgfree(searchResult);
                            ldap_unbind_s(ld);
                            return 0;
                        }
                    }
                }
            }

            /// Check require group
            if (server->require_group != NULL) {
                if (server->group_attribute_dn == 1) {
                    bvalue.bv_val = dn;
                    bvalue.bv_len = ngx_strlen(dn);
                } else {
                    bvalue.bv_val = (char*) r->headers_in.user.data;
                    bvalue.bv_len = r->headers_in.user.len;
                }

                value = server->require_group->elts;

                for (i = 0; i < server->require_group->nelts; i++) {
                    ngx_str_t val;
                    if (ngx_http_complex_value(r, &value[i], &val) != NGX_OK) {
                        ldap_memfree(dn);
                        ldap_msgfree(searchResult);
                        ldap_unbind_s(ld);
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }

                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: group compare with: %V", &val);

                    rc = ldap_compare_ext_s(ld, (const char*) val.data, (const char*) server->group_attribute.data,
                        &bvalue, NULL, NULL);

                    /*if (rc != LDAP_COMPARE_TRUE && rc != LDAP_COMPARE_FALSE && rc != LDAP_NO_SUCH_ATTRIBUTE ) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "LDAP: ldap_search_ext_s: %d, %s", rc,
                            ldap_err2string(rc));
                    ldap_memfree(dn);
                    ldap_msgfree(searchResult);
                    ldap_unbind_s(ld);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                    }*/

                    if (rc == LDAP_COMPARE_TRUE) {
                        pass = 1;
                        if (server->satisfy_all == 0) {
                            break;
                        }
                    } else {
                        if (server->satisfy_all == 1) {
                            pass = 0;
                            break;
                        }
                    }
                }
            }

            /// Check valid user
            if ( pass != 0 || (server->require_valid_user == 1 && server->satisfy_all == 0 && pass == 0)) {
                /// Bind user to the server
                rc = ldap_simple_bind_s(ld, dn, (const char *) r->headers_in.passwd.data);
                if (rc != LDAP_SUCCESS) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "LDAP: ldap_simple_bind_s error: %d, %s", rc,
                        ldap_err2string(rc));
                    pass = 0;
                } else {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: User bind successful", NULL);
                    if (server->require_valid_user == 1) pass = 1;
                }
            }

        }
        ldap_memfree(dn);
    }

    ldap_msgfree(searchResult);
    ldap_unbind_s(ld);

    return pass;
}

/**
 * Respond with forbidden and add correct headers
 */
static ngx_int_t ngx_http_auth_ldap_set_realm(ngx_http_request_t *r, ngx_str_t *realm) {
    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->key.len = sizeof("WWW-Authenticate") - 1;
    r->headers_out.www_authenticate->key.data = (u_char *) "WWW-Authenticate";
    r->headers_out.www_authenticate->value = *realm;

    return NGX_HTTP_UNAUTHORIZED;
}

/**
 * Init module and add ldap auth handler to NGX_HTTP_ACCESS_PHASE
 */
static ngx_int_t ngx_http_auth_ldap_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_ldap_handler;
    return NGX_OK;
}
