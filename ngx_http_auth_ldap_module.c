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

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <ldap.h>
#include <openssl/opensslv.h>

// used for manual warnings
#define XSTR(x) STR(x)
#define STR(x) #x
// make sure manual warnings don't get escalated to errors
#ifdef __clang__
#pragma clang diagnostic warning "-W#warnings"
#else
#ifdef __GNUC__
#if GNUC > 4
#pragma GCC diagnostic warning "-Wcpp"
#endif
#endif
#endif
// TODO: do the same stuff for MSVC and/or other compilers


#ifndef LDAP_PROTO_EXT
/* Some OpenLDAP headers are accidentally missing ldap_init_fd() etc. */

#define LDAP_PROTO_TCP 1 /* ldap://  */
#define LDAP_PROTO_UDP 2 /* reserved */
#define LDAP_PROTO_IPC 3 /* ldapi:// */
#define LDAP_PROTO_EXT 4 /* user-defined socket/sockbuf */

extern int ldap_init_fd(ber_socket_t fd, int proto, const char *url, LDAP **ld);
#endif

#define OUTCOME_ERROR          -1 /* Some error occured in the process */
#define OUTCOME_DENY            0
#define OUTCOME_ALLOW           1
#define OUTCOME_CACHED_DENY     2 /* Cached results */
#define OUTCOME_CACHED_ALLOW    3
#define OUTCOME_UNCERTAIN       4 /* Not yet decided */

#define NGX_HTTP_AUTH_LDAP_MAX_SERVERS_SIZE 7


typedef struct {
    LDAPURLDesc *ludpp;
    ngx_str_t url;
    ngx_url_t parsed_url;
    ngx_str_t alias;

    ngx_str_t bind_dn;
    ngx_str_t bind_dn_passwd;

    ngx_str_t group_attribute;
    ngx_flag_t group_attribute_dn;

    ngx_flag_t ssl_check_cert;
    ngx_str_t ssl_ca_dir;
    ngx_str_t ssl_ca_file;

    ngx_array_t *require_group;     /* array of ngx_http_complex_value_t */
    ngx_array_t *require_user;      /* array of ngx_http_complex_value_t */
    ngx_flag_t require_valid_user;
    ngx_http_complex_value_t require_valid_user_dn;
    ngx_flag_t satisfy_all;
    ngx_flag_t referral;

    ngx_uint_t connections;
    ngx_uint_t max_down_retries;
    ngx_uint_t max_down_retries_count;
    ngx_msec_t connect_timeout;
    ngx_msec_t reconnect_timeout;
    ngx_msec_t bind_timeout;
    ngx_msec_t request_timeout;
    ngx_queue_t free_connections;
    ngx_queue_t waiting_requests;
} ngx_http_auth_ldap_server_t;

typedef struct {
    ngx_array_t *servers;        /* array of ngx_http_auth_ldap_server_t */
    ngx_flag_t cache_enabled;
    ngx_msec_t cache_expiration_time;
    size_t cache_size;
    ngx_int_t servers_size;
#if (NGX_OPENSSL)
    ngx_ssl_t ssl;
#endif
} ngx_http_auth_ldap_main_conf_t;

typedef struct {
    ngx_str_t realm;
    ngx_array_t *servers;       /* array of ngx_http_auth_ldap_server_t* */
} ngx_http_auth_ldap_loc_conf_t;

typedef struct {
    uint32_t small_hash;     /* murmur2 hash of username ^ &server       */
    uint32_t outcome;        /* OUTCOME_DENY or OUTCOME_ALLOW            */
    ngx_msec_t time;         /* ngx_current_msec when created            */
    u_char big_hash[16];     /* md5 hash of (username, server, password) */
} ngx_http_auth_ldap_cache_elt_t;

typedef struct {
    ngx_http_auth_ldap_cache_elt_t *buckets;
    ngx_uint_t num_buckets;
    ngx_uint_t elts_per_bucket;
    ngx_msec_t expiration_time;
} ngx_http_auth_ldap_cache_t;

typedef enum {
    PHASE_START,
    PHASE_SEARCH,
    PHASE_CHECK_USER,
    PHASE_CHECK_GROUP,
    PHASE_CHECK_BIND,
    PHASE_REBIND,
    PHASE_NEXT
} ngx_http_auth_ldap_request_phase_t;

typedef struct {
    ngx_http_request_t *r;
    ngx_uint_t server_index;
    ngx_http_auth_ldap_server_t *server;
    ngx_http_auth_ldap_request_phase_t phase;
    unsigned int iteration;
    int outcome;

    struct ngx_http_auth_ldap_connection *c;
    ngx_queue_t queue;
    int replied;
    int error_code;
    ngx_str_t error_msg;
    ngx_str_t dn;
    ngx_str_t user_dn;
    ngx_str_t group_dn;

    ngx_http_auth_ldap_cache_elt_t *cache_bucket;
    u_char cache_big_hash[16];
    uint32_t cache_small_hash;
} ngx_http_auth_ldap_ctx_t;

typedef enum {
    STATE_DISCONNECTED,
    STATE_INITIAL_BINDING,
    STATE_CONNECTING,
    STATE_READY,
    STATE_BINDING,
    STATE_SEARCHING,
    STATE_COMPARING
} ngx_http_auth_ldap_connection_state_t;

typedef struct ngx_http_auth_ldap_connection {
    ngx_log_t *log;
    ngx_http_auth_ldap_server_t *server;
    ngx_peer_connection_t conn;
    ngx_event_t reconnect_event;

#if (NGX_OPENSSL)
    ngx_pool_t *pool;
    ngx_ssl_t *ssl;
#endif

    ngx_queue_t queue;
    ngx_http_auth_ldap_ctx_t *rctx;

    LDAP* ld;
    ngx_http_auth_ldap_connection_state_t state;
    int msgid;
} ngx_http_auth_ldap_connection_t;

static char * ngx_http_auth_ldap_ldap_server_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_auth_ldap_ldap_server(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
static char * ngx_http_auth_ldap(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_auth_ldap_servers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_auth_ldap_parse_url(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static char * ngx_http_auth_ldap_parse_require(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static char * ngx_http_auth_ldap_parse_satisfy(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static char * ngx_http_auth_ldap_parse_referral(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static void * ngx_http_auth_ldap_create_main_conf(ngx_conf_t *cf);
static char * ngx_http_auth_ldap_init_main_conf(ngx_conf_t *cf, void *parent);
static void * ngx_http_auth_ldap_create_loc_conf(ngx_conf_t *);
static char * ngx_http_auth_ldap_merge_loc_conf(ngx_conf_t *, void *, void *);
static ngx_int_t ngx_http_auth_ldap_init_worker(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_auth_ldap_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_ldap_init_cache(ngx_cycle_t *cycle);
static void ngx_http_auth_ldap_close_connection(ngx_http_auth_ldap_connection_t *c);
static void ngx_http_auth_ldap_read_handler(ngx_event_t *rev);
static void ngx_http_auth_ldap_reconnect_handler(ngx_event_t *);
static ngx_int_t ngx_http_auth_ldap_init_connections(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_auth_ldap_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_ldap_authenticate(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx,
        ngx_http_auth_ldap_loc_conf_t *conf);
static ngx_int_t ngx_http_auth_ldap_search(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static ngx_int_t ngx_http_auth_ldap_check_user(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static ngx_int_t ngx_http_auth_ldap_check_group(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static ngx_int_t ngx_http_auth_ldap_check_bind(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static ngx_int_t ngx_http_auth_ldap_recover_bind(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
#if (NGX_OPENSSL)
static ngx_int_t ngx_http_auth_ldap_restore_handlers(ngx_connection_t *conn);
#endif

ngx_http_auth_ldap_cache_t ngx_http_auth_ldap_cache;

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
        ngx_string("auth_ldap_cache_enabled"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_auth_ldap_main_conf_t, cache_enabled),
        NULL
    },
    {
        ngx_string("auth_ldap_cache_expiration_time"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_auth_ldap_main_conf_t, cache_expiration_time),
        NULL
    },
    {
        ngx_string("auth_ldap_cache_size"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_auth_ldap_main_conf_t, cache_size),
        NULL
    },
    {
        ngx_string("auth_ldap_servers_size"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_auth_ldap_main_conf_t, servers_size),
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
        ngx_http_auth_ldap_servers,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_auth_ldap_module_ctx = {
    NULL,                                /* preconfiguration */
    ngx_http_auth_ldap_init,             /* postconfiguration */
    ngx_http_auth_ldap_create_main_conf, /* create main configuration */
    ngx_http_auth_ldap_init_main_conf,   /* init main configuration */
    NULL,                                /* create server configuration */
    NULL,                                /* merge server configuration */
    ngx_http_auth_ldap_create_loc_conf,  /* create location configuration */
    ngx_http_auth_ldap_merge_loc_conf    /* merge location configuration */
};

ngx_module_t ngx_http_auth_ldap_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_ldap_module_ctx,      /* module context */
    ngx_http_auth_ldap_commands,         /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    ngx_http_auth_ldap_init_worker,      /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};


/*** Configuration and initialization ***/

/**
 * Reads ldap_server block and sets ngx_http_auth_ldap_ldap_server as a handler of each conf value
 */
static char *
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
    } else if (ngx_strcmp(value[0].data, "group_attribute_is_dn") == 0 && ngx_strcmp(value[1].data, "on") == 0) {
        server->group_attribute_dn = 1;
    } else if (ngx_strcmp(value[0].data, "require") == 0) {
        return ngx_http_auth_ldap_parse_require(cf, server);
    } else if (ngx_strcmp(value[0].data, "satisfy") == 0) {
        return ngx_http_auth_ldap_parse_satisfy(cf, server);
    } else if (ngx_strcmp(value[0].data, "referral") == 0) {
        return ngx_http_auth_ldap_parse_referral(cf, server);
    } else if (ngx_strcmp(value[0].data, "max_down_retries") == 0) {
        i = ngx_atoi(value[1].data, value[1].len);
        if (i == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: 'max_down_retries' value must be an integer: using default of 0");
            i = 0;
        }
        server->max_down_retries = i;
    } else if (ngx_strcmp(value[0].data, "connections") == 0) {
        i = ngx_atoi(value[1].data, value[1].len);
        if (i == NGX_ERROR || i == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "http_auth_ldap: 'connections' value has to be a number greater than 0");
            return NGX_CONF_ERROR;
        }
        server->connections = i;
    } else if (ngx_strcmp(value[0].data, "ssl_check_cert") == 0  && ngx_strcmp(value[1].data, "on") == 0) {
      #if OPENSSL_VERSION_NUMBER >= 0x10002000
      server->ssl_check_cert = 1;
      #else
      #if GNUC > 4
      #warning "http_auth_ldap: Compiling with OpenSSL < 1.0.2, certificate verification will be unavailable. OPENSSL_VERSION_NUMBER == " XSTR(OPENSSL_VERSION_NUMBER)
      #endif
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
        "http_auth_ldap: 'ssl_cert_check': cannot verify remote certificate's domain name because "
        "your version of OpenSSL is too old. "
        "Please install OpenSSL >= 1.02 and recompile nginx.");
      #endif
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
    }

    rv = NGX_CONF_OK;

    return rv;
}

/**
 * Parse auth_ldap directive
 */
static char *
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
static char *
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

/**
 * Create main config which will store ldap_servers array
 */
static void *
ngx_http_auth_ldap_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_auth_ldap_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_ldap_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->cache_enabled = NGX_CONF_UNSET;
    conf->cache_expiration_time = NGX_CONF_UNSET_MSEC;
    conf->cache_size = NGX_CONF_UNSET_SIZE;
    conf->servers_size = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_auth_ldap_init_main_conf(ngx_conf_t *cf, void *parent)
{
    ngx_http_auth_ldap_main_conf_t *conf = parent;

    if (conf->cache_enabled == NGX_CONF_UNSET) {
        conf->cache_enabled = 0;
    }
    if (conf->cache_enabled == 0) {
        return NGX_CONF_OK;
    }

    if (conf->cache_size == NGX_CONF_UNSET_SIZE) {
        conf->cache_size = 100;
    }
    if (conf->cache_size < 100) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "http_auth_ldap: auth_ldap_cache_size cannot be smaller than 100 entries.");
        return NGX_CONF_ERROR;
    }

    if (conf->cache_expiration_time == NGX_CONF_UNSET_MSEC) {
        conf->cache_expiration_time = 10000;
    }
    if (conf->cache_expiration_time < 1000) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "http_auth_ldap: auth_ldap_cache_expiration_time cannot be smaller than 1000 ms.");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/**
 * Create location conf
 */
static void *
ngx_http_auth_ldap_create_loc_conf(ngx_conf_t *cf)
{
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
ngx_http_auth_ldap_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_ldap_loc_conf_t *prev = parent;
    ngx_http_auth_ldap_loc_conf_t *conf = child;

    if (conf->realm.data == NULL) {
        conf->realm = prev->realm;
    }
    ngx_conf_merge_ptr_value(conf->servers, prev->servers, NULL);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_auth_ldap_init_worker(ngx_cycle_t *cycle)
{
    ngx_int_t rc;

    if (ngx_process != NGX_PROCESS_SINGLE && ngx_process != NGX_PROCESS_WORKER) {
        return NGX_OK;
    }

    rc = ngx_http_auth_ldap_init_cache(cycle);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_auth_ldap_init_connections(cycle);
    if (rc != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}

/**
 * Init module and add ldap auth handler to NGX_HTTP_ACCESS_PHASE
 */
static ngx_int_t
ngx_http_auth_ldap_init(ngx_conf_t *cf)
{
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


/*** Authentication cache ***/

static ngx_int_t
ngx_http_auth_ldap_init_cache(ngx_cycle_t *cycle)
{
    ngx_http_auth_ldap_main_conf_t *conf;
    ngx_uint_t want, count, i;
    ngx_http_auth_ldap_cache_t *cache;
    static const uint16_t primes[] = {
        13, 53, 101, 151, 199, 263, 317, 383, 443, 503,
        577, 641, 701, 769, 839, 911, 983, 1049, 1109
    };

    conf = (ngx_http_auth_ldap_main_conf_t *) ngx_http_cycle_get_module_main_conf(cycle, ngx_http_auth_ldap_module);
    if (conf == NULL || !conf->cache_enabled) {
        return NGX_OK;
    }

    want = (conf->cache_size + 7) / 8;
    count = 0;
    for (i = 0; i < sizeof(primes)/sizeof(primes[0]); i++) {
        count = primes[i];
        if (count >= want) {
            break;
        }
    }

    cache = &ngx_http_auth_ldap_cache;
    cache->expiration_time = conf->cache_expiration_time;
    cache->num_buckets = count;
    cache->elts_per_bucket = 8;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "http_auth_ldap: Allocating %ud bytes of LDAP cache.",
        cache->num_buckets * cache->elts_per_bucket * sizeof(ngx_http_auth_ldap_cache_elt_t));

    cache->buckets = (ngx_http_auth_ldap_cache_elt_t *) ngx_calloc(count * 8 * sizeof(ngx_http_auth_ldap_cache_elt_t), cycle->log);
    if (cache->buckets == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "http_auth_ldap: Unable to allocate memory for LDAP cache.");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_ldap_check_cache(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx,
    ngx_http_auth_ldap_cache_t *cache, ngx_http_auth_ldap_server_t *server)
{
    ngx_http_auth_ldap_cache_elt_t *elt;
    ngx_md5_t md5ctx;
    ngx_msec_t time_limit;
    ngx_uint_t i;

    ctx->cache_small_hash = ngx_murmur_hash2(r->headers_in.user.data, r->headers_in.user.len) ^ (uint32_t) (ngx_uint_t) server;

    ngx_md5_init(&md5ctx);
    ngx_md5_update(&md5ctx, r->headers_in.user.data, r->headers_in.user.len);
    ngx_md5_update(&md5ctx, server, offsetof(ngx_http_auth_ldap_server_t, free_connections));
    ngx_md5_update(&md5ctx, r->headers_in.passwd.data, r->headers_in.passwd.len);
    ngx_md5_final(ctx->cache_big_hash, &md5ctx);

    ctx->cache_bucket = &cache->buckets[ctx->cache_small_hash % cache->num_buckets];

    elt = ctx->cache_bucket;
    time_limit = ngx_current_msec - cache->expiration_time;
    for (i = 0; i < cache->elts_per_bucket; i++, elt++) {
        if (elt->small_hash == ctx->cache_small_hash &&
                elt->time > time_limit &&
                memcmp(elt->big_hash, ctx->cache_big_hash, 16) == 0) {
            return elt->outcome;
        }
    }

    return -1;
}

static void
ngx_http_auth_ldap_update_cache(ngx_http_auth_ldap_ctx_t *ctx,
        ngx_http_auth_ldap_cache_t *cache, ngx_flag_t outcome)
{
    ngx_http_auth_ldap_cache_elt_t *elt, *oldest_elt;
    ngx_uint_t i;

    elt = ctx->cache_bucket;
    oldest_elt = elt;
    for (i = 1; i < cache->elts_per_bucket; i++, elt++) {
        if (elt->time < oldest_elt->time) {
            oldest_elt = elt;
        }
    }

    oldest_elt->time = ngx_current_msec;
    oldest_elt->outcome = outcome;
    oldest_elt->small_hash = ctx->cache_small_hash;
    ngx_memcpy(oldest_elt->big_hash, ctx->cache_big_hash, 16);
}


/*** OpenLDAP SockBuf implementation over nginx socket functions ***/

static int
ngx_http_auth_ldap_sb_setup(Sockbuf_IO_Desc *sbiod, void *arg)
{
    sbiod->sbiod_pvt = arg;
    return 0;
}

static int
ngx_http_auth_ldap_sb_remove(Sockbuf_IO_Desc *sbiod)
{
    ngx_http_auth_ldap_connection_t *c = (ngx_http_auth_ldap_connection_t *)sbiod->sbiod_pvt;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_auth_ldap_sb_remove()");
    (void)c; /* 'c' would be left unused on debug builds */

    sbiod->sbiod_pvt = NULL;
    return 0;
}

static int
ngx_http_auth_ldap_sb_close(Sockbuf_IO_Desc *sbiod)
{
    ngx_http_auth_ldap_connection_t *c = (ngx_http_auth_ldap_connection_t *)sbiod->sbiod_pvt;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_auth_ldap_sb_close()");

    if (!c->conn.connection->read->error && !c->conn.connection->read->eof) {
        if (ngx_shutdown_socket(c->conn.connection->fd, SHUT_RDWR) == -1) {
            ngx_connection_error(c->conn.connection, ngx_socket_errno, ngx_shutdown_socket_n " failed");
            ngx_http_auth_ldap_close_connection(c);
            return -1;
        }
    }

    return 0;
}

static int
ngx_http_auth_ldap_sb_ctrl(Sockbuf_IO_Desc *sbiod, int opt, void *arg)
{
    ngx_http_auth_ldap_connection_t *c = (ngx_http_auth_ldap_connection_t *)sbiod->sbiod_pvt;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_auth_ldap_sb_ctrl(opt=%d)", opt);

    switch (opt) {
        case LBER_SB_OPT_DATA_READY:
            if (c->conn.connection->read->ready) {
                return 1;
            }
            return 0;
    }

    return 0;
}

static ber_slen_t
ngx_http_auth_ldap_sb_read(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
    ngx_http_auth_ldap_connection_t *c = (ngx_http_auth_ldap_connection_t *)sbiod->sbiod_pvt;
    ber_slen_t ret;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_auth_ldap_sb_read(len=%d)", len);

    ret = c->conn.connection->recv(c->conn.connection, buf, len);
    if (ret < 0) {
        errno = (ret == NGX_AGAIN) ? NGX_EAGAIN : NGX_ECONNRESET;
        return -1;
    }

    return ret;
}

static ber_slen_t
ngx_http_auth_ldap_sb_write(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
    ngx_http_auth_ldap_connection_t *c = (ngx_http_auth_ldap_connection_t *)sbiod->sbiod_pvt;
    ber_slen_t ret;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_auth_ldap_sb_write(len=%d)", len);

    ret = c->conn.connection->send(c->conn.connection, buf, len);
    if (ret < 0) {
        errno = (ret == NGX_AGAIN) ? NGX_EAGAIN : NGX_ECONNRESET;
        return 0;
    }

    return ret;
}

static Sockbuf_IO ngx_http_auth_ldap_sbio =
{
    ngx_http_auth_ldap_sb_setup,
    ngx_http_auth_ldap_sb_remove,
    ngx_http_auth_ldap_sb_ctrl,
    ngx_http_auth_ldap_sb_read,
    ngx_http_auth_ldap_sb_write,
    ngx_http_auth_ldap_sb_close
};


/*** Asynchronous LDAP connection handling ***/

static void
ngx_http_auth_ldap_close_connection(ngx_http_auth_ldap_connection_t *c)
{
    ngx_queue_t *q;

    if (c->ld) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Unbinding from the server \"%V\")",
            &c->server->url);
        ldap_unbind_ext(c->ld, NULL, NULL);
        /* Unbind is always synchronous, even though the function name does not end with an '_s'. */
        c->ld = NULL;
    }

    if (c->conn.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Closing connection (fd=%d)",
            c->conn.connection->fd);

#if (NGX_OPENSSL)
        if (c->conn.connection->ssl) {
            c->conn.connection->ssl->no_wait_shutdown = 1;
            (void) ngx_ssl_shutdown(c->conn.connection);
        }
#endif

        ngx_close_connection(c->conn.connection);
        c->conn.connection = NULL;
    }

    q = ngx_queue_head(&c->server->free_connections);
    while (q != ngx_queue_sentinel(&c->server->free_connections)) {
        if (q == &c->queue) {
            ngx_queue_remove(q);
            break;
        }
        q = ngx_queue_next(q);
    }

    c->rctx = NULL;
    if (c->state != STATE_DISCONNECTED) {
        c->state = STATE_DISCONNECTED;
        ngx_add_timer(&c->reconnect_event, c->server->reconnect_timeout);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Connection scheduled for reconnection in %d ms", c->server->reconnect_timeout);
    }
}

static void
ngx_http_auth_ldap_wake_request(ngx_http_request_t *r)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Waking authentication request \"%V\"",
        &r->request_line);
    ngx_http_core_run_phases(r);
}

static int
ngx_http_auth_ldap_get_connection(ngx_http_auth_ldap_ctx_t *ctx)
{
    ngx_http_auth_ldap_server_t *server;
    ngx_queue_t *q;
    ngx_http_auth_ldap_connection_t *c;

    /*
     * If we already have a connection, just say we got them one.
     */
    if (ctx->c != NULL)
        return 1;

    server = ctx->server;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->r->connection->log, 0, "http_auth_ldap: Wants a free connection to \"%V\"",
        &server->alias);

    if (!ngx_queue_empty(&server->free_connections)) {
        q = ngx_queue_last(&server->free_connections);
        ngx_queue_remove(q);
        c = ngx_queue_data(q, ngx_http_auth_ldap_connection_t, queue);
        c->rctx = ctx;
        ctx->c = c;
        ctx->replied = 0;
        return 1;
    }

    q = ngx_queue_next(&server->waiting_requests);
    while (q != ngx_queue_sentinel(&server->waiting_requests)) {
        if (q == &ctx->queue) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->r->connection->log, 0, "http_auth_ldap: Tried to insert a same request");
            return 0;
        }
        q = ngx_queue_next(q);
    }
    ngx_queue_insert_head(&server->waiting_requests, &ctx->queue);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ctx->r->connection->log, 0, "http_auth_ldap: No connection available at the moment, waiting...");
    return 0;
}

static void
ngx_http_auth_ldap_return_connection(ngx_http_auth_ldap_connection_t *c)
{
    ngx_queue_t *q;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Marking the connection to \"%V\" as free",
        &c->server->alias);

    if (c->rctx != NULL) {
        c->rctx->c = NULL;
        c->rctx = NULL;
        c->msgid = -1;
        c->state = STATE_READY;
    }

    ngx_queue_insert_head(&c->server->free_connections, &c->queue);
    if (!ngx_queue_empty(&c->server->waiting_requests)) {
        q = ngx_queue_last(&c->server->waiting_requests);
        ngx_queue_remove(q);
        ngx_http_auth_ldap_wake_request((ngx_queue_data(q, ngx_http_auth_ldap_ctx_t, queue))->r);
    }
}

static void
ngx_http_auth_ldap_reply_connection(ngx_http_auth_ldap_connection_t *c, int error_code, char* error_msg)
{
    ngx_http_auth_ldap_ctx_t *ctx = c->rctx;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: LDAP request to \"%V\" has finished",
        &c->server->alias);

    ctx->replied = 1;
    ctx->error_code = error_code;
    if (error_msg) {
        ctx->error_msg.len = ngx_strlen(error_msg);
        ctx->error_msg.data = ngx_palloc(ctx->r->pool, ctx->error_msg.len);
        ngx_memcpy(ctx->error_msg.data, error_msg, ctx->error_msg.len);
    } else {
        ctx->error_msg.len = 0;
        ctx->error_msg.data = NULL;
    }

    ngx_http_auth_ldap_wake_request(ctx->r);
}

static void
ngx_http_auth_ldap_dummy_write_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "http_auth_ldap: Dummy write handler");

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_auth_ldap_close_connection(((ngx_connection_t *) wev->data)->data);
    }
}


#if (NGX_OPENSSL)
/* Make sure the event handlers are activated. */
static ngx_int_t
ngx_http_auth_ldap_restore_handlers(ngx_connection_t *conn)
{
    ngx_int_t rc;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, conn->log, 0, "http_auth_ldap: Restoring event handlers. read=%d write=%d", conn->read->active, conn->write->active);

    if (!conn->read->active) {
        rc = ngx_add_event(conn->read, NGX_READ_EVENT, 0);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    if (!conn->write->active &&
        (conn->write->handler != ngx_http_auth_ldap_dummy_write_handler)) {
        rc = ngx_add_event(conn->write, NGX_WRITE_EVENT, 0);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}
#endif

static void
ngx_http_auth_ldap_connection_established(ngx_http_auth_ldap_connection_t *c)
{
    ngx_connection_t *conn;
    Sockbuf *sb;
    ngx_int_t rc;
    struct berval cred;

    conn = c->conn.connection;
    ngx_del_timer(conn->read);
    conn->write->handler = ngx_http_auth_ldap_dummy_write_handler;


    /* Initialize OpenLDAP on the connection */

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Initializing connection using URL \"%V\"", &c->server->url);

    rc = ldap_init_fd(c->conn.connection->fd, LDAP_PROTO_EXT, (const char *) c->server->url.data, &c->ld);
    if (rc != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, c->log, errno, "http_auth_ldap: ldap_init_fd() failed (%d: %s)", rc, ldap_err2string(rc));
        ngx_http_auth_ldap_close_connection(c);
        return;
    }

    if (c->server->referral == 0) {
        rc = ldap_set_option(c->ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
        if (rc != LDAP_OPT_SUCCESS) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: ldap_set_option() failed (%d: %s)", rc, ldap_err2string(rc));
            ngx_http_auth_ldap_close_connection(c);
            return;
        }
    }

    rc = ldap_get_option(c->ld, LDAP_OPT_SOCKBUF, (void *) &sb);
    if (rc != LDAP_OPT_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: ldap_get_option() failed (%d: %s)", rc, ldap_err2string(rc));
        ngx_http_auth_ldap_close_connection(c);
        return;
    }

    ber_sockbuf_add_io(sb, &ngx_http_auth_ldap_sbio, LBER_SBIOD_LEVEL_PROVIDER, (void *) c);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Connection initialized");


    /* Perform initial bind to the server */

    cred.bv_val = (char *) c->server->bind_dn_passwd.data;
    cred.bv_len = c->server->bind_dn_passwd.len;
    rc = ldap_sasl_bind(c->ld, (const char *) c->server->bind_dn.data, LDAP_SASL_SIMPLE, &cred, NULL, NULL, &c->msgid);
    if (rc != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: ldap_sasl_bind() failed (%d: %s)",
            rc, ldap_err2string(rc));
        ngx_http_auth_ldap_close_connection(c);
        return;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: ldap_sasl_bind() -> msgid=%d", c->msgid);

    c->state = STATE_INITIAL_BINDING;
    ngx_add_timer(c->conn.connection->read, c->server->bind_timeout);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: bind_timeout=%d", c->server->bind_timeout);
}

#if (NGX_OPENSSL)
static void
ngx_http_auth_ldap_ssl_handshake_handler(ngx_connection_t *conn, ngx_flag_t validate)
{
    ngx_http_auth_ldap_connection_t *c;
    c = conn->data;

    if (conn->ssl->handshaked) {
        #if OPENSSL_VERSION_NUMBER >= 0x10002000
        if (validate) { // verify remote certificate if requested
          X509 *cert = SSL_get_peer_certificate(conn->ssl->connection);
          long chain_verified = SSL_get_verify_result(conn->ssl->connection);

          int addr_verified;
          char *hostname = c->server->ludpp->lud_host;
          addr_verified = X509_check_host(cert, hostname, 0, 0, 0);

          if (!addr_verified) { // domain not in cert? try IP
            size_t len; // get IP length
            if (conn->sockaddr->sa_family == 4) len = 4;
            else if (conn->sockaddr->sa_family == 6) len = 16;
            else { // very unlikely indeed
              ngx_http_auth_ldap_close_connection(c);
              return;
            }
            addr_verified = X509_check_ip(cert, (const unsigned char*)conn->sockaddr->sa_data, len, 0);
          }

          // Find anything fishy?
          if ( !(cert && addr_verified && chain_verified == X509_V_OK) ) {
            if (!addr_verified) {
              ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "http_auth_ldap: Remote side presented invalid SSL certificate: "
                "does not match address (neither server's domain nor IP in certificate's CN or SAN)");
                fprintf(stderr, "DEBUG: SSL cert domain mismatch\n"); fflush(stderr);
            } else {
              ngx_log_error(NGX_LOG_ERR, c->log, 0,
                "http_auth_ldap: Remote side presented invalid SSL certificate: error %l, %s",
                chain_verified, X509_verify_cert_error_string(chain_verified));
            }
            ngx_http_auth_ldap_close_connection(c);
            return;
          }
        }
        #endif

        // handshaked validation successful -- or not required in the first place
        conn->read->handler = &ngx_http_auth_ldap_read_handler;
        ngx_http_auth_ldap_restore_handlers(conn);
        ngx_http_auth_ldap_connection_established(c);
        return;
    }
    else { // handshake failed
      ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: SSL handshake failed");
      ngx_http_auth_ldap_close_connection(c);
    }
}

static void
ngx_http_auth_ldap_ssl_handshake_validating_handler(ngx_connection_t *conn)
{ ngx_http_auth_ldap_ssl_handshake_handler(conn, 1); }

static void
ngx_http_auth_ldap_ssl_handshake_non_validating_handler(ngx_connection_t *conn)
{ ngx_http_auth_ldap_ssl_handshake_handler(conn, 0); }

typedef void (*ngx_http_auth_ldap_ssl_callback)(ngx_connection_t *conn);

static void
ngx_http_auth_ldap_ssl_handshake(ngx_http_auth_ldap_connection_t *c)
{
    ngx_int_t rc;

    c->conn.connection->pool = c->pool;
    rc = ngx_ssl_create_connection(c->ssl, c->conn.connection, NGX_SSL_BUFFER | NGX_SSL_CLIENT);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: SSL initialization failed");
        ngx_http_auth_ldap_close_connection(c);
        return;
    }

    c->log->action = "SSL handshaking to LDAP server";
    ngx_connection_t *transport = c->conn.connection;

    ngx_http_auth_ldap_ssl_callback callback;
    if (c->server->ssl_check_cert) {
      // load CA certificates: custom ones if specified, default ones instead
      if (c->server->ssl_ca_file.data || c->server->ssl_ca_dir.data) {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
        int setcode = SSL_CTX_load_verify_locations(transport->ssl->session_ctx,
          (char*)(c->server->ssl_ca_file.data), (char*)(c->server->ssl_ca_dir.data));
#else
        int setcode = SSL_CTX_load_verify_locations(transport->ssl->connection->ctx,
          (char*)(c->server->ssl_ca_file.data), (char*)(c->server->ssl_ca_dir.data));
#endif
        if (setcode != 1) {
          unsigned long error_code = ERR_get_error();
          char *error_msg = ERR_error_string(error_code, NULL);
          ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "http_auth_ldap: SSL initialization failed. Could not set custom CA certificate location. "
            "Error: %lu, %s", error_code, error_msg);
        }
      }
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
      int setcode = SSL_CTX_set_default_verify_paths(transport->ssl->session_ctx);
#else
      int setcode = SSL_CTX_set_default_verify_paths(transport->ssl->connection->ctx);
#endif
      if (setcode != 1) {
        unsigned long error_code = ERR_get_error();
        char *error_msg = ERR_error_string(error_code, NULL);
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
          "http_auth_ldap: SSL initialization failed. Could not use default CA certificate location. "
          "Error: %lu, %s", error_code, error_msg);
      }

      // use validating version of next function
      callback = &ngx_http_auth_ldap_ssl_handshake_validating_handler;
    } else {
      // use non-validating version of next function
      callback = &ngx_http_auth_ldap_ssl_handshake_non_validating_handler;
    }

    rc = ngx_ssl_handshake(transport);
    if (rc == NGX_AGAIN) {
        transport->ssl->handler = callback;
        return;
    }

    (*callback)(transport);
    return;
}
#endif

static void
ngx_http_auth_ldap_connect_handler(ngx_event_t *wev)
{
    ngx_connection_t *conn;
    ngx_http_auth_ldap_connection_t *c;
    int keepalive;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "http_auth_ldap: Connect handler");

    conn = wev->data;
    c = conn->data;

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_auth_ldap_close_connection(c);
        return;
    }

    keepalive = 1;
    if (setsockopt(conn->fd, SOL_SOCKET, SO_KEEPALIVE, (const void *) &keepalive, sizeof(int)) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno, "http_auth_ldap: setsockopt(SO_KEEPALIVE) failed");
    }

#if (NGX_OPENSSL)
    if (ngx_strcmp(c->server->ludpp->lud_scheme, "ldaps") == 0) {
        ngx_http_auth_ldap_ssl_handshake(c);
        return;
    }
#endif

    ngx_http_auth_ldap_connection_established(c);
}

static void
ngx_http_auth_ldap_read_handler(ngx_event_t *rev)
{
    ngx_connection_t *conn;
    ngx_http_auth_ldap_connection_t *c;
    ngx_int_t rc;
    struct timeval timeout = {0, 0};
    LDAPMessage *result;
    int error_code;
    char *error_msg;
    char *dn;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http_auth_ldap: Read handler");

    conn = rev->data;
    c = conn->data;

    if (c->ld == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: Could not connect");
        ngx_http_auth_ldap_close_connection(c);
        return;
    }

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT, "http_auth_ldap: Request timed out (state=%d)", c->state);
        conn->timedout = 1;
        ngx_http_auth_ldap_close_connection(c);
        return;
    }

    c->log->action = "reading response from LDAP";

    for (;;) {
        rc = ldap_result(c->ld, LDAP_RES_ANY, 0, &timeout, &result);
        if (rc < 0) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: ldap_result() failed (%d: %s)",
                rc, ldap_err2string(rc));
            ngx_http_auth_ldap_close_connection(c);

            // if LDAP_SERVER_DOWN (usually timeouts or server disconnects)
            if (rc == LDAP_SERVER_DOWN && \
                c->server->max_down_retries_count < c->server->max_down_retries) { 
                /** 
                    update counter (this is always reset in 
                    ngx_http_auth_ldap_connect() for a successful ldap 
                    connection  
                **/
                c->server->max_down_retries_count++;
                ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: LDAP_SERVER_DOWN: retry count: %d",
                    c->server->max_down_retries_count);
                c->state = STATE_DISCONNECTED;
                // immediate reconnect synchronously, this schedules another
                // timer call to this read handler again
                ngx_http_auth_ldap_reconnect_handler(rev);
                return;
            } 

            return;
        }
        if (rc == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: ldap_result() -> rc=0");
            break;
        }
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: ldap_result() -> rc=%d, msgid=%d, msgtype=%d",
            rc, ldap_msgid(result), ldap_msgtype(result));

        if (ldap_msgid(result) != c->msgid) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Message with unknown ID received, ignoring.");
            ldap_msgfree(result);
            continue;
        }

        rc = ldap_parse_result(c->ld, result, &error_code, NULL, &error_msg, NULL, NULL, 0);
        if (rc == LDAP_NO_RESULTS_RETURNED) {
            error_code = LDAP_NO_RESULTS_RETURNED;
            error_msg = NULL;
        } else if (rc != LDAP_SUCCESS) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: ldap_parse_result() failed (%d: %s)",
                rc, ldap_err2string(rc));
            ldap_msgfree(result);
            ngx_http_auth_ldap_close_connection(c);
            return;
        }

        switch (c->state) {
            case STATE_INITIAL_BINDING:
                if (ldap_msgtype(result) != LDAP_RES_BIND) {
                    break;
                }
                ngx_del_timer(conn->read);
                if (error_code == LDAP_SUCCESS) {
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Initial bind successful");
                    c->state = STATE_READY;
                    ngx_http_auth_ldap_return_connection(c);
                } else {
                    ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: Initial bind failed (%d: %s [%s])",
                        error_code, ldap_err2string(error_code), error_msg ? error_msg : "-");
                    ldap_memfree(error_msg);
                    ldap_msgfree(result);
                    ngx_http_auth_ldap_close_connection(c);
                    return;
                }
                break;

            case STATE_BINDING:
                if (ldap_msgtype(result) != LDAP_RES_BIND) {
                    break;
                }
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Received bind response (%d: %s [%s])",
                    error_code, ldap_err2string(error_code), error_msg ? error_msg : "-");
                ngx_http_auth_ldap_reply_connection(c, error_code, error_msg);
                break;

            case STATE_SEARCHING:
                if (ldap_msgtype(result) == LDAP_RES_SEARCH_ENTRY) {
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Received a search entry");
                    if (c->rctx->dn.data == NULL) {
                        dn = ldap_get_dn(c->ld, result);
                        if (dn != NULL) {
                            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Found entry with DN \"%s\"", dn);
                            c->rctx->dn.len = ngx_strlen(dn);
                            c->rctx->dn.data = (u_char *) ngx_palloc(c->rctx->r->pool, c->rctx->dn.len + 1);
                            ngx_memcpy(c->rctx->dn.data, dn, c->rctx->dn.len + 1);
                            ldap_memfree(dn);
                        }
                    }
                } else if (ldap_msgtype(result) == LDAP_RES_SEARCH_RESULT) {
                    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Received search result (%d: %s [%s])",
                        error_code, ldap_err2string(error_code), error_msg ? error_msg : "-");
                    ngx_http_auth_ldap_reply_connection(c, error_code, error_msg);
                }
                break;

            case STATE_COMPARING:
                if (ldap_msgtype(result) != LDAP_RES_COMPARE) {
                    break;
                }
                ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Received comparison result (%d: %s [%s])",
                    error_code, ldap_err2string(error_code), error_msg ? error_msg : "-");
                ngx_http_auth_ldap_reply_connection(c, error_code, error_msg);
                break;

            default:
                break;
        }

        ldap_memfree(error_msg);
        ldap_msgfree(result);
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_http_auth_ldap_close_connection(c);
        return;
    }
}

static void
ngx_http_auth_ldap_connect(ngx_http_auth_ldap_connection_t *c)
{
    ngx_peer_connection_t *pconn;
    ngx_connection_t *conn;
    ngx_addr_t *addr;
    ngx_int_t rc;

    addr = &c->server->parsed_url.addrs[ngx_random() % c->server->parsed_url.naddrs];

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Connecting to LDAP server \"%V\".",
        &addr->name);

    pconn = &c->conn;
    pconn->sockaddr = addr->sockaddr;
    pconn->socklen = addr->socklen;
    pconn->name = &addr->name;
    pconn->get = ngx_event_get_peer;
    pconn->log = c->log;
    pconn->log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(pconn);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: ngx_event_connect_peer() -> %d.", rc);
    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: Unable to connect to LDAP server \"%V\".",
            &addr->name);
        ngx_add_timer(&c->reconnect_event, c->server->reconnect_timeout);
        return;
    }

    conn = pconn->connection;
    conn->data = c;
#if (NGX_OPENSSL)
    conn->pool = c->pool;
#endif
    conn->write->handler = ngx_http_auth_ldap_connect_handler;
    conn->read->handler = ngx_http_auth_ldap_read_handler;
    ngx_add_timer(conn->read, c->server->connect_timeout);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: connect_timeout=%d.", c->server->connect_timeout);

    c->server->max_down_retries_count = 0;   /* reset retries count */
    c->state = STATE_CONNECTING;
}

static void
ngx_http_auth_ldap_connection_cleanup(void *data)
{
    ngx_http_auth_ldap_close_connection((ngx_http_auth_ldap_connection_t *) data);
}

static void
ngx_http_auth_ldap_reconnect_handler(ngx_event_t *ev)
{
    ngx_connection_t *conn = ev->data;
    ngx_http_auth_ldap_connection_t *c = conn->data;
    ngx_http_auth_ldap_connect(c);
}

static ngx_int_t
ngx_http_auth_ldap_init_connections(ngx_cycle_t *cycle)
{
    ngx_http_auth_ldap_connection_t *c;
    ngx_http_auth_ldap_main_conf_t *halmcf;
    ngx_http_auth_ldap_server_t *server;
    ngx_pool_cleanup_t *cleanup;
    ngx_connection_t *dummy_conn;
    ngx_uint_t i, j;
    int option;

    halmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_auth_ldap_module);
    if (halmcf == NULL || halmcf->servers == NULL) {
	return NGX_OK;
    }

    option = LDAP_VERSION3;
    ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, &option);

    for (i = 0; i < halmcf->servers->nelts; i++) {
        server = &((ngx_http_auth_ldap_server_t *) halmcf->servers->elts)[i];
        ngx_queue_init(&server->free_connections);
        ngx_queue_init(&server->waiting_requests);
        if (server->connections <= 1) {
            server->connections = 1;
        }

        for (j = 0; j < server->connections; j++) {
            c = ngx_pcalloc(cycle->pool, sizeof(ngx_http_auth_ldap_connection_t));
            cleanup = ngx_pool_cleanup_add(cycle->pool, 0);
            dummy_conn = ngx_pcalloc(cycle->pool, sizeof(ngx_connection_t));
            if (c == NULL || cleanup == NULL || dummy_conn == NULL) {
                return NGX_ERROR;
            }

            cleanup->handler = &ngx_http_auth_ldap_connection_cleanup;
            cleanup->data = c;

            c->log = cycle->log;
            c->server = server;
            c->state = STATE_DISCONNECTED;

            /* Various debug logging around timer management assume that the field
               'data' in ngx_event_t is a pointer to ngx_connection_t, therefore we
               have a dummy such structure around so that it does not crash etc. */
            dummy_conn->data = c;
            c->reconnect_event.log = c->log;
            c->reconnect_event.data = dummy_conn;
            c->reconnect_event.handler = ngx_http_auth_ldap_reconnect_handler;

#if (NGX_OPENSSL)
            c->pool = cycle->pool;
            c->ssl = &halmcf->ssl;
#endif

            ngx_http_auth_ldap_connect(c);
        }
    }

    return NGX_OK;
}



/*** Per-request authentication processing ***/

/**
 * Respond with "403 Forbidden" and add correct headers
 */
static ngx_int_t
ngx_http_auth_ldap_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
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
 * LDAP Authentication handler
 */
static ngx_int_t
ngx_http_auth_ldap_handler(ngx_http_request_t *r)
{
    ngx_http_auth_ldap_loc_conf_t *alcf;
    ngx_http_auth_ldap_ctx_t *ctx;
    int rc;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_ldap_module);
    if (alcf->realm.len == 0) {
        return NGX_DECLINED;
    }

    if (alcf->servers == NULL || alcf->servers->nelts == 0) {
        /* No LDAP servers for the location. */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: \"auth_ldap\" requires "
                      "one or more \"auth_ldap_servers\" in the same location");
        return ngx_http_auth_ldap_set_realm(r, &alcf->realm);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_ldap_module);
    if (ctx == NULL) {
        rc = ngx_http_auth_basic_user(r);
        if (rc == NGX_DECLINED) {
            return ngx_http_auth_ldap_set_realm(r, &alcf->realm);
        }
        if (rc == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Username is \"%V\"",
            &r->headers_in.user);
        if (r->headers_in.passwd.len == 0)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Password is empty");
            return ngx_http_auth_ldap_set_realm(r, &alcf->realm);
        }

        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_ldap_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ctx->r = r;
        /* Other fields have been initialized to zero/NULL */
        ngx_http_set_ctx(r, ctx, ngx_http_auth_ldap_module);
    }

    return ngx_http_auth_ldap_authenticate(r, ctx, alcf);
}

/**
 * Iteratively handle all phases of the authentication process, might be called many times
 */
static ngx_int_t
ngx_http_auth_ldap_authenticate(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx,
        ngx_http_auth_ldap_loc_conf_t *conf)
{
    ngx_int_t rc;
    ngx_uint_t i;
    ngx_http_auth_ldap_server_t *s;

    if (r->connection->write->timedout) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: Authentication timed out");
        if (ctx->c != NULL) {
            ngx_http_auth_ldap_return_connection(ctx->c);
        }

        // Remove ctx from waiting_requests queue if it was added.
        if (ngx_queue_next(&ctx->queue)) {
            ngx_queue_remove(&ctx->queue);
        }

        return NGX_ERROR;
    }

    /*
     * If we are not starting up a request (ctx->phase != PHASE_START) and we actually already
     * sent a request (ctx->iteration > 0) and didn't receive a reply yet (!ctx->replied) we
     * ask to be called again at a later time when we hopefully have received a reply.
     *
     * It is quite possible that we reach this if while not having sent a request yet (ctx->iteration == 0) -
     * this happens when we are trying to get an LDAP connection but all of them are busy right now.
     */
    if (ctx->iteration > 0 && !ctx->replied && ctx->phase != PHASE_START) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: The LDAP operation did not finish yet");
        return NGX_AGAIN;
    }

    for (;;) {
        loop:
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Authentication loop (phase=%d, iteration=%d)",
            ctx->phase, ctx->iteration);

        switch (ctx->phase) {
            case PHASE_START:
                ctx->server = ((ngx_http_auth_ldap_server_t **) conf->servers->elts)[ctx->server_index];
                ctx->outcome = OUTCOME_UNCERTAIN;

                ngx_add_timer(r->connection->write, ctx->server->request_timeout);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: request_timeout=%d",ctx->server->request_timeout);


                /* Check cache if enabled */
                if (ngx_http_auth_ldap_cache.buckets != NULL) {
                    for (i = 0; i < conf->servers->nelts; i++) {
                        s = &((ngx_http_auth_ldap_server_t *) conf->servers->elts)[i];
                        rc = ngx_http_auth_ldap_check_cache(r, ctx, &ngx_http_auth_ldap_cache, s);
                        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Using cached outcome %d from server %d", rc, i);
                        if (rc == OUTCOME_DENY || rc == OUTCOME_ALLOW) {
                            ctx->outcome = (rc == OUTCOME_DENY ? OUTCOME_CACHED_DENY : OUTCOME_CACHED_ALLOW);
                            ctx->phase = PHASE_NEXT;
                            goto loop;
                        }
                    }
                }

                if (ctx->server->require_valid_user_dn.value.data != NULL) {
                    /* Construct user DN */
                    if (ngx_http_complex_value(r, &ctx->server->require_valid_user_dn, &ctx->user_dn) != NGX_OK) {
                        ngx_del_timer(r->connection->write);
                        return NGX_ERROR;
                    }
                    ctx->phase = PHASE_CHECK_USER;
                    break;
                }

                ctx->phase = PHASE_SEARCH;
                ctx->iteration = 0;
                break;

            case PHASE_SEARCH:
                /* Search the directory to retrieve full user DN */
                rc = ngx_http_auth_ldap_search(r, ctx);
                if (rc == NGX_AGAIN) {
                    /* LDAP operation in progress, wait for the results */
                    return NGX_AGAIN;
                }
                if (rc != NGX_OK) {
                    /* Search failed, try next server */
                    ctx->phase = PHASE_NEXT;
                    break;
                }

                /* User DN has been found, check user next */
                ctx->phase = PHASE_CHECK_USER;
                break;

            case PHASE_CHECK_USER:
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: User DN is \"%V\"",
                    &ctx->user_dn);

                if (ctx->server->require_user != NULL) {
                    rc = ngx_http_auth_ldap_check_user(r, ctx);
                    if (rc != NGX_OK) {
                        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Not ok", &ctx->user_dn);
                        /* User check failed, try next server */
                        ctx->phase = PHASE_NEXT;
                        break;
                    }
                }

                /* User not yet fully authenticated, check group next */
                if ((ctx->outcome == OUTCOME_UNCERTAIN) &&
                    (ctx->server->require_group != NULL)) {
                        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Moving to group check", &ctx->user_dn);
                        ctx->phase = PHASE_CHECK_GROUP;
                        ctx->iteration = 0;
                        break;
                }

                /* No groups to validate, try binding next */
                ctx->phase = PHASE_CHECK_BIND;
                ctx->iteration = 0;
                break;

            case PHASE_CHECK_GROUP:
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Checking group", &ctx->user_dn);
                rc = ngx_http_auth_ldap_check_group(r, ctx);
                if (rc == NGX_AGAIN) {
                    /* LDAP operation in progress, wait for the results */
                    return NGX_AGAIN;
                }
                if (rc != NGX_OK) {
                    /* Group check failed, try next server */
                    ctx->phase = PHASE_NEXT;
                    break;
                }

                /* Groups validated, try binding next */
                ctx->phase = PHASE_CHECK_BIND;
                ctx->iteration = 0;
                break;

            case PHASE_CHECK_BIND:
                if (ctx->outcome == OUTCOME_UNCERTAIN) {
                    /* If we're still uncertain when satisfy is 'any' and there
                     * is at least one require user/group rule, it means no
                     * rule has matched.
                     */
                    if ((ctx->server->satisfy_all == 0) && (
                            (ctx->server->require_user != NULL) ||
                            (ctx->server->require_group != NULL))){
                        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: no requirement satisfied");
                        ctx->outcome = OUTCOME_DENY;
                        ctx->phase = PHASE_NEXT;
                        /*rc = NGX_DECLINED;*/
                        break;
                    } else {
                        /* So far so good */
                        ctx->outcome = OUTCOME_ALLOW;
                    }
                }

                /* Initiate bind using the found DN and request password */
                rc = ngx_http_auth_ldap_check_bind(r, ctx);
                if (rc == NGX_AGAIN) {
                    /* LDAP operation in progress, wait for the result */
                    return NGX_AGAIN;
                }

                /* All steps done, finish the processing */
                ctx->phase = PHASE_REBIND;
                ctx->iteration = 0;
                break;

            case PHASE_REBIND:
                /* Initiate bind using the found DN and request password */
                rc = ngx_http_auth_ldap_recover_bind(r, ctx);
                if (rc == NGX_AGAIN) {
                    /* LDAP operation in progress, wait for the result */
                    return NGX_AGAIN;
                }

                /* All steps done, finish the processing */
                ctx->phase = PHASE_NEXT;
                break;

            case PHASE_NEXT:
                if (r->connection->write->timer_set) {
                    ngx_del_timer(r->connection->write);
                }

                if (ctx->c != NULL) {
                    ngx_http_auth_ldap_return_connection(ctx->c);
                }

                if (ngx_http_auth_ldap_cache.buckets != NULL &&
                    (ctx->outcome == OUTCOME_DENY || ctx->outcome == OUTCOME_ALLOW)) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Caching outcome %d", ctx->outcome);
                    ngx_http_auth_ldap_update_cache(ctx, &ngx_http_auth_ldap_cache, ctx->outcome);
                }

                if (ctx->outcome == OUTCOME_ALLOW || ctx->outcome == OUTCOME_CACHED_ALLOW) {
                    return NGX_OK;
                }

                ctx->server_index++;
                if (ctx->server_index >= conf->servers->nelts) {
                    return ngx_http_auth_ldap_set_realm(r, &conf->realm);
                }

                ctx->phase = PHASE_START;
                break;
        }
    }
}

static ngx_int_t
ngx_http_auth_ldap_search(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx)
{
    LDAPURLDesc *ludpp;
    u_char *filter;
    char *attrs[2];
    ngx_int_t rc;

    /* On the first call, initiate the LDAP search operation */
    if (ctx->iteration == 0) {
        if (!ngx_http_auth_ldap_get_connection(ctx)) {
            return NGX_AGAIN;
        }

        ludpp = ctx->server->ludpp;
        filter = ngx_pcalloc(
            r->pool,
            (ludpp->lud_filter != NULL ? ngx_strlen(ludpp->lud_filter) : ngx_strlen("(objectClass=*)")) +
            ngx_strlen("(&(=))") + ngx_strlen(ludpp->lud_attrs[0]) + r->headers_in.user.len + 1);
        ngx_sprintf(filter, "(&%s(%s=%V))%Z",
                ludpp->lud_filter != NULL ? ludpp->lud_filter : "(objectClass=*)",
                ludpp->lud_attrs[0], &r->headers_in.user);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Search filter is \"%s\"",
            (const char *) filter);

        attrs[0] = LDAP_NO_ATTRS;
        attrs[1] = NULL;

        rc = ldap_search_ext(ctx->c->ld, ludpp->lud_dn, ludpp->lud_scope, (const char *) filter, attrs, 0, NULL, NULL, NULL, 0, &ctx->c->msgid);
        if (rc != LDAP_SUCCESS) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: ldap_search_ext() failed (%d, %s)",
                rc, ldap_err2string(rc));
            ngx_http_auth_ldap_return_connection(ctx->c);
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: ldap_search_ext() -> msgid=%d",
            ctx->c->msgid);
        ctx->c->state = STATE_SEARCHING;
        ctx->iteration++;
        return NGX_AGAIN;
    }

    /* On the second call, handle the search results */
    if (ctx->error_code != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: ldap_search_ext() request failed (%d: %s)",
            ctx->error_code, ldap_err2string(ctx->error_code));
        return NGX_ERROR;
    }

    if (ctx->dn.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: Could not find user DN");
        return NGX_ERROR;
    } else {
        ctx->user_dn.len = ngx_strlen(ctx->dn.data);
        ctx->user_dn.data = (u_char *) ngx_palloc(ctx->r->pool, ctx->user_dn.len + 1);
        ngx_memcpy(ctx->user_dn.data, ctx->dn.data, ctx->user_dn.len + 1);
        ctx->dn.data = NULL;
        ctx->dn.len = 0;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_ldap_check_user(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx)
{
    ngx_http_complex_value_t *values;
    ngx_uint_t i;

    values = ctx->server->require_user->elts;
    for (i = 0; i < ctx->server->require_user->nelts; i++) {
        ngx_str_t val;
        if (ngx_http_complex_value(r, &values[i], &val) != NGX_OK) {
            ctx->outcome = OUTCOME_ERROR;
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Comparing user DN with \"%V\"", &val);
        if (val.len == ctx->user_dn.len && ngx_memcmp(val.data, ctx->user_dn.data, val.len) == 0) {
            if (ctx->server->satisfy_all == 0) {
                ctx->outcome = OUTCOME_ALLOW;
                return NGX_OK;
            }
        } else {
            if (ctx->server->satisfy_all == 1) {
                ctx->outcome = OUTCOME_DENY;
                return NGX_DECLINED;
            }
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_ldap_check_group(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx)
{
    ngx_http_complex_value_t *values;
    ngx_int_t rc;
    u_char *filter;
    char *user_val;
    char *attrs[2];
    size_t for_filter;

    /* Handle result of the search started during previous call */
    if (ctx->iteration > 0) {
        ctx->group_dn.data = ctx->dn.data;
        if (ctx->group_dn.data == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: ldap_search_ext() returned NULL result");
            if (ctx->server->satisfy_all == 1) {
                ctx->outcome = OUTCOME_DENY;
                return NGX_DECLINED;
            }
        } else {
            if (ctx->error_code == LDAP_SUCCESS) {
                if (ctx->server->satisfy_all == 0) {
                    ctx->outcome = OUTCOME_ALLOW;
                    return NGX_OK;
                }
            } else if (ctx->error_code == LDAP_NO_RESULTS_RETURNED) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: ldap_search_ext() request failed (%d: %s)",
                              ctx->error_code, ldap_err2string(ctx->error_code));
                if (ctx->server->satisfy_all == 1) {
                    ctx->outcome = OUTCOME_DENY;
                    return NGX_DECLINED;
                }
            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: ldap_search_ext() request failed (%d: %s)",
                    ctx->error_code, ldap_err2string(ctx->error_code));
                return NGX_ERROR;
            }
        }
    }

    /* Check next group */
    if (ctx->iteration >= ctx->server->require_group->nelts) {
        /* No more groups */
        return NGX_OK;
    }

    if (!ngx_http_auth_ldap_get_connection(ctx)) {
        return NGX_AGAIN;
    }

    ctx->replied = 0;
    ngx_str_t val;
    values = ctx->server->require_group->elts;
    if (ngx_http_complex_value(r, &values[ctx->iteration], &val) != NGX_OK) {
        ctx->outcome = OUTCOME_ERROR;
        ngx_http_auth_ldap_return_connection(ctx->c);
        return NGX_ERROR;
    }

    char *gr;
    char *cn_gr;
    char *tail_gr;
    gr = ngx_pcalloc(r->pool,val.len+1);
    ngx_memcpy(gr, val.data, val.len);
    gr[val.len] = '\0';
    tail_gr = ngx_strchr(gr, ',');
    if (tail_gr == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: Incorrect group DN: \"%s\"", gr);
        ctx->outcome = OUTCOME_ERROR;
        ngx_http_auth_ldap_return_connection(ctx->c);
        return NGX_ERROR;
    }
    *tail_gr = '\0';
    tail_gr++;
    cn_gr = gr;

    if (ctx->server->group_attribute_dn == 1) {
        user_val = ngx_pcalloc(
            r->pool,
            ctx->user_dn.len + 1);
        ngx_memcpy(user_val, ctx->user_dn.data, ctx->user_dn.len);
        user_val[ctx->user_dn.len] = '\0';
    } else {
        user_val = ngx_pcalloc(
            r->pool,
            r->headers_in.user.len + 1);
        ngx_memcpy(user_val, r->headers_in.user.data, r->headers_in.user.len);
        user_val[r->headers_in.user.len] = '\0';
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Search user in group \"%V\"", &val);

    if (ctx->server->group_attribute.data == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: group_attribute.data is \"%V\" so calling a failure here", ctx->server->group_attribute.data);
        rc = !LDAP_SUCCESS;
    } else {
        for_filter = ngx_strlen(cn_gr) + ctx->server->group_attribute.len + ngx_strlen((const char *) user_val) + ngx_strlen("(&()(=))") + 1;
        filter = ngx_pcalloc(
            r->pool,
            for_filter);
        ngx_sprintf(filter, "(&(%s)(%s=%s))", cn_gr, ctx->server->group_attribute.data, user_val);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Search group filter is \"%s\"", (const char *) filter);
        attrs[0] = LDAP_NO_ATTRS;
        attrs[1] = NULL;
        rc = ldap_search_ext(ctx->c->ld, tail_gr, LDAP_SCOPE_ONELEVEL, (const char *) filter, attrs, 0, NULL, NULL, NULL, 0, &ctx->c->msgid);
    }
    if (rc != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: ldap_search_ext() failed (%d: %s)",
            rc, ldap_err2string(rc));
        ctx->outcome = OUTCOME_ERROR;
        ngx_http_auth_ldap_return_connection(ctx->c);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: ldap_search_ext() -> msgid=%d",
        ctx->c->msgid);
    ctx->c->state = STATE_SEARCHING;
    ctx->iteration++;
    return NGX_AGAIN;
}

/**
 * Initiate and handle a bind operation using the authentication parameters
 */
static ngx_int_t
ngx_http_auth_ldap_check_bind(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx)
{
    struct berval cred;
    ngx_int_t rc;

    /* On the first call, initiate the bind LDAP operation */
    if (ctx->iteration == 0) {
        if (!ngx_http_auth_ldap_get_connection(ctx)) {
            return NGX_AGAIN;
        }

        cred.bv_val = (char *) r->headers_in.passwd.data;
        cred.bv_len = r->headers_in.passwd.len;
        rc = ldap_sasl_bind(ctx->c->ld, (const char *) ctx->user_dn.data, LDAP_SASL_SIMPLE, &cred, NULL, NULL, &ctx->c->msgid);
        if (rc != LDAP_SUCCESS) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: ldap_sasl_bind() failed (%d: %s)",
                rc, ldap_err2string(rc));
            ctx->outcome = OUTCOME_ERROR;
            ngx_http_auth_ldap_return_connection(ctx->c);
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: ldap_sasl_bind() -> msgid=%d",
            ctx->c->msgid);
        ctx->c->state = STATE_BINDING;
        ctx->iteration++;

        return NGX_AGAIN;
    }

    /* On the second call, process the operation result */
    if (ctx->error_code != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: User bind failed (%d: %s)",
            ctx->error_code, ldap_err2string(ctx->error_code));
        ctx->outcome = OUTCOME_DENY;
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: User bind successful");
        ctx->outcome = OUTCOME_ALLOW;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_ldap_recover_bind(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx)
{
    struct berval cred;
    ngx_int_t rc;

    /* On the first call, initiate the bind LDAP operation */
    if (ctx->iteration == 0) {
        if (!ngx_http_auth_ldap_get_connection(ctx)) {
            return NGX_AGAIN;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Rebinding to binddn");
        cred.bv_val = (char *) ctx->server->bind_dn_passwd.data;
        cred.bv_len = ctx->server->bind_dn_passwd.len;
        rc = ldap_sasl_bind(ctx->c->ld, (const char *) ctx->server->bind_dn.data, LDAP_SASL_SIMPLE, &cred, NULL, NULL, &ctx->c->msgid);
        if (rc != LDAP_SUCCESS) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: ldap_sasl_bind() failed (%d: %s)",
                rc, ldap_err2string(rc));
            ctx->outcome = OUTCOME_ERROR;
            ngx_http_auth_ldap_return_connection(ctx->c);
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: ldap_sasl_bind() -> msgid=%d",
            ctx->c->msgid);
        ctx->c->state = STATE_BINDING;
        ctx->iteration++;
        return NGX_AGAIN;
    }

    /* On the second call, process the operation result */
    if (ctx->error_code != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: binddn bind failed (%d: %s)",
            ctx->error_code, ldap_err2string(ctx->error_code));
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: binddn bind successful");
    }
    return NGX_OK;
}
