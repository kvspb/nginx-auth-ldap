/**
 * Copyright (C) 2011-2013 Valery Komarov <komarov@valerka.net>
 * Copyright (C) 2013 Jiri Hruska <jirka@fud.cz>
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
    ngx_http_complex_value_t require_valid_user_dn;
    ngx_flag_t satisfy_all;
} ngx_http_auth_ldap_server_t;

typedef struct {
    ngx_array_t *servers;        /* array of ngx_http_auth_ldap_server_t */
    ngx_flag_t cache_enabled;
    ngx_msec_t cache_expiration_time;
    size_t cache_size;
} ngx_http_auth_ldap_main_conf_t;

typedef struct {
    ngx_str_t realm;
    ngx_array_t *servers;       /* array of ngx_http_auth_ldap_server_t* */
} ngx_http_auth_ldap_loc_conf_t;

typedef struct {
    uint32_t small_hash;   /* murmur2 hash of username ^ &server       */
    uint32_t outcome;      /* 0 = authentication failed, 1 = succeeded */
    ngx_msec_t time;       /* ngx_current_msec when created            */
    u_char big_hash[16];   /* md5 hash of (username, server, password) */
} ngx_http_auth_ldap_cache_elt_t;

typedef struct {
    ngx_http_auth_ldap_cache_elt_t *buckets;
    ngx_uint_t num_buckets;
    ngx_uint_t elts_per_bucket;
    ngx_msec_t expiration_time;
} ngx_http_auth_ldap_cache_t;

typedef struct {
    ngx_http_auth_ldap_cache_elt_t *cache_bucket;
    u_char cache_big_hash[16];
    uint32_t cache_small_hash;
} ngx_http_auth_ldap_ctx_t;

static char * ngx_http_auth_ldap_ldap_server_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_auth_ldap_ldap_server(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
static char * ngx_http_auth_ldap(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_auth_ldap_servers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char * ngx_http_auth_ldap_parse_url(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static char * ngx_http_auth_ldap_parse_require(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static char * ngx_http_auth_ldap_parse_satisfy(ngx_conf_t *cf, ngx_http_auth_ldap_server_t *server);
static void * ngx_http_auth_ldap_create_main_conf(ngx_conf_t *cf);
static char * ngx_http_auth_ldap_init_main_conf(ngx_conf_t *cf, void *parent);
static void * ngx_http_auth_ldap_create_loc_conf(ngx_conf_t *);
static char * ngx_http_auth_ldap_merge_loc_conf(ngx_conf_t *, void *, void *);
static ngx_int_t ngx_http_auth_ldap_init_worker(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_auth_ldap_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_ldap_init_cache(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_auth_ldap_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_ldap_authenticate(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx,
        ngx_http_auth_ldap_loc_conf_t *conf);
static ngx_int_t ngx_http_auth_ldap_authenticate_against_server(ngx_http_request_t *r, ngx_http_auth_ldap_server_t *server,
        ngx_http_auth_ldap_loc_conf_t *conf);

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
    ngx_http_auth_ldap_server_t    server, *s;
    ngx_http_auth_ldap_main_conf_t *cnf = conf;

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
    ngx_http_auth_ldap_main_conf_t *cnf = conf;

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
 * Parse auth_ldap_servers directive
 */
static char *
ngx_http_auth_ldap_servers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

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

        for (j = 0; j < mconf->servers->nelts; j++) {
            s = &((ngx_http_auth_ldap_server_t *) mconf->servers->elts)[j];
            if (s->alias.len == value->len && ngx_memcmp(s->alias.data, value->data, s->alias.len) == 0) {
                server = s;
                break;
            }
        }

        if (server == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP server \"%V\" is not defined!", value);
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
    ngx_http_complex_value_t* target = NULL;
    ngx_http_compile_complex_value_t ccv;

    value = cf->args->elts;

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
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "auth_ldap_cache_size cannot be smaller than 100 entries.");
        return NGX_CONF_ERROR;
    }

    if (conf->cache_expiration_time == NGX_CONF_UNSET_MSEC) {
        conf->cache_expiration_time = 10000;
    }
    if (conf->cache_expiration_time < 1000) {
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "auth_ldap_cache_expiration_time cannot be smaller than 1000 ms.");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
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

    return NGX_OK;
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

    ctx->cache_small_hash = ngx_murmur_hash2(r->headers_in.user.data, r->headers_in.user.len) ^ (uint32_t)(ngx_uint_t)server;

    ngx_md5_init(&md5ctx);
    ngx_md5_update(&md5ctx, r->headers_in.user.data, r->headers_in.user.len);
    ngx_md5_update(&md5ctx, server, sizeof(*server));
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


/*** Per-request authentication processing ***/

/**
 * Respond with "403 Forbidden" and add correct headers
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
 * LDAP Authentication handler
 */
static ngx_int_t ngx_http_auth_ldap_handler(ngx_http_request_t *r) {
    ngx_http_auth_ldap_loc_conf_t *alcf;
    ngx_http_auth_ldap_ctx_t *ctx;
    int rc;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_ldap_module);
    if (alcf->realm.len == 0) {
        return NGX_DECLINED;
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

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP username: %V", &r->headers_in.user);
        if (r->headers_in.passwd.len == 0)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP password is empty");
            return ngx_http_auth_ldap_set_realm(r, &alcf->realm);
        }

        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_ldap_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_auth_ldap_module);
    }

    return ngx_http_auth_ldap_authenticate(r, ctx, alcf);
}

/**
 * Read user credentials from request, set LDAP parameters and call authentication against required servers
 */
static ngx_int_t ngx_http_auth_ldap_authenticate(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx,
        ngx_http_auth_ldap_loc_conf_t *conf) {

    ngx_http_auth_ldap_server_t *server;
    int rc;
    ngx_uint_t i;

    int version = LDAP_VERSION3;
    int reqcert = LDAP_OPT_X_TLS_ALLOW;
    struct timeval timeOut = { 10, 0 };

    /// Set LDAP version to 3 and set connection timeout.
    ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, &version);
    ldap_set_option(NULL, LDAP_OPT_NETWORK_TIMEOUT, &timeOut);

    rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &reqcert);
    if (rc != LDAP_OPT_SUCCESS) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "LDAP: unable to set require cert option: %s",
            ldap_err2string(rc));
    }

    for (i = 0; i < conf->servers->nelts; i++) {
        server = ((ngx_http_auth_ldap_server_t **) conf->servers->elts)[i];

        if (ngx_http_auth_ldap_cache.buckets != NULL) {
            rc = ngx_http_auth_ldap_check_cache(r, ctx, &ngx_http_auth_ldap_cache, server);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: Cached outcome %d", rc);
            if (rc == 0) {
                continue;
            }
            if (rc == 1) {
                return NGX_OK;
            }
        }

        rc = ngx_http_auth_ldap_authenticate_against_server(r, server, conf);

        if ((rc == 0 || rc == 1) && ngx_http_auth_ldap_cache.buckets != NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: Caching outcome %d", rc);
            ngx_http_auth_ldap_update_cache(ctx, &ngx_http_auth_ldap_cache, rc);
        }

        if (rc == 1) {
            return NGX_OK;
        } else if (rc == NGX_HTTP_INTERNAL_SERVER_ERROR) {
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
    char* ldn = NULL;
    ngx_str_t dn;
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

    if (server->require_valid_user_dn.value.data != NULL) {
        // Construct user DN
        if (ngx_http_complex_value(r, &server->require_valid_user_dn, &dn) != NGX_OK) {
            ldap_unbind_s(ld);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        /// Create filter for search users by uid
        filter = ngx_pcalloc(
            r->pool,
            (ludpp->lud_filter != NULL ? ngx_strlen(ludpp->lud_filter) : ngx_strlen("(objectClass=*)")) +
            ngx_strlen("(&(=))") + ngx_strlen(ludpp->lud_attrs[0]) + r->headers_in.user.len + 1);

        p = ngx_sprintf(filter, "(&%s(%s=%V))",
                ludpp->lud_filter != NULL ? ludpp->lud_filter : "(objectClass=*)",
                ludpp->lud_attrs[0], &r->headers_in.user);
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
            ldn = ldap_get_dn(ld, searchResult);
        }
        ldap_msgfree(searchResult);

        if (!ldn) {
            ldap_unbind_s(ld);
            return 0;
        }

        dn.data = (u_char*) ldn;
        dn.len = ngx_strlen(ldn);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: result DN %V", &dn);

    /// Check require user
    if (server->require_user != NULL) {
        value = server->require_user->elts;
        for (i = 0; i < server->require_user->nelts; i++) {
            ngx_str_t val;
            if (ngx_http_complex_value(r, &value[i], &val) != NGX_OK) {
                ldap_memfree(ldn);
                ldap_unbind_s(ld);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: compare with: %V", &val);
            if (val.len == dn.len && ngx_memcmp(val.data, dn.data, val.len) == 0) {
                pass = 1;
                if (server->satisfy_all == 0) {
                    break;
                }
            } else {
                if (server->satisfy_all == 1) {
                    ldap_memfree(ldn);
                    ldap_unbind_s(ld);
                    return 0;
                }
            }
        }
    }

    /// Check require group
    if (server->require_group != NULL) {
        if (server->group_attribute_dn == 1) {
            bvalue.bv_val = (char*) dn.data;
            bvalue.bv_len = dn.len;
        } else {
            bvalue.bv_val = (char*) r->headers_in.user.data;
            bvalue.bv_len = r->headers_in.user.len;
        }

        value = server->require_group->elts;
        for (i = 0; i < server->require_group->nelts; i++) {
            ngx_str_t val;
            if (ngx_http_complex_value(r, &value[i], &val) != NGX_OK) {
                ldap_memfree(ldn);
                ldap_unbind_s(ld);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: group compare with: %V", &val);
            rc = ldap_compare_ext_s(ld, (const char*) val.data, (const char*) server->group_attribute.data,
                &bvalue, NULL, NULL);

            /*if (rc != LDAP_COMPARE_TRUE && rc != LDAP_COMPARE_FALSE && rc != LDAP_NO_SUCH_ATTRIBUTE) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "LDAP: ldap_search_ext_s: %d, %s", rc,
                    ldap_err2string(rc));
            ldap_memfree(ldn);
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
    if (pass != 0 || (server->require_valid_user == 1 && server->satisfy_all == 0 && pass == 0)) {
        /// Bind user to the server
        rc = ldap_simple_bind_s(ld, (const char *) dn.data, (const char *) r->headers_in.passwd.data);
        if (rc != LDAP_SUCCESS) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "LDAP: ldap_simple_bind_s error: %d, %s", rc,
                ldap_err2string(rc));
            pass = 0;
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: User bind successful", NULL);
            if (server->require_valid_user == 1) pass = 1;
        }
    }

    ldap_memfree(ldn);
    ldap_unbind_s(ld);

    return pass;
}
