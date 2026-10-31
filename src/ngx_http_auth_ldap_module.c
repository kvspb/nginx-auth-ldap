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

/* Module definition: directives, configuration contexts, init hooks. */

#include "ngx_http_auth_ldap.h"

static void * ngx_http_auth_ldap_create_main_conf(ngx_conf_t *cf);
static char * ngx_http_auth_ldap_init_main_conf(ngx_conf_t *cf, void *parent);
static void * ngx_http_auth_ldap_create_loc_conf(ngx_conf_t *);
static char * ngx_http_auth_ldap_merge_loc_conf(ngx_conf_t *, void *, void *);
static ngx_int_t ngx_http_auth_ldap_init_worker(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_auth_ldap_init(ngx_conf_t *cf);

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
