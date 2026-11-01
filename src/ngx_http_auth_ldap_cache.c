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

/* Cache of authentication outcomes. */

#include "ngx_http_auth_ldap.h"

ngx_http_auth_ldap_cache_t ngx_http_auth_ldap_cache;

static void ngx_http_auth_ldap_cache_hash_str(ngx_md5_t *md5ctx,
    ngx_str_t *value);
static ngx_int_t ngx_http_auth_ldap_cache_hash_templates(ngx_http_request_t *r,
    ngx_md5_t *md5ctx, ngx_http_complex_value_t *values, ngx_uint_t n);

/*** Authentication cache ***/

ngx_int_t
ngx_http_auth_ldap_init_cache(ngx_cycle_t *cycle)
{
    ngx_http_auth_ldap_main_conf_t *conf;
    ngx_uint_t count;
    ngx_http_auth_ldap_cache_t *cache;

    conf = (ngx_http_auth_ldap_main_conf_t *) ngx_http_cycle_get_module_main_conf(cycle, ngx_http_auth_ldap_module);
    if (conf == NULL || !conf->cache_enabled) {
        return NGX_OK;
    }

    /*
     * Buckets of eight entries, enough for auth_ldap_cache_size entries; a
     * table of primes used to stop at 8872 entries (audit F30). The bucket
     * is picked by a murmur hash, which needs no prime count.
     */
    count = (conf->cache_size + 7) / 8;

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

ngx_int_t
ngx_http_auth_ldap_check_cache(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx,
    ngx_http_auth_ldap_cache_t *cache, ngx_http_auth_ldap_server_t *server)
{
    ngx_http_auth_ldap_cache_elt_t *elt;
    ngx_md5_t md5ctx;
    ngx_msec_t time_limit;
    ngx_uint_t i;

    ctx->cache_small_hash = ngx_murmur_hash2(r->headers_in.user.data, r->headers_in.user.len) ^ (uint32_t) (ngx_uint_t) server;

    /*
     * The key holds the server identity and every require template as the
     * request expands it: with a variable in a template, the same login and
     * password can be allowed for one request and denied for another.
     */
    ngx_md5_init(&md5ctx);
    ngx_http_auth_ldap_cache_hash_str(&md5ctx, &r->headers_in.user);
    ngx_http_auth_ldap_cache_hash_str(&md5ctx, &server->alias);
    ngx_http_auth_ldap_cache_hash_str(&md5ctx, &server->url);
    ngx_http_auth_ldap_cache_hash_str(&md5ctx, &r->headers_in.passwd);

    ctx->cache_bucket = NULL;

    if (ngx_http_auth_ldap_cache_hash_templates(r, &md5ctx,
            &server->require_valid_user_dn,
            server->require_valid_user_dn.value.data != NULL) != NGX_OK
        || (server->require_user != NULL
            && ngx_http_auth_ldap_cache_hash_templates(r, &md5ctx,
                   server->require_user->elts, server->require_user->nelts)
               != NGX_OK)
        || (server->require_group != NULL
            && ngx_http_auth_ldap_cache_hash_templates(r, &md5ctx,
                   server->require_group->elts, server->require_group->nelts)
               != NGX_OK))
    {
        return -1;
    }

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

void
ngx_http_auth_ldap_update_cache(ngx_http_auth_ldap_ctx_t *ctx,
        ngx_http_auth_ldap_cache_t *cache, ngx_flag_t outcome)
{
    ngx_http_auth_ldap_cache_elt_t *elt, *oldest_elt;
    ngx_uint_t i;

    if (ctx->cache_bucket == NULL) {
        /* The key could not be built: never store under a partial key. */
        return;
    }

    /* The entry used least recently, an unused one first (time 0). */
    elt = ctx->cache_bucket;
    oldest_elt = elt;
    for (i = 1; i < cache->elts_per_bucket; i++) {
        if (elt[i].time < oldest_elt->time) {
            oldest_elt = &elt[i];
        }
    }

    oldest_elt->time = ngx_current_msec;
    oldest_elt->outcome = outcome;
    oldest_elt->small_hash = ctx->cache_small_hash;
    ngx_memcpy(oldest_elt->big_hash, ctx->cache_big_hash, 16);
}

/* Length-prefixed, so that adjacent values cannot run into each other. */
static void
ngx_http_auth_ldap_cache_hash_str(ngx_md5_t *md5ctx, ngx_str_t *value)
{
    ngx_md5_update(md5ctx, &value->len, sizeof(value->len));
    ngx_md5_update(md5ctx, value->data, value->len);
}

static ngx_int_t
ngx_http_auth_ldap_cache_hash_templates(ngx_http_request_t *r,
    ngx_md5_t *md5ctx, ngx_http_complex_value_t *values, ngx_uint_t n)
{
    ngx_str_t val;
    ngx_uint_t i;

    for (i = 0; i < n; i++) {
        if (ngx_http_complex_value(r, &values[i], &val) != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "http_auth_ldap: Unable to expand a require template "
                "for the cache key");
            return NGX_ERROR;
        }

        ngx_http_auth_ldap_cache_hash_str(md5ctx, &val);
    }

    return NGX_OK;
}
