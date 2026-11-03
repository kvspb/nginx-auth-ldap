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

/* Access phase handler and the authentication state machine. */

#include "ngx_http_auth_ldap.h"

static ngx_int_t ngx_http_auth_ldap_authenticate(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx,
        ngx_http_auth_ldap_loc_conf_t *conf);
static int ngx_http_auth_ldap_cached_outcome(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx,
        ngx_http_auth_ldap_loc_conf_t *conf);
static ngx_int_t ngx_http_auth_ldap_expand_user_dn(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static ngx_flag_t ngx_http_auth_ldap_same_shape(ngx_http_request_t *r, ngx_array_t *expected, ngx_str_t *dn);
static ngx_int_t ngx_http_auth_ldap_dn_equal(ngx_http_request_t *r, ngx_str_t *a, ngx_str_t *b);
static ngx_int_t ngx_http_auth_ldap_search(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static u_char *ngx_http_auth_ldap_user_filter(ngx_http_request_t *r, ngx_http_auth_ldap_server_t *server,
    ngx_str_t *user);
static ngx_int_t ngx_http_auth_ldap_check_user(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static ngx_int_t ngx_http_auth_ldap_check_group(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static ngx_int_t ngx_http_auth_ldap_check_bind(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static ngx_int_t ngx_http_auth_ldap_recover_bind(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static ngx_int_t ngx_http_auth_ldap_wait_result(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx,
        const char *call, int rc, ngx_http_auth_ldap_connection_state_t state);
static void ngx_http_auth_ldap_cleanup_request(void *data);
static ngx_flag_t ngx_http_auth_ldap_server_failed(int code);
static ngx_str_t *ngx_http_auth_ldap_login(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static ngx_flag_t ngx_http_auth_ldap_control(u_char c);
static ngx_int_t ngx_http_auth_ldap_header_safe(ngx_pool_t *pool, u_char *data, size_t len, ngx_str_t *out);
static ngx_int_t ngx_http_auth_ldap_allow(ngx_http_auth_ldap_ctx_t *ctx);
static void ngx_http_auth_ldap_deny_requirements(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static ngx_int_t ngx_http_auth_ldap_challenge(ngx_http_request_t *r, ngx_http_auth_ldap_loc_conf_t *alcf,
    ngx_str_t *challenge);

#define NGX_HTTP_AUTH_LDAP_GC_HINT \
    "for Active Directory, use the Global Catalog (port 3268)"

/*** Per-request authentication processing ***/

/*
 * Whether an LDAP result says the server could not answer, as opposed to
 * an answer about the request: the connection broke or timed out (the
 * client-side codes), or the server is busy, unavailable or over a limit.
 * Such a result decides nothing about the credentials (nal-5br.17).
 */
static ngx_flag_t
ngx_http_auth_ldap_server_failed(int code)
{
    switch (code) {
    case LDAP_NO_RESULTS_RETURNED:   /* set by the read handler, an answer */
        return 0;
    case LDAP_REFERRAL:              /* the entry is on another server */
    case LDAP_TIMELIMIT_EXCEEDED:
    case LDAP_ADMINLIMIT_EXCEEDED:
    case LDAP_BUSY:
    case LDAP_UNAVAILABLE:
    case LDAP_OTHER:
        return 1;
    default:
        /* OpenLDAP API errors (LDAP_SERVER_DOWN, LDAP_TIMEOUT...) */
        return code < 0;
    }
}

/*
 * The login for the error log: quotes, backslashes and control characters
 * escaped as \xNN, so that a login cannot forge a log line. Computed once
 * per request; "-" when memory runs out.
 */
static ngx_str_t *
ngx_http_auth_ldap_login(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx)
{
    static ngx_str_t unknown = ngx_string("-");
    ngx_str_t *user;
    ngx_uint_t i;
    u_char c, *p;

    if (ctx->login.data != NULL) {
        return &ctx->login;
    }

    /* Room for every byte written as \xNN. */
    user = &r->headers_in.user;
    p = ngx_pnalloc(r->pool, 4 * user->len + 1);
    if (p == NULL) {
        return &unknown;
    }

    ctx->login.data = p;
    for (i = 0; i < user->len; i++) {
        c = user->data[i];
        if (c < 0x20 || c == 0x7f || c == '"' || c == '\\') {
            p = ngx_sprintf(p, "\\x%02xd", c);
        } else {
            *p++ = c;
        }
    }
    ctx->login.len = p - ctx->login.data;

    return &ctx->login;
}

/*
 * A copy of a value of the directory for a variable, which may end up in a
 * header: control characters, CR and LF among them, are written as \xNN so
 * that they cannot start a header of their own.
 */
static ngx_flag_t
ngx_http_auth_ldap_control(u_char c)
{
    return c < 0x20 || c == 0x7f;
}

static ngx_int_t
ngx_http_auth_ldap_header_safe(ngx_pool_t *pool, u_char *data, size_t len, ngx_str_t *out)
{
    size_t  i;
    u_char *p;

    p = ngx_pnalloc(pool, 4 * len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    out->data = p;
    for (i = 0; i < len; i++) {
        if (ngx_http_auth_ldap_control(data[i])) {
            p = ngx_sprintf(p, "\\x%02xd", data[i]);
        } else {
            *p++ = data[i];
        }
    }
    out->len = p - out->data;

    return NGX_OK;
}

/*
 * The first value of each of user_attributes in the first entry of the
 * user search, for $ldap_attr_<name>. On allocation failure the
 * variables stay empty.
 */
void
ngx_http_auth_ldap_entry_attributes(ngx_http_auth_ldap_ctx_t *ctx, LDAP *ld, LDAPMessage *entry)
{
    ngx_http_auth_ldap_server_t *server;
    struct berval **bv;
    ngx_str_t *names, *values;
    ngx_uint_t i;

    server = ctx->server;
    if (server->user_attributes == NULL) {
        return;
    }

    names = server->user_attributes->elts;
    values = ngx_pcalloc(ctx->r->pool, server->user_attributes->nelts * sizeof(ngx_str_t));
    if (values == NULL) {
        return;
    }

    for (i = 0; i < server->user_attributes->nelts; i++) {
        bv = ldap_get_values_len(ld, entry, (const char *) names[i].data);
        if (bv == NULL) {
            continue;
        }
        if (bv[0] != NULL) {
            /* Left empty on allocation failure. */
            (void) ngx_http_auth_ldap_header_safe(ctx->r->pool, (u_char *) bv[0]->bv_val,
                       bv[0]->bv_len, &values[i]);
        }
        ldap_value_free_len(bv);
    }

    ctx->search_attrs = values;
}

/* LDAP allowed the request on ctx->server: keep the user for the variables. */
static ngx_int_t
ngx_http_auth_ldap_allow(ngx_http_auth_ldap_ctx_t *ctx)
{
    if (ngx_http_auth_ldap_header_safe(ctx->r->pool, ctx->user_dn.data, ctx->user_dn.len,
            &ctx->allowed_dn) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ctx->allowed_server = ctx->server;
    ctx->allowed_attrs = ctx->search_attrs;

    return NGX_OK;
}

static ngx_http_auth_ldap_ctx_t *
ngx_http_auth_ldap_allowed_ctx(ngx_http_request_t *r)
{
    ngx_http_auth_ldap_ctx_t *ctx;

    /* Subrequests skip the access phase: the user is that of the main one. */
    ctx = ngx_http_get_module_ctx(r->main, ngx_http_auth_ldap_module);
    if (ctx == NULL || ctx->allowed_server == NULL) {
        return NULL;
    }

    return ctx;
}

ngx_int_t
ngx_http_auth_ldap_user_dn_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_auth_ldap_ctx_t *ctx;

    ctx = ngx_http_auth_ldap_allowed_ctx(r);
    if (ctx == NULL || ctx->allowed_dn.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->allowed_dn.data;
    v->len = ctx->allowed_dn.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

/* $ldap_attr_<name>: data is the name of the variable, in lower case. */
ngx_int_t
ngx_http_auth_ldap_attr_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t *var = (ngx_str_t *) data;
    ngx_http_auth_ldap_ctx_t *ctx;
    ngx_str_t *names, name;
    ngx_uint_t i;

    v->not_found = 1;

    ctx = ngx_http_auth_ldap_allowed_ctx(r);
    if (ctx == NULL || ctx->allowed_attrs == NULL) {
        return NGX_OK;
    }

    name.data = var->data + sizeof("ldap_attr_") - 1;
    name.len = var->len - (sizeof("ldap_attr_") - 1);

    names = ctx->allowed_server->user_attributes->elts;
    for (i = 0; i < ctx->allowed_server->user_attributes->nelts; i++) {
        if (names[i].len == name.len
            && ngx_strncasecmp(names[i].data, name.data, name.len) == 0)
        {
            v->data = ctx->allowed_attrs[i].data;
            v->len = ctx->allowed_attrs[i].len;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            break;
        }
    }

    return NGX_OK;
}

/* The user was found and may have the right password, but the require
 * rules of this server do not admit them. */
static void
ngx_http_auth_ldap_deny_requirements(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx)
{
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        "http_auth_ldap: User \"%V\" does not meet the requirements of server \"%V\"",
        ngx_http_auth_ldap_login(r, ctx), &ctx->server->alias);
    ctx->outcome = OUTCOME_DENY;
}

/*
 * The WWW-Authenticate value for this request: the realm with its variables
 * expanded, as an RFC 9110 quoted string. NGX_DECLINED when it is "off".
 * charset="UTF-8" (RFC 7617, 2.1) asks the browser for UTF-8 credentials,
 * as LDAP stores them (kvspb#145).
 */
static ngx_int_t
ngx_http_auth_ldap_challenge(ngx_http_request_t *r, ngx_http_auth_ldap_loc_conf_t *alcf,
    ngx_str_t *challenge)
{
    ngx_str_t realm;
    ngx_uint_t i, escapes;
    u_char *p;

    if (ngx_http_complex_value(r, alcf->realm, &realm) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
        return NGX_DECLINED;
    }

    escapes = 0;
    for (i = 0; i < realm.len; i++) {
        if (realm.data[i] == '"' || realm.data[i] == '\\') {
            escapes++;
        }
    }

    challenge->len = sizeof("Basic realm=\"") - 1 + realm.len + escapes
                     + sizeof("\", charset=\"UTF-8\"") - 1;
    challenge->data = ngx_pnalloc(r->pool, challenge->len);
    if (challenge->data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(challenge->data, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    for (i = 0; i < realm.len; i++) {
        if (realm.data[i] == '"' || realm.data[i] == '\\') {
            *p++ = '\\';
        }
        *p++ = realm.data[i];
    }
    ngx_memcpy(p, "\", charset=\"UTF-8\"", sizeof("\", charset=\"UTF-8\"") - 1);

    return NGX_OK;
}

/* Answer 401 with the challenge. */
static ngx_int_t
ngx_http_auth_ldap_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
#if (nginx_version >= 1023000)
    /* Since 1.23 headers of the same name form a list; the core walks it. */
    r->headers_out.www_authenticate->next = NULL;
#endif
    r->headers_out.www_authenticate->key.len = sizeof("WWW-Authenticate") - 1;
    r->headers_out.www_authenticate->key.data = (u_char *) "WWW-Authenticate";
    r->headers_out.www_authenticate->value = *realm;

    return NGX_HTTP_UNAUTHORIZED;
}

/**
 * LDAP Authentication handler
 */
ngx_int_t
ngx_http_auth_ldap_handler(ngx_http_request_t *r)
{
    ngx_http_auth_ldap_loc_conf_t *alcf;
    ngx_http_auth_ldap_ctx_t *ctx;
    ngx_pool_cleanup_t *cln;
    ngx_str_t challenge;
    int rc;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_ldap_module);
    if (alcf->realm == NULL) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_ldap_module);
    if (ctx == NULL) {
        /* Expanded once per request: a later run must not change it. */
        rc = ngx_http_auth_ldap_challenge(r, alcf, &challenge);
        if (rc != NGX_OK) {
            return rc;
        }

        if (alcf->servers == NULL || alcf->servers->nelts == 0) {
            /* No LDAP servers for the location. */
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: \"auth_ldap\" requires "
                          "one or more \"auth_ldap_servers\" in the same location");
            return ngx_http_auth_ldap_set_realm(r, &challenge);
        }

        rc = ngx_http_auth_basic_user(r);
        if (rc == NGX_DECLINED) {
            return ngx_http_auth_ldap_set_realm(r, &challenge);
        }
        if (rc == NGX_ERROR) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Username is \"%V\"",
            &r->headers_in.user);
        if (r->headers_in.passwd.len == 0)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Password is empty");
            return ngx_http_auth_ldap_set_realm(r, &challenge);
        }

        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_auth_ldap_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ctx->r = r;
        ctx->challenge = challenge;
        ngx_queue_init(&ctx->queue);
        /* Other fields have been initialized to zero/NULL */

        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        cln->handler = ngx_http_auth_ldap_cleanup_request;
        cln->data = ctx;

        ngx_http_set_ctx(r, ctx, ngx_http_auth_ldap_module);
    }

    rc = ngx_http_auth_ldap_authenticate(r, ctx, alcf);

    /* Watch for client aborts without replacing another module's reader. */
    if (rc == NGX_AGAIN) {
        if (r->read_event_handler == ngx_http_block_reading) {
            r->read_event_handler = ngx_http_test_reading;
            if (r->connection->read->ready) {
                ngx_post_event(r->connection->read, &ngx_posted_events);
            } else if (ngx_handle_read_event(r->connection->read, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    return rc;
}

/*
 * The request is freed. It may still wait for a free connection or for
 * the answer to its operation, when it was terminated in the access phase
 * without coming back to the handler (worker_shutdown_timeout, HTTP/2
 * stream teardown, another module). Leave nothing behind that points to
 * it. Its operation is still in flight, so its connection is closed, not
 * handed to the next request (see the request_timeout case).
 */
static void
ngx_http_auth_ldap_cleanup_request(void *data)
{
    ngx_http_auth_ldap_ctx_t *ctx = data;

    ngx_http_auth_ldap_unqueue_request(ctx);
    ngx_http_auth_ldap_close_request_connection(ctx);
}

/**
 * Iteratively handle all phases of the authentication process, might be called many times
 */
static ngx_int_t
ngx_http_auth_ldap_authenticate(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx,
        ngx_http_auth_ldap_loc_conf_t *conf)
{
    ngx_int_t rc;

    if (r->connection->write->timedout) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "http_auth_ldap: Authentication timed out on server \"%V\"", &ctx->server->alias);
        /*
         * The operation of this request is still in flight: a pending user
         * bind may yet bind the connection as the user, and a hung server
         * never answers. Never hand it to the next request.
         */
        ngx_http_auth_ldap_close_request_connection(ctx);
        ngx_http_auth_ldap_unqueue_request(ctx);

        /*
         * The timer is the write event of the client connection: clear its
         * flag, or the response would be dropped as a send timeout. Answer
         * instead of closing the connection without a word (kvspb#115).
         */
        r->connection->write->timedout = 0;

        /* The server could not decide: try the next one (kvspb#115). */
        ctx->outcome = OUTCOME_UNAVAILABLE;
        ctx->phase = PHASE_NEXT;
        ctx->iteration = 0;
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
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Authentication loop (phase=%d, iteration=%d)",
            ctx->phase, ctx->iteration);

        switch (ctx->phase) {
            case PHASE_START:
                ctx->server = ((ngx_http_auth_ldap_server_t **) conf->servers->elts)[ctx->server_index];
                ctx->outcome = OUTCOME_UNCERTAIN;

                ngx_add_timer(r->connection->write, ctx->server->request_timeout);
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: request_timeout=%d",ctx->server->request_timeout);


                if (ngx_http_auth_ldap_cache.buckets != NULL) {
                    ctx->outcome = ngx_http_auth_ldap_cached_outcome(r, ctx, conf);
                    if (ctx->outcome == OUTCOME_CACHED_DENY) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "http_auth_ldap: User \"%V\" denied by the cache of server \"%V\"",
                            ngx_http_auth_ldap_login(r, ctx), &ctx->server->alias);
                    }
                    if (ctx->outcome != OUTCOME_UNCERTAIN) {
                        ctx->phase = PHASE_NEXT;
                        break;
                    }
                }

                /*
                 * A server without a single connection bound as binddn,
                 * whose last connection attempt failed (unreachable, or
                 * rejecting binddn), cannot answer soon: go on to the next
                 * one instead of waiting for its request_timeout. A server
                 * that is still connecting, as after the start of a worker,
                 * is waited for, and so is the last server.
                 */
                if (ctx->server->established == 0 && ctx->server->failing
                    && ctx->server_index + 1 < conf->servers->nelts)
                {
                    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                        "http_auth_ldap: Server \"%V\" has no connection, trying the next server",
                        &ctx->server->alias);
                    ctx->outcome = OUTCOME_UNAVAILABLE;
                    ctx->phase = PHASE_NEXT;
                    break;
                }

                if (ctx->server->require_valid_user_dn.value.data != NULL) {
                    rc = ngx_http_auth_ldap_expand_user_dn(r, ctx);
                    if (rc == NGX_DECLINED) {
                        ctx->outcome = OUTCOME_DENY;
                        ctx->phase = PHASE_NEXT;
                        break;
                    }
                    if (rc != NGX_OK) {
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
                        ngx_http_auth_ldap_deny_requirements(r, ctx);
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
                if (rc != NGX_OK || ctx->c == NULL) {
                    /*
                     * The bind was never sent, or its connection died
                     * under it (LDAP_SERVER_DOWN): nothing to rebind.
                     */
                    ctx->phase = PHASE_NEXT;
                    break;
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

                if (ctx->outcome == OUTCOME_ALLOW && ngx_http_auth_ldap_allow(ctx) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                if (ngx_http_auth_ldap_cache.buckets != NULL &&
                    (ctx->outcome == OUTCOME_DENY || ctx->outcome == OUTCOME_ALLOW)) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Caching outcome %d", ctx->outcome);
                    ngx_http_auth_ldap_update_cache(ctx, &ngx_http_auth_ldap_cache, ctx->outcome);
                }

                if (ctx->outcome == OUTCOME_ALLOW || ctx->outcome == OUTCOME_CACHED_ALLOW) {
                    return NGX_OK;
                }

                if (ctx->outcome == OUTCOME_UNAVAILABLE) {
                    ctx->unavailable = 1;
                }

                ctx->server_index++;
                if (ctx->server_index >= conf->servers->nelts) {
                    /* A server that could not decide may know the user. */
                    if (ctx->unavailable) {
                        return NGX_HTTP_SERVICE_UNAVAILABLE;
                    }
                    return ngx_http_auth_ldap_set_realm(r, &ctx->challenge);
                }

                ctx->phase = PHASE_START;
                break;
        }
    }
}

/*
 * Look the request up in the cache. An ALLOW cached by any server of this
 * location admits the user (kvspb#201); a DENY only skips the server that
 * produced it, the next server may still allow. OUTCOME_UNCERTAIN when
 * nothing is cached.
 */
static int
ngx_http_auth_ldap_cached_outcome(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx,
        ngx_http_auth_ldap_loc_conf_t *conf)
{
    ngx_int_t rc;
    ngx_uint_t i;
    ngx_http_auth_ldap_server_t *s;

    for (i = 0; i < conf->servers->nelts; i++) {
        s = ((ngx_http_auth_ldap_server_t **) conf->servers->elts)[i];
        if (s == ctx->server) {
            continue;
        }
        rc = ngx_http_auth_ldap_check_cache(r, ctx, &ngx_http_auth_ldap_cache, s);
        if (rc == OUTCOME_ALLOW && ngx_http_auth_ldap_restore_user(ctx, s) == NGX_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "http_auth_ldap: Using cached allow from server %ui", i);
            return OUTCOME_CACHED_ALLOW;
        }
    }

    /* Last, so that ctx keeps the key of ctx->server for
     * ngx_http_auth_ldap_update_cache() in PHASE_NEXT. */
    rc = ngx_http_auth_ldap_check_cache(r, ctx, &ngx_http_auth_ldap_cache, ctx->server);
    if (rc == OUTCOME_ALLOW && ngx_http_auth_ldap_restore_user(ctx, ctx->server) != NGX_OK) {
        return OUTCOME_UNCERTAIN;
    }
    if (rc == OUTCOME_DENY || rc == OUTCOME_ALLOW) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http_auth_ldap: Using cached outcome %d", rc);
        return rc == OUTCOME_DENY ? OUTCOME_CACHED_DENY : OUTCOME_CACHED_ALLOW;
    }

    return OUTCOME_UNCERTAIN;
}

/*
 * Build the user DN from the "require valid_user" template. $remote_user
 * expands to the login escaped as an RDN value, so that the login names
 * one entry of the template and never changes the rest of the DN. A login
 * that cannot be such a value: NGX_DECLINED.
 */
static ngx_int_t
ngx_http_auth_ldap_expand_user_dn(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx)
{
    ngx_http_variable_value_t *vv, saved;
    ngx_str_t login;
    ngx_int_t rc;
    u_char *p;

    rc = ngx_http_auth_ldap_escape_dn_value(r->pool, &r->headers_in.user, &login);
    if (rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
            "http_auth_ldap: Login with a NUL byte rejected");
        return NGX_DECLINED;
    }
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * Preset the cached value of $remote_user for the evaluation and put
     * the real one back afterwards, for the access log and other modules.
     */
    vv = &r->variables[ctx->server->remote_user_index];
    saved = *vv;
    vv->len = login.len;
    vv->data = login.data;
    vv->valid = 1;
    vv->no_cacheable = 0;
    vv->not_found = 0;

    rc = ngx_http_complex_value(r, &ctx->server->require_valid_user_dn, &ctx->user_dn);
    *vv = saved;
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* The DN goes to ldap_sasl_bind() as a C string, but a complex value is
     * not NUL-terminated (nal-5br.12). */
    p = ngx_pnalloc(r->pool, ctx->user_dn.len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }
    *ngx_cpymem(p, ctx->user_dn.data, ctx->user_dn.len) = '\0';
    ctx->user_dn.data = p;

    if (ctx->server->user_dn_shape != NULL
        && !ngx_http_auth_ldap_same_shape(r, ctx->server->user_dn_shape, &ctx->user_dn))
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
            "http_auth_ldap: DN built from the template for \"%V\" "
            "does not have the RDNs of the template", &r->headers_in.user);
        return NGX_DECLINED;
    }

    return NGX_OK;
}

/* Whether dn has the RDNs and attribute-value pairs of the template. */
static ngx_flag_t
ngx_http_auth_ldap_same_shape(ngx_http_request_t *r, ngx_array_t *expected, ngx_str_t *dn)
{
    ngx_array_t *shape;

    shape = ngx_http_auth_ldap_dn_shape(r->pool, dn);
    if (shape == NULL || shape->nelts != expected->nelts) {
        return 0;
    }

    return ngx_memcmp(shape->elts, expected->elts, shape->nelts * sizeof(ngx_uint_t)) == 0;
}

/*
 * Compare two DNs as DNs: normalised by OpenLDAP (spacing, escaping) and
 * then case-insensitively, as the attribute types and the values of the
 * naming attributes in use (uid, cn, ou, dc) are (RFC 4514, RFC 4517).
 * NGX_OK when equal, NGX_DECLINED when not or when a DN is invalid.
 */
static ngx_int_t
ngx_http_auth_ldap_dn_equal(ngx_http_request_t *r, ngx_str_t *a, ngx_str_t *b)
{
    char       *in[2], *out[2];
    ngx_str_t  *dn[2];
    ngx_int_t   i, rc;

    dn[0] = a;
    dn[1] = b;
    out[0] = NULL;
    out[1] = NULL;
    rc = NGX_DECLINED;

    for (i = 0; i < 2; i++) {
        in[i] = (char *) ngx_pnalloc(r->pool, dn[i]->len + 1);
        if (in[i] == NULL) {
            rc = NGX_ERROR;
            goto done;
        }
        *ngx_cpymem(in[i], dn[i]->data, dn[i]->len) = '\0';

        if (ldap_dn_normalize(in[i], LDAP_DN_FORMAT_LDAP, &out[i], LDAP_DN_FORMAT_LDAPV3)
            != LDAP_SUCCESS)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "http_auth_ldap: Invalid DN \"%s\"", in[i]);
            goto done;
        }
    }

    if (ngx_strcasecmp((u_char *) out[0], (u_char *) out[1]) == 0) {
        rc = NGX_OK;
    }

done:

    ldap_memfree(out[0]);
    ldap_memfree(out[1]);
    return rc;
}

/*
 * The filter of the user search: the filter of the url, and either the
 * user_filter with the login for each $remote_user or (<attribute>=<login>).
 * The login is escaped already.
 */
static u_char *
ngx_http_auth_ldap_user_filter(ngx_http_request_t *r, ngx_http_auth_ldap_server_t *server,
    ngx_str_t *user)
{
    LDAPURLDesc *ludpp;
    ngx_str_t *parts;
    ngx_uint_t i;
    size_t len;
    u_char *filter, *p;
    const char *base;

    ludpp = server->ludpp;
    base = ludpp->lud_filter != NULL ? ludpp->lud_filter : "(objectClass=*)";
    len = sizeof("(&)") + ngx_strlen(base);

    if (server->user_filter == NULL) {
        len += sizeof("(=)") - 1 + ngx_strlen(ludpp->lud_attrs[0]) + user->len;
        filter = ngx_pnalloc(r->pool, len);
        if (filter == NULL) {
            return NULL;
        }
        ngx_sprintf(filter, "(&%s(%s=%V))%Z", base, ludpp->lud_attrs[0], user);
        return filter;
    }

    parts = server->user_filter->elts;
    for (i = 0; i < server->user_filter->nelts; i++) {
        len += parts[i].len + user->len;
    }

    filter = ngx_pnalloc(r->pool, len);
    if (filter == NULL) {
        return NULL;
    }

    p = ngx_sprintf(filter, "(&%s", base);
    for (i = 0; i < server->user_filter->nelts; i++) {
        if (i > 0) {
            p = ngx_cpymem(p, user->data, user->len);
        }
        p = ngx_cpymem(p, parts[i].data, parts[i].len);
    }
    *p++ = ')';
    *p = '\0';

    return filter;
}

static ngx_int_t
ngx_http_auth_ldap_search(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx)
{
    u_char *filter;
    char *attrs[2];
    ngx_int_t rc;
    ngx_str_t user;

    /* On the first call, initiate the LDAP search operation */
    if (ctx->iteration == 0) {
        /* The login name comes from the client: never let it change the filter. */
        if (ngx_http_auth_ldap_escape_filter_value(r->pool, &r->headers_in.user, &user) != NGX_OK) {
            return NGX_ERROR;
        }

        if (!ngx_http_auth_ldap_get_connection(ctx)) {
            return NGX_AGAIN;
        }

        filter = ngx_http_auth_ldap_user_filter(r, ctx->server, &user);
        if (filter == NULL) {
            ngx_http_auth_ldap_return_connection(ctx->c);
            return NGX_ERROR;
        }
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Search filter is \"%s\"",
            (const char *) filter);

        attrs[0] = LDAP_NO_ATTRS;
        attrs[1] = NULL;
        ctx->search_attrs = NULL;
        ctx->search_entries = 0;
        ngx_str_null(&ctx->referral);
        /* The read handler only records the first entry DN while ctx->dn is
         * empty: an entry left by the search of a previous server (one that
         * found two entries, for example) must not become this one's user. */
        ngx_str_null(&ctx->dn);

        /* Two entries are enough to tell an ambiguous login from a unique one. */
        rc = ldap_search_ext(ctx->c->ld, ctx->server->ludpp->lud_dn, ctx->server->ludpp->lud_scope, (const char *) filter,
            ctx->server->search_attrs != NULL ? ctx->server->search_attrs : attrs,
            0, NULL, NULL, NULL, 2, &ctx->c->msgid);
        return ngx_http_auth_ldap_wait_result(r, ctx, "ldap_search_ext", rc, STATE_SEARCHING);
    }

    /* On the second call, handle the search results */
    if (ctx->search_entries > 1 || ctx->error_code == LDAP_SIZELIMIT_EXCEEDED) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "http_auth_ldap: User search for \"%V\" returned more than one entry",
            ngx_http_auth_ldap_login(r, ctx));
        ctx->outcome = OUTCOME_ERROR;
        return NGX_ERROR;
    }

    if (ctx->error_code == LDAP_REFERRAL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "http_auth_ldap: Server \"%V\" referred the user search to \"%V\": "
            "the base DN of its url is on another server; "
            NGX_HTTP_AUTH_LDAP_GC_HINT, &ctx->server->alias, &ctx->referral);
        ctx->outcome = OUTCOME_UNAVAILABLE;
        return NGX_ERROR;
    }

    if (ctx->error_code != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: ldap_search_ext() request failed (%d: %s)",
            ctx->error_code, ldap_err2string(ctx->error_code));
        if (ngx_http_auth_ldap_server_failed(ctx->error_code)) {
            ctx->outcome = OUTCOME_UNAVAILABLE;
        }
        return NGX_ERROR;
    }

    if (ctx->dn.data == NULL && ctx->referral.data != NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "http_auth_ldap: User \"%V\" not found on server \"%V\", which referred to \"%V\"; "
            NGX_HTTP_AUTH_LDAP_GC_HINT, ngx_http_auth_ldap_login(r, ctx), &ctx->server->alias, &ctx->referral);
        return NGX_ERROR;
    }

    if (ctx->dn.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "http_auth_ldap: Could not find user DN for \"%V\" on server \"%V\"",
            ngx_http_auth_ldap_login(r, ctx), &ctx->server->alias);
        return NGX_ERROR;
    }

    /* The read handler copied it, NUL-terminated, into the request pool. */
    ctx->user_dn = ctx->dn;
    ngx_str_null(&ctx->dn);

    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_ldap_check_user(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx)
{
    ngx_http_complex_value_t *values;
    ngx_str_t val;
    ngx_uint_t i;
    ngx_int_t rc;

    values = ctx->server->require_user->elts;
    for (i = 0; i < ctx->server->require_user->nelts; i++) {
        if (ngx_http_complex_value(r, &values[i], &val) != NGX_OK) {
            ctx->outcome = OUTCOME_ERROR;
            return NGX_ERROR;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Comparing user DN with \"%V\"", &val);
        rc = ngx_http_auth_ldap_dn_equal(r, &val, &ctx->user_dn);
        if (rc == NGX_ERROR) {
            ctx->outcome = OUTCOME_ERROR;
            return NGX_ERROR;
        }
        if (rc == NGX_OK) {
            if (ctx->server->satisfy_all == 0) {
                ctx->outcome = OUTCOME_ALLOW;
                return NGX_OK;
            }
        } else {
            if (ctx->server->satisfy_all == 1) {
                ngx_http_auth_ldap_deny_requirements(r, ctx);
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
    ngx_str_t val, user_val;
    char *attrs[2];
    char *group;
    size_t for_filter;
    LDAPDN dn;

    /* Handle result of the search started during previous call */
    if (ctx->iteration > 0) {
        if (ngx_http_auth_ldap_server_failed(ctx->error_code)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: ldap_search_ext() request failed (%d: %s)",
                ctx->error_code, ldap_err2string(ctx->error_code));
            ctx->outcome = OUTCOME_UNAVAILABLE;
            return NGX_ERROR;
        }
        if (ctx->dn.data == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: ldap_search_ext() returned NULL result");
            if (ctx->server->satisfy_all == 1) {
                ngx_http_auth_ldap_deny_requirements(r, ctx);
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
                    ngx_http_auth_ldap_deny_requirements(r, ctx);
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

    /* The read handler only records the first entry DN while ctx->dn is
     * empty; without this reset the entry found for the previous group would
     * count as a match for this one (kvspb#194). */
    ngx_str_null(&ctx->dn);
    values = ctx->server->require_group->elts;
    if (ngx_http_complex_value(r, &values[ctx->iteration], &val) != NGX_OK) {
        goto failed;
    }

    /* The group entry itself is searched, so its DN is never parsed here
     * and no part of it reaches the filter. */
    group = ngx_pnalloc(r->pool, val.len + 1);
    if (group == NULL) {
        goto failed;
    }
    *ngx_cpymem(group, val.data, val.len) = '\0';

    dn = NULL;
    if (val.len == 0
        || ldap_str2dn(group, &dn, LDAP_DN_FORMAT_LDAPV3) != LDAP_SUCCESS)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "http_auth_ldap: Incorrect group DN: \"%s\"", group);
        goto failed;
    }
    ldap_dnfree(dn);

    /* Both the DN (e.g. "cn=Doe\, John,...") and the login name may contain
     * characters that are special in a filter. */
    rc = ngx_http_auth_ldap_escape_filter_value(r->pool,
        ctx->server->group_attribute_dn == 1 ? &ctx->user_dn : &r->headers_in.user, &user_val);
    if (rc != NGX_OK) {
        goto failed;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Search user in group \"%V\"", &val);

    if (ctx->server->group_attribute.data == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http_auth_ldap: group_attribute is not set, the group check fails");
        rc = !LDAP_SUCCESS;
    } else {
        for_filter = ctx->server->group_attribute.len + user_val.len + ngx_strlen("(=)") + 1;
        filter = ngx_pcalloc(
            r->pool,
            for_filter);
        if (filter == NULL) {
            goto failed;
        }
        ngx_sprintf(filter, "(%V=%V)", &ctx->server->group_attribute, &user_val);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Search group filter is \"%s\"", (const char *) filter);
        attrs[0] = LDAP_NO_ATTRS;
        attrs[1] = NULL;
        rc = ldap_search_ext(ctx->c->ld, group, LDAP_SCOPE_BASE, (const char *) filter, attrs, 0, NULL, NULL, NULL, 0, &ctx->c->msgid);
    }

    return ngx_http_auth_ldap_wait_result(r, ctx, "ldap_search_ext", rc, STATE_SEARCHING);

failed:

    ctx->outcome = OUTCOME_ERROR;
    ngx_http_auth_ldap_return_connection(ctx->c);
    return NGX_ERROR;
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
        return ngx_http_auth_ldap_wait_result(r, ctx, "ldap_sasl_bind", rc, STATE_BINDING);
    }

    /* On the second call, process the operation result */
    if (ctx->error_code != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "http_auth_ldap: User bind failed for \"%V\" on server \"%V\" (%d: %s)",
            ngx_http_auth_ldap_login(r, ctx), &ctx->server->alias,
            ctx->error_code, ldap_err2string(ctx->error_code));
        ctx->outcome = ngx_http_auth_ldap_server_failed(ctx->error_code)
                       ? OUTCOME_UNAVAILABLE : OUTCOME_DENY;
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
        return ngx_http_auth_ldap_wait_result(r, ctx, "ldap_sasl_bind", rc, STATE_BINDING);
    }

    /* On the second call, process the operation result */
    if (ctx->error_code != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: binddn bind failed (%d: %s)",
            ctx->error_code, ldap_err2string(ctx->error_code));

        /*
         * The connection is still bound as the user: never hand it to the
         * next request. The outcome of the user bind stands.
         */
        ngx_http_auth_ldap_close_request_connection(ctx);
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: binddn bind successful");
    }
    return NGX_OK;
}

/*
 * Finish sending an LDAP operation on ctx->c. If "call" failed, the
 * request fails on this server. A failed send (LDAP_SERVER_DOWN) left the
 * connection without its socket inside OpenLDAP: close it, and since the
 * server was not asked, decide nothing about the credentials. Any other
 * error (a bad filter from the configuration) gives the connection back.
 * Otherwise wait for the answer in the given connection state.
 */
static ngx_int_t
ngx_http_auth_ldap_wait_result(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx,
        const char *call, int rc, ngx_http_auth_ldap_connection_state_t state)
{
    if (rc != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: %s() failed (%d: %s)",
            call, rc, ldap_err2string(rc));
        if (rc == LDAP_SERVER_DOWN) {
            ctx->outcome = OUTCOME_UNAVAILABLE;
            ngx_http_auth_ldap_close_request_connection(ctx);
        } else {
            ctx->outcome = OUTCOME_ERROR;
            ngx_http_auth_ldap_return_connection(ctx->c);
        }
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: %s() -> msgid=%d",
        call, ctx->c->msgid);
    ctx->c->state = state;
    /* The answer to the previous operation set it; until this one comes, a
     * run of the phases must wait instead of judging that answer. */
    ctx->replied = 0;
    ctx->iteration++;
    return NGX_AGAIN;
}
