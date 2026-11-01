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
static ngx_int_t ngx_http_auth_ldap_dn_equal(ngx_http_request_t *r, ngx_str_t *a, ngx_str_t *b);
static ngx_int_t ngx_http_auth_ldap_search(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static ngx_int_t ngx_http_auth_ldap_check_user(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static ngx_int_t ngx_http_auth_ldap_check_group(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static ngx_int_t ngx_http_auth_ldap_check_bind(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);
static ngx_int_t ngx_http_auth_ldap_recover_bind(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx);

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
        ngx_queue_init(&ctx->queue);
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
    u_char *p;

    if (r->connection->write->timedout) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "http_auth_ldap: Authentication timed out");
        if (ctx->c != NULL) {
            ngx_http_auth_ldap_return_connection(ctx->c);
        }

        ngx_http_auth_ldap_unqueue_request(ctx);

        /*
         * The timer is the write event of the client connection: clear its
         * flag, or the response would be dropped as a send timeout. Answer
         * instead of closing the connection without a word (kvspb#115).
         */
        r->connection->write->timedout = 0;
        return NGX_HTTP_SERVICE_UNAVAILABLE;
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


                /*
                 * Check cache if enabled. An ALLOW cached by any server of this
                 * location admits the user (kvspb#201); a DENY only skips the
                 * server that produced it, the next server may still allow.
                 */
                if (ngx_http_auth_ldap_cache.buckets != NULL) {
                    for (i = 0; i < conf->servers->nelts; i++) {
                        s = ((ngx_http_auth_ldap_server_t **) conf->servers->elts)[i];
                        if (s == ctx->server) {
                            continue;
                        }
                        rc = ngx_http_auth_ldap_check_cache(r, ctx, &ngx_http_auth_ldap_cache, s);
                        if (rc == OUTCOME_ALLOW) {
                            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                "http_auth_ldap: Using cached allow from server %ui", i);
                            ctx->outcome = OUTCOME_CACHED_ALLOW;
                            ctx->phase = PHASE_NEXT;
                            goto loop;
                        }
                    }

                    /* Last, so that ctx keeps the key of ctx->server for
                     * ngx_http_auth_ldap_update_cache() in PHASE_NEXT. */
                    rc = ngx_http_auth_ldap_check_cache(r, ctx, &ngx_http_auth_ldap_cache, ctx->server);
                    if (rc == OUTCOME_DENY || rc == OUTCOME_ALLOW) {
                        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                            "http_auth_ldap: Using cached outcome %d", rc);
                        ctx->outcome = (rc == OUTCOME_DENY ? OUTCOME_CACHED_DENY : OUTCOME_CACHED_ALLOW);
                        ctx->phase = PHASE_NEXT;
                        goto loop;
                    }
                }

                if (ctx->server->require_valid_user_dn.value.data != NULL) {
                    /* Construct user DN */
                    if (ngx_http_complex_value(r, &ctx->server->require_valid_user_dn, &ctx->user_dn) != NGX_OK) {
                        ngx_del_timer(r->connection->write);
                        return NGX_ERROR;
                    }

                    /* The DN goes to ldap_sasl_bind() as a C string, but a
                     * complex value is not NUL-terminated (nal-5br.12). */
                    p = ngx_pnalloc(r->pool, ctx->user_dn.len + 1);
                    if (p == NULL) {
                        ngx_del_timer(r->connection->write);
                        return NGX_ERROR;
                    }
                    *ngx_cpymem(p, ctx->user_dn.data, ctx->user_dn.len) = '\0';
                    ctx->user_dn.data = p;
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

static ngx_int_t
ngx_http_auth_ldap_search(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx)
{
    LDAPURLDesc *ludpp;
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

        ludpp = ctx->server->ludpp;
        filter = ngx_pcalloc(
            r->pool,
            (ludpp->lud_filter != NULL ? ngx_strlen(ludpp->lud_filter) : ngx_strlen("(objectClass=*)")) +
            ngx_strlen("(&(=))") + ngx_strlen(ludpp->lud_attrs[0]) + user.len + 1);
        if (filter == NULL) {
            ngx_http_auth_ldap_return_connection(ctx->c);
            return NGX_ERROR;
        }
        ngx_sprintf(filter, "(&%s(%s=%V))%Z",
                ludpp->lud_filter != NULL ? ludpp->lud_filter : "(objectClass=*)",
                ludpp->lud_attrs[0], &user);
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
    ngx_int_t rc;

    values = ctx->server->require_user->elts;
    for (i = 0; i < ctx->server->require_user->nelts; i++) {
        ngx_str_t val;
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
    ngx_str_t user_val;
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
    /* The read handler only records the first entry DN while ctx->dn is
     * empty; without this reset the entry found for the previous group would
     * count as a match for this one (kvspb#194). */
    ngx_str_null(&ctx->dn);
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

    /* Both the DN (e.g. "cn=Doe\, John,...") and the login name may contain
     * characters that are special in a filter. */
    rc = ngx_http_auth_ldap_escape_filter_value(r->pool,
        ctx->server->group_attribute_dn == 1 ? &ctx->user_dn : &r->headers_in.user, &user_val);
    if (rc != NGX_OK) {
        ctx->outcome = OUTCOME_ERROR;
        ngx_http_auth_ldap_return_connection(ctx->c);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: Search user in group \"%V\"", &val);

    if (ctx->server->group_attribute.data == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "http_auth_ldap: group_attribute is not set, the group check fails");
        rc = !LDAP_SUCCESS;
    } else {
        for_filter = ngx_strlen(cn_gr) + ctx->server->group_attribute.len + user_val.len + ngx_strlen("(&()(=))") + 1;
        filter = ngx_pcalloc(
            r->pool,
            for_filter);
        if (filter == NULL) {
            ctx->outcome = OUTCOME_ERROR;
            ngx_http_auth_ldap_return_connection(ctx->c);
            return NGX_ERROR;
        }
        ngx_sprintf(filter, "(&(%s)(%s=%V))", cn_gr, ctx->server->group_attribute.data, &user_val);
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
    ngx_http_auth_ldap_connection_t *c;

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

        /*
         * The connection is still bound as the user: never hand it to the
         * next request. Detach it first, so that closing it does not wake
         * this request again; the outcome of the user bind stands.
         */
        c = ctx->c;
        if (c != NULL) {
            ctx->c = NULL;
            c->rctx = NULL;
            ngx_http_auth_ldap_close_connection(c);
        }
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http_auth_ldap: binddn bind successful");
    }
    return NGX_OK;
}
