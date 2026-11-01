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

/* Pool of asynchronous LDAP connections. */

#include "ngx_http_auth_ldap.h"

static void ngx_http_auth_ldap_reconnect_handler(ngx_event_t *);
static void ngx_http_auth_ldap_wake_request(ngx_http_request_t *r);
static void ngx_http_auth_ldap_initial_bind(ngx_http_auth_ldap_connection_t *c);
static void ngx_http_auth_ldap_idle_closed(ngx_http_auth_ldap_connection_t *c);
static void ngx_http_auth_ldap_note_referral(ngx_http_auth_ldap_connection_t *c, char **refs);
static void ngx_http_auth_ldap_set_keepalive(ngx_http_auth_ldap_connection_t *c, ngx_socket_t fd);

/*** Asynchronous LDAP connection handling ***/

void
ngx_http_auth_ldap_close_connection(ngx_http_auth_ldap_connection_t *c)
{
    ngx_queue_t *q;
    ngx_http_auth_ldap_ctx_t *ctx;
    ngx_pool_t *pool;

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

        pool = c->conn.connection->pool;
        ngx_close_connection(c->conn.connection);
        c->conn.connection = NULL;
        if (pool != NULL) {
            ngx_destroy_pool(pool);
        }
    }

    q = ngx_queue_head(&c->server->free_connections);
    while (q != ngx_queue_sentinel(&c->server->free_connections)) {
        if (q == &c->queue) {
            ngx_queue_remove(q);
            break;
        }
        q = ngx_queue_next(q);
    }

    ctx = c->rctx;
    c->rctx = NULL;
    if (c->state != STATE_DISCONNECTED) {
        if (c->state == STATE_READY || c->state == STATE_BINDING
            || c->state == STATE_SEARCHING)
        {
            c->server->established--;
        }
        c->state = STATE_DISCONNECTED;
        ngx_add_timer(&c->reconnect_event, c->server->reconnect_timeout);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Connection scheduled for reconnection in %d ms", c->server->reconnect_timeout);
    }

    /*
     * A request still waiting for an answer on this connection gets the
     * failure now. It must also let go of the connection: otherwise it
     * would return it to the free list later, after the reconnect has
     * already put it there (kvspb#62 #99 #104).
     */
    if (ctx != NULL) {
        ctx->c = NULL;
        ctx->replied = 1;
        ctx->error_code = LDAP_SERVER_DOWN;
        ngx_http_auth_ldap_wake_request(ctx->r);
    }
}

/*
 * Close the connection of a request whose operation may still be in flight
 * or whose connection is still bound as the user: it is never handed to the
 * next request, the reconnect binds a fresh one as binddn. The request is
 * detached first, so that closing the connection does not wake it again.
 */
void
ngx_http_auth_ldap_close_request_connection(ngx_http_auth_ldap_ctx_t *ctx)
{
    ngx_http_auth_ldap_connection_t *c;

    c = ctx->c;
    if (c == NULL) {
        return;
    }

    ctx->c = NULL;
    c->rctx = NULL;
    ngx_http_auth_ldap_close_connection(c);

    /*
     * The operation of the request is given up, not the server: connect
     * again at once instead of after reconnect_timeout, or the next
     * requests wait for it. If the server is down, that connect fails
     * and the next one waits for reconnect_timeout as usual.
     */
    if (c->reconnect_event.timer_set) {
        ngx_add_timer(&c->reconnect_event, 0);
    }
}

/*
 * Run the phases of a request that waited for LDAP. This runs from an
 * event of the LDAP connection, not of the client connection, so run the
 * subrequests it posts (SSI, mirror) here too, as nginx does after its own
 * event handlers; otherwise they wait for the next client event.
 */
static void
ngx_http_auth_ldap_wake_request(ngx_http_request_t *r)
{
    ngx_connection_t *c;

    c = r->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Waking authentication request \"%V\"",
        &r->request_line);
    ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(c);
}

int
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

void
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
        ngx_http_auth_ldap_unqueue_request(ngx_queue_data(q, ngx_http_auth_ldap_ctx_t, queue));
        ngx_http_auth_ldap_wake_request((ngx_queue_data(q, ngx_http_auth_ldap_ctx_t, queue))->r);
    }
}

/*
 * Take a request out of the waiting queue of its server, if it is there.
 * ctx->queue is initialised when the context is created and again after
 * every removal, so a second call cannot unlink it twice.
 */
void
ngx_http_auth_ldap_unqueue_request(ngx_http_auth_ldap_ctx_t *ctx)
{
    if (ctx->queue.prev != &ctx->queue) {
        ngx_queue_remove(&ctx->queue);
        ngx_queue_init(&ctx->queue);
    }
}

static void
ngx_http_auth_ldap_reply_connection(ngx_http_auth_ldap_connection_t *c, int error_code)
{
    ngx_http_auth_ldap_ctx_t *ctx = c->rctx;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: LDAP request to \"%V\" has finished",
        &c->server->alias);

    ctx->replied = 1;
    ctx->error_code = error_code;

    ngx_http_auth_ldap_wake_request(ctx->r);
}

void
ngx_http_auth_ldap_dummy_write_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "http_auth_ldap: Dummy write handler");

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_auth_ldap_close_connection(((ngx_connection_t *) wev->data)->data);
    }
}

void
ngx_http_auth_ldap_connection_established(ngx_http_auth_ldap_connection_t *c)
{
    ngx_connection_t *conn;
    Sockbuf *sb;
    ngx_int_t rc;

    conn = c->conn.connection;
    if (conn->read->timer_set) {
        ngx_del_timer(conn->read);
    }
    conn->write->handler = ngx_http_auth_ldap_dummy_write_handler;

    /* Called again after the StartTLS handshake: OpenLDAP is set up. */
    if (c->ld != NULL) {
        ngx_http_auth_ldap_initial_bind(c);
        return;
    }

    /* Initialize OpenLDAP on the connection */

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Initializing connection using URL \"%V\"", &c->server->url);

    rc = ldap_init_fd(c->conn.connection->fd, LDAP_PROTO_EXT, (const char *) c->server->url.data, &c->ld);
    if (rc != LDAP_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, c->log, errno, "http_auth_ldap: ldap_init_fd() failed (%d: %s)", rc, ldap_err2string(rc));
        ngx_http_auth_ldap_close_connection(c);
        return;
    }

    /*
     * Never chase referrals, whatever "referral" says: libldap would
     * connect to the referred host with a blocking connect() outside the
     * event loop and to any host a server names.
     */
    rc = ldap_set_option(c->ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (rc != LDAP_OPT_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: ldap_set_option() failed (%d: %s)", rc, ldap_err2string(rc));
        ngx_http_auth_ldap_close_connection(c);
        return;
    }

    rc = ldap_get_option(c->ld, LDAP_OPT_SOCKBUF, (void *) &sb);
    if (rc != LDAP_OPT_SUCCESS) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: ldap_get_option() failed (%d: %s)", rc, ldap_err2string(rc));
        ngx_http_auth_ldap_close_connection(c);
        return;
    }

    ber_sockbuf_add_io(sb, &ngx_http_auth_ldap_sbio, LBER_SBIOD_LEVEL_PROVIDER, (void *) c);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Connection initialized");

#if (NGX_OPENSSL)
    if (c->server->starttls) {
        /*
         * Ask for TLS before anything else is sent; the handshake runs on
         * this connection when the server agrees (RFC 4511, 4.14).
         */
        rc = ldap_extended_operation(c->ld, LDAP_EXOP_START_TLS, NULL, NULL, NULL, &c->msgid);
        if (rc != LDAP_SUCCESS) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: StartTLS request failed (%d: %s)",
                rc, ldap_err2string(rc));
            ngx_http_auth_ldap_close_connection(c);
            return;
        }
        c->state = STATE_STARTTLS;
        ngx_add_timer(conn->read, c->server->bind_timeout);
        return;
    }
#endif

    ngx_http_auth_ldap_initial_bind(c);
}

/* Bind as binddn: the connection becomes usable when the server agrees. */
static void
ngx_http_auth_ldap_initial_bind(ngx_http_auth_ldap_connection_t *c)
{
    ngx_int_t rc;
    struct berval cred;

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

/*
 * TCP keepalive finds a connection that a firewall or NAT forgot while it
 * was idle: the kernel then fails the socket and the read handler reopens
 * the connection, instead of the next request waiting for request_timeout.
 */
static void
ngx_http_auth_ldap_set_keepalive(ngx_http_auth_ldap_connection_t *c, ngx_socket_t fd)
{
    int value;

    if (!c->server->so_keepalive) {
        return;
    }

#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    value = c->server->keepidle;
    if (value != 0) {
#if (NGX_KEEPALIVE_FACTOR)
        value *= NGX_KEEPALIVE_FACTOR;
#endif
        if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (const void *) &value, sizeof(int)) == -1) {
            ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno, "http_auth_ldap: setsockopt(TCP_KEEPIDLE) failed");
        }
    }

    value = c->server->keepintvl;
    if (value != 0) {
#if (NGX_KEEPALIVE_FACTOR)
        value *= NGX_KEEPALIVE_FACTOR;
#endif
        if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (const void *) &value, sizeof(int)) == -1) {
            ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno, "http_auth_ldap: setsockopt(TCP_KEEPINTVL) failed");
        }
    }

    value = c->server->keepcnt;
    if (value != 0) {
        if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, (const void *) &value, sizeof(int)) == -1) {
            ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno, "http_auth_ldap: setsockopt(TCP_KEEPCNT) failed");
        }
    }
#endif

    value = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const void *) &value, sizeof(int)) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_socket_errno, "http_auth_ldap: setsockopt(SO_KEEPALIVE) failed");
    }
}

static void
ngx_http_auth_ldap_connect_handler(ngx_event_t *wev)
{
    ngx_connection_t *conn;
    ngx_http_auth_ldap_connection_t *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0, "http_auth_ldap: Connect handler");

    conn = wev->data;
    c = conn->data;

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_auth_ldap_close_connection(c);
        return;
    }

    ngx_http_auth_ldap_set_keepalive(c, conn->fd);

#if (NGX_OPENSSL)
    if (ngx_strcmp(c->server->ludpp->lud_scheme, "ldaps") == 0) {
        ngx_http_auth_ldap_ssl_handshake(c);
        return;
    }
#endif

    ngx_http_auth_ldap_connection_established(c);
}

/*
 * The server or a firewall closed a connection that was waiting for work,
 * as servers do with idle connections (Active Directory after 15 minutes).
 * That is no outage: say so quietly and connect again at once, at most
 * once per reconnect_timeout, so that a server that drops every connection
 * right after the bind is not reconnected in a loop.
 */
static void
ngx_http_auth_ldap_idle_closed(ngx_http_auth_ldap_connection_t *c)
{
    ngx_flag_t at_once;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
        "http_auth_ldap: Server \"%V\" closed the idle connection",
        &c->server->alias);

    at_once = c->idle_reconnect == 0
              || ngx_current_msec - c->idle_reconnect >= c->server->reconnect_timeout;

    ngx_http_auth_ldap_close_connection(c);

    if (at_once) {
        c->idle_reconnect = ngx_current_msec;
        ngx_add_timer(&c->reconnect_event, 0);
    }
}

/*
 * Keep the first referral URL of a user search, from a search reference or
 * a referral result, so that the request can say where the server pointed.
 * Referrals are never chased.
 */
static void
ngx_http_auth_ldap_note_referral(ngx_http_auth_ldap_connection_t *c, char **refs)
{
    ngx_http_auth_ldap_ctx_t *ctx;
    size_t len;

    ctx = c->rctx;
    if (ctx == NULL || refs == NULL || refs[0] == NULL || ctx->referral.data != NULL) {
        return;
    }

    len = ngx_strlen(refs[0]);
    ctx->referral.data = ngx_pnalloc(ctx->r->pool, len);
    if (ctx->referral.data != NULL) {
        ngx_memcpy(ctx->referral.data, refs[0], len);
        ctx->referral.len = len;
    }
}

void
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
    char **refs;
    u_char *p;
    size_t len;

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
            if (rc == LDAP_SERVER_DOWN && c->state == STATE_READY) {
                ngx_http_auth_ldap_idle_closed(c);
                return;
            }

            ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: ldap_result() failed (%d: %s)",
                rc, ldap_err2string(rc));
            ngx_http_auth_ldap_close_connection(c);

            // if LDAP_SERVER_DOWN (usually timeouts or server disconnects)
            if (rc == LDAP_SERVER_DOWN && \
                c->down_retries < c->server->max_down_retries) {
                /* reset only after a successful initial bind */
                c->down_retries++;
                ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: LDAP_SERVER_DOWN: retry count: %ui",
                    c->down_retries);
                /*
                 * Reconnect at once, through the reconnect timer that
                 * close_connection() above has set: connecting directly
                 * used the freed event of the closed nginx connection and
                 * raced that timer.
                 */
                ngx_add_timer(&c->reconnect_event, 0);
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

        refs = NULL;
        rc = ldap_parse_result(c->ld, result, &error_code, NULL, &error_msg, &refs, NULL, 0);
        if (rc == LDAP_NO_RESULTS_RETURNED) {
            error_code = LDAP_NO_RESULTS_RETURNED;
            error_msg = NULL;
            refs = NULL;
        } else if (rc != LDAP_SUCCESS) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: ldap_parse_result() failed (%d: %s)",
                rc, ldap_err2string(rc));
            ldap_msgfree(result);
            ngx_http_auth_ldap_close_connection(c);
            return;
        }

        switch (c->state) {
#if (NGX_OPENSSL)
            case STATE_STARTTLS:
                if (ldap_msgtype(result) != LDAP_RES_EXTENDED) {
                    break;
                }
                ngx_del_timer(conn->read);
                ldap_msgfree(result);
                if (error_code != LDAP_SUCCESS) {
                    /* Never fall back to plain LDAP. */
                    ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: StartTLS refused (%d: %s [%s])",
                        error_code, ldap_err2string(error_code), error_msg ? error_msg : "-");
                    ldap_memfree(error_msg);
                    ngx_http_auth_ldap_close_connection(c);
                    return;
                }
                ldap_memfree(error_msg);
                /*
                 * The handshake calls connection_established() again. A
                 * server that never answers it is given up after
                 * connect_timeout, as for ldaps://.
                 */
                ngx_add_timer(conn->read, c->server->connect_timeout);
                ngx_http_auth_ldap_ssl_handshake(c);
                return;
#endif

            case STATE_INITIAL_BINDING:
                if (ldap_msgtype(result) != LDAP_RES_BIND) {
                    break;
                }
                ngx_del_timer(conn->read);
                if (error_code == LDAP_SUCCESS) {
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Initial bind successful");
                    c->state = STATE_READY;
                    c->server->established++;
                    c->down_retries = 0;
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
                ngx_http_auth_ldap_reply_connection(c, error_code);
                break;

            case STATE_SEARCHING:
                if (ldap_msgtype(result) == LDAP_RES_SEARCH_ENTRY) {
                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Received a search entry");
                    c->rctx->search_entries++;
                    if (c->rctx->dn.data == NULL) {
                        dn = ldap_get_dn(c->ld, result);
                        if (dn != NULL) {
                            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Found entry with DN \"%s\"", dn);
                            /* Left unset on allocation failure: the user is denied. */
                            len = ngx_strlen(dn);
                            p = ngx_pnalloc(c->rctx->r->pool, len + 1);
                            if (p != NULL) {
                                ngx_memcpy(p, dn, len + 1);
                                c->rctx->dn.data = p;
                                c->rctx->dn.len = len;
                            }
                            ldap_memfree(dn);
                        }
                    }
                } else if (ldap_msgtype(result) == LDAP_RES_SEARCH_REFERENCE) {
                    /* Never chased; kept to explain a user not found. */
                    if (ldap_parse_reference(c->ld, result, &refs, NULL, 0) == LDAP_SUCCESS) {
                        ngx_http_auth_ldap_note_referral(c, refs);
                    }
                } else if (ldap_msgtype(result) == LDAP_RES_SEARCH_RESULT) {
                    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: Received search result (%d: %s [%s])",
                        error_code, ldap_err2string(error_code), error_msg ? error_msg : "-");
                    ngx_http_auth_ldap_note_referral(c, refs);
                    ngx_http_auth_ldap_reply_connection(c, error_code);
                }
                break;

            default:
                break;
        }

        ldap_memfree(error_msg);
        ldap_memvfree((void **) refs);
        ldap_msgfree(result);

        if (c->ld == NULL) {
            /* The woken request closed the connection (a failed rebind). */
            return;
        }
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
    /* A reset is logged by the module, in context: as info when idle. */
    pconn->log_error = NGX_ERROR_INFO;

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
    conn->write->handler = ngx_http_auth_ldap_connect_handler;
    conn->read->handler = ngx_http_auth_ldap_read_handler;
    ngx_add_timer(conn->read, c->server->connect_timeout);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http_auth_ldap: connect_timeout=%d.", c->server->connect_timeout);

    c->state = STATE_CONNECTING;

    /*
     * connect() completed at once: with select or poll nginx has not
     * added the write event, so the connect handler would never run
     * (PR #617). With epoll a later write event goes to the handler the
     * connection has set by then.
     */
    if (rc == NGX_OK) {
        ngx_http_auth_ldap_connect_handler(conn->write);
    }
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

    /* A worker that shuts down only finishes the requests it has. */
    if (ngx_exiting) {
        return;
    }

    ngx_http_auth_ldap_connect(c);
}

ngx_int_t
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
        server = ((ngx_http_auth_ldap_server_t **) halmcf->servers->elts)[i];
        ngx_queue_init(&server->free_connections);
        ngx_queue_init(&server->waiting_requests);
        if (server->connections <= 1) {
            server->connections = 1;
        }
        server->conns = ngx_pcalloc(cycle->pool, server->connections * sizeof(ngx_http_auth_ldap_connection_t *));
        if (server->conns == NULL) {
            return NGX_ERROR;
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
            server->conns[j] = c;

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
            /* A worker shutting down gracefully does not wait for it. */
            c->reconnect_event.cancelable = 1;

#if (NGX_OPENSSL)
            c->ssl = &server->ssl;
#endif

            ngx_http_auth_ldap_connect(c);
        }
    }

    return NGX_OK;
}

/*
 * Close every LDAP connection of the worker when it exits. nginx reports
 * any socket still open at a graceful exit as left open, and the cycle pool
 * cleanup that would close them runs only after that check. A request still
 * on a connection (on SIGTERM) is let go first: it is never run again.
 */
void
ngx_http_auth_ldap_close_connections(ngx_cycle_t *cycle)
{
    ngx_http_auth_ldap_main_conf_t *halmcf;
    ngx_http_auth_ldap_server_t *server;
    ngx_http_auth_ldap_connection_t *c;
    ngx_uint_t i, j;

    halmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_auth_ldap_module);
    if (halmcf == NULL || halmcf->servers == NULL) {
        return;
    }

    for (i = 0; i < halmcf->servers->nelts; i++) {
        server = ((ngx_http_auth_ldap_server_t **) halmcf->servers->elts)[i];
        if (server->conns == NULL) {
            continue;
        }
        for (j = 0; j < server->connections; j++) {
            c = server->conns[j];
            if (c == NULL) {
                continue;
            }
            if (c->rctx != NULL) {
                c->rctx->c = NULL;
                c->rctx = NULL;
            }
            ngx_http_auth_ldap_close_connection(c);
        }
    }
}
