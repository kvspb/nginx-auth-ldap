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

/* Pool of asynchronous LDAP connections. */

#include "ngx_http_auth_ldap.h"

static void ngx_http_auth_ldap_reconnect_handler(ngx_event_t *);

/*** Asynchronous LDAP connection handling ***/

void
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
