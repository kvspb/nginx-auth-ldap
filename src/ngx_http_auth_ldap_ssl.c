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

/* TLS handshake and certificate verification for ldaps:// and StartTLS. */

#include "ngx_http_auth_ldap.h"

#if (NGX_OPENSSL)
#include <openssl/x509v3.h>

static ngx_int_t ngx_http_auth_ldap_restore_handlers(ngx_connection_t *conn);
static ngx_int_t ngx_http_auth_ldap_check_peer(ngx_http_auth_ldap_connection_t *c,
    ngx_connection_t *conn);
#endif

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

#if (NGX_OPENSSL)
static void
ngx_http_auth_ldap_ssl_handshake_handler(ngx_connection_t *conn)
{
    ngx_http_auth_ldap_connection_t *c;

    c = conn->data;

    if (!conn->ssl->handshaked) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: SSL handshake failed");
        ngx_http_auth_ldap_close_connection(c);
        return;
    }

    /* The CA certificates were loaded into c->ssl at configuration time. */
    if (c->server->ssl_check_cert && ngx_http_auth_ldap_check_peer(c, conn) != NGX_OK) {
        ngx_http_auth_ldap_close_connection(c);
        return;
    }

    conn->read->handler = &ngx_http_auth_ldap_read_handler;
    ngx_http_auth_ldap_restore_handlers(conn);
    ngx_http_auth_ldap_connection_established(c);
}

/*
 * Verify the certificate of the LDAP server: a trusted chain, and the host
 * name of the url or the address connected to in its subjectAltName.
 */
static ngx_int_t
ngx_http_auth_ldap_check_peer(ngx_http_auth_ldap_connection_t *c,
    ngx_connection_t *conn)
{
    X509                 *cert;
    long                  chain_verified;
    ngx_int_t             rc;
    struct sockaddr      *sa;
    const unsigned char  *ip;
    size_t                iplen;

    cert = SSL_get_peer_certificate(conn->ssl->connection);
    if (cert == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "http_auth_ldap: Remote side presented no SSL certificate");
        return NGX_ERROR;
    }

    rc = NGX_ERROR;

    chain_verified = SSL_get_verify_result(conn->ssl->connection);
    if (chain_verified != X509_V_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
            "http_auth_ldap: Remote side presented invalid SSL certificate: error %l, %s",
            chain_verified, X509_verify_cert_error_string(chain_verified));
        goto done;
    }

    /* RFC 9525: the subject CN is not a reference identifier. */
    if (X509_check_host(cert, c->server->ludpp->lud_host, 0,
                        X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, NULL) == 1)
    {
        rc = NGX_OK;
        goto done;
    }

    /* Not the host name: try the address connected to. */
    sa = c->conn.sockaddr;
    ip = NULL;
    iplen = 0;

    if (sa != NULL && sa->sa_family == AF_INET) {
        ip = (const unsigned char *) &((struct sockaddr_in *) sa)->sin_addr;
        iplen = 4;
#if (NGX_HAVE_INET6)
    } else if (sa != NULL && sa->sa_family == AF_INET6) {
        ip = (const unsigned char *) &((struct sockaddr_in6 *) sa)->sin6_addr;
        iplen = 16;
#endif
    }

    if (ip != NULL && X509_check_ip(cert, ip, iplen, 0) == 1) {
        rc = NGX_OK;
        goto done;
    }

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
        "http_auth_ldap: Remote side presented invalid SSL certificate: "
        "does not match address (neither server's domain nor IP in certificate's SAN)");

done:

    X509_free(cert);
    return rc;
}

void
ngx_http_auth_ldap_ssl_handshake(ngx_http_auth_ldap_connection_t *c)
{
    ngx_connection_t *conn;
    ngx_int_t rc;

    conn = c->conn.connection;
    conn->pool = c->pool;
    rc = ngx_ssl_create_connection(c->ssl, conn, NGX_SSL_BUFFER | NGX_SSL_CLIENT);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: SSL initialization failed");
        ngx_http_auth_ldap_close_connection(c);
        return;
    }

    c->log->action = "SSL handshaking to LDAP server";

    rc = ngx_ssl_handshake(conn);
    if (rc == NGX_AGAIN) {
        conn->ssl->handler = ngx_http_auth_ldap_ssl_handshake_handler;
        return;
    }

    ngx_http_auth_ldap_ssl_handshake_handler(conn);
}
#endif
