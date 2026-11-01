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
static ngx_flag_t ngx_http_auth_ldap_is_address(const char *host);
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
 * of the url in its subjectAltName.
 */
static ngx_int_t
ngx_http_auth_ldap_check_peer(ngx_http_auth_ldap_connection_t *c,
    ngx_connection_t *conn)
{
    X509                 *cert;
    long                  chain_verified;
    ngx_int_t             rc;
    const char           *host;

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

    /*
     * The reference identity is the host of the url (RFC 9525): a name
     * matches a DNS subjectAltName only, never the subject CN, and an
     * address an IP subjectAltName only. An IP SAN of the address a name
     * resolved to does not vouch for the name.
     */
    host = c->server->ludpp->lud_host;
    if (host != NULL
        && (ngx_http_auth_ldap_is_address(host)
            ? X509_check_ip_asc(cert, host, 0)
            : X509_check_host(cert, host, 0, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, NULL)) == 1)
    {
        rc = NGX_OK;
        goto done;
    }

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
        "http_auth_ldap: Remote side presented invalid SSL certificate: "
        "does not match address \"%s\" (not in its subjectAltName)", host != NULL ? host : "");

done:

    X509_free(cert);
    return rc;
}

/* Whether the host of the url is an IPv4 or IPv6 address, not a name. */
static ngx_flag_t
ngx_http_auth_ldap_is_address(const char *host)
{
    u_char buf[sizeof(struct in6_addr)];

    return host == NULL
           || inet_pton(AF_INET, host, buf) == 1
#if (NGX_HAVE_INET6)
           || inet_pton(AF_INET6, host, buf) == 1
#endif
           ;
}

void
ngx_http_auth_ldap_ssl_handshake(ngx_http_auth_ldap_connection_t *c)
{
    ngx_connection_t *conn;
    ngx_int_t rc;

    conn = c->conn.connection;
    /*
     * The TLS state of this connection lives in a pool of its own, which
     * close_connection() destroys: from the cycle pool, every reconnect
     * left one behind for the life of the worker (audit F17).
     */
    conn->pool = ngx_create_pool(512, c->log);
    if (conn->pool == NULL) {
        ngx_http_auth_ldap_close_connection(c);
        return;
    }
    rc = ngx_ssl_create_connection(c->ssl, conn, NGX_SSL_BUFFER | NGX_SSL_CLIENT);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: SSL initialization failed");
        ngx_http_auth_ldap_close_connection(c);
        return;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    /*
     * SNI, so that a server with several certificates on one address can
     * pick the one for this host. Never for an address (RFC 6066, 3).
     */
    if (!ngx_http_auth_ldap_is_address(c->server->ludpp->lud_host)
        && SSL_set_tlsext_host_name(conn->ssl->connection, c->server->ludpp->lud_host) != 1)
    {
        ngx_ssl_error(NGX_LOG_ERR, c->log, 0, "http_auth_ldap: SSL_set_tlsext_host_name() failed");
        ngx_http_auth_ldap_close_connection(c);
        return;
    }
#endif

    c->log->action = "SSL handshaking to LDAP server";

    rc = ngx_ssl_handshake(conn);
    if (rc == NGX_AGAIN) {
        conn->ssl->handler = ngx_http_auth_ldap_ssl_handshake_handler;
        return;
    }

    ngx_http_auth_ldap_ssl_handshake_handler(conn);
}
#endif
