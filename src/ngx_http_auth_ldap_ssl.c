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

/* TLS handshake and certificate verification for ldaps://. */

#include "ngx_http_auth_ldap.h"

#if (NGX_OPENSSL)
static ngx_int_t ngx_http_auth_ldap_restore_handlers(ngx_connection_t *conn);
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

void
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
