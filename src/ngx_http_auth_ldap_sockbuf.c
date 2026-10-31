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

/* OpenLDAP Sockbuf_IO implementation over nginx connections. */

#include "ngx_http_auth_ldap.h"

/*** OpenLDAP SockBuf implementation over nginx socket functions ***/

static int
ngx_http_auth_ldap_sb_setup(Sockbuf_IO_Desc *sbiod, void *arg)
{
    sbiod->sbiod_pvt = arg;
    return 0;
}

static int
ngx_http_auth_ldap_sb_remove(Sockbuf_IO_Desc *sbiod)
{
    ngx_http_auth_ldap_connection_t *c = (ngx_http_auth_ldap_connection_t *)sbiod->sbiod_pvt;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_auth_ldap_sb_remove()");
    (void)c; /* 'c' would be left unused on debug builds */

    sbiod->sbiod_pvt = NULL;
    return 0;
}

static int
ngx_http_auth_ldap_sb_close(Sockbuf_IO_Desc *sbiod)
{
    ngx_http_auth_ldap_connection_t *c = (ngx_http_auth_ldap_connection_t *)sbiod->sbiod_pvt;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_auth_ldap_sb_close()");

    if (!c->conn.connection->read->error && !c->conn.connection->read->eof) {
        if (ngx_shutdown_socket(c->conn.connection->fd, SHUT_RDWR) == -1) {
            ngx_connection_error(c->conn.connection, ngx_socket_errno, ngx_shutdown_socket_n " failed");
            ngx_http_auth_ldap_close_connection(c);
            return -1;
        }
    }

    return 0;
}

static int
ngx_http_auth_ldap_sb_ctrl(Sockbuf_IO_Desc *sbiod, int opt, void *arg)
{
    ngx_http_auth_ldap_connection_t *c = (ngx_http_auth_ldap_connection_t *)sbiod->sbiod_pvt;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_auth_ldap_sb_ctrl(opt=%d)", opt);

    switch (opt) {
        case LBER_SB_OPT_DATA_READY:
            if (c->conn.connection->read->ready) {
                return 1;
            }
            return 0;
    }

    return 0;
}

static ber_slen_t
ngx_http_auth_ldap_sb_read(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
    ngx_http_auth_ldap_connection_t *c = (ngx_http_auth_ldap_connection_t *)sbiod->sbiod_pvt;
    ber_slen_t ret;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_auth_ldap_sb_read(len=%d)", len);

    ret = c->conn.connection->recv(c->conn.connection, buf, len);
    if (ret < 0) {
        errno = (ret == NGX_AGAIN) ? NGX_EAGAIN : NGX_ECONNRESET;
        return -1;
    }

    return ret;
}

static ber_slen_t
ngx_http_auth_ldap_sb_write(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
    ngx_http_auth_ldap_connection_t *c = (ngx_http_auth_ldap_connection_t *)sbiod->sbiod_pvt;
    ber_slen_t ret;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "ngx_http_auth_ldap_sb_write(len=%d)", len);

    ret = c->conn.connection->send(c->conn.connection, buf, len);
    if (ret < 0) {
        errno = (ret == NGX_AGAIN) ? NGX_EAGAIN : NGX_ECONNRESET;
        return 0;
    }

    return ret;
}

Sockbuf_IO ngx_http_auth_ldap_sbio =
{
    ngx_http_auth_ldap_sb_setup,
    ngx_http_auth_ldap_sb_remove,
    ngx_http_auth_ldap_sb_ctrl,
    ngx_http_auth_ldap_sb_read,
    ngx_http_auth_ldap_sb_write,
    ngx_http_auth_ldap_sb_close
};
