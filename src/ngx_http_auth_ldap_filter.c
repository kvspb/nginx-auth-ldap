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

/* Escaping of values placed into LDAP search filters and DNs. */

#include "ngx_http_auth_ldap.h"

static ngx_uint_t ngx_http_auth_ldap_dn_special(ngx_str_t *value, size_t i);

/*
 * Escape a value for use inside an LDAP search filter (RFC 4515, section 3):
 * '*', '(', ')', '\' and NUL become "\XX". The result is NUL-terminated.
 */
ngx_int_t
ngx_http_auth_ldap_escape_filter_value(ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst)
{
    static u_char hex[] = "0123456789abcdef";
    u_char *p, c;
    size_t i, len;

    len = src->len;
    for (i = 0; i < src->len; i++) {
        switch (src->data[i]) {
        case '*':
        case '(':
        case ')':
        case '\\':
        case '\0':
            len += 2;
            break;
        default:
            break;
        }
    }

    dst->data = ngx_pnalloc(pool, len + 1);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    p = dst->data;
    for (i = 0; i < src->len; i++) {
        c = src->data[i];
        switch (c) {
        case '*':
        case '(':
        case ')':
        case '\\':
        case '\0':
            *p++ = '\\';
            *p++ = hex[c >> 4];
            *p++ = hex[c & 0x0f];
            break;
        default:
            *p++ = c;
            break;
        }
    }
    *p = '\0';
    dst->len = len;

    return NGX_OK;
}

/*
 * Escape a value for use as an attribute value of an RDN (RFC 4514,
 * section 2.4): '"', '+', ',', ';', '<', '>', '=' and '\' anywhere, a
 * leading '#' or space and a trailing space get a backslash. A value with
 * a NUL cannot be one of a DN passed as a C string: NGX_DECLINED.
 */
ngx_int_t
ngx_http_auth_ldap_escape_dn_value(ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst)
{
    u_char *p, c;
    size_t i, len;

    len = src->len;
    for (i = 0; i < src->len; i++) {
        c = src->data[i];
        if (c == '\0') {
            return NGX_DECLINED;
        }
        if (ngx_http_auth_ldap_dn_special(src, i)) {
            len++;
        }
    }

    dst->data = ngx_pnalloc(pool, len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    p = dst->data;
    for (i = 0; i < src->len; i++) {
        if (ngx_http_auth_ldap_dn_special(src, i)) {
            *p++ = '\\';
        }
        *p++ = src->data[i];
    }
    dst->len = len;

    return NGX_OK;
}

/* Whether byte i of an RDN value needs a backslash (RFC 4514, 2.4). */
static ngx_uint_t
ngx_http_auth_ldap_dn_special(ngx_str_t *value, size_t i)
{
    switch (value->data[i]) {
    case '"':
    case '+':
    case ',':
    case ';':
    case '<':
    case '>':
    case '=':
    case '\\':
        return 1;
    case '#':
        return i == 0;
    case ' ':
        return i == 0 || i == value->len - 1;
    default:
        return 0;
    }
}

/*
 * The number of attribute-value pairs of each RDN of a DN, in order: the
 * shape that a DN built from a template must keep whatever its variables
 * hold. NULL when the DN holds a NUL or does not parse, or when allocation
 * fails.
 */
ngx_array_t *
ngx_http_auth_ldap_dn_shape(ngx_pool_t *pool, ngx_str_t *dn)
{
    struct berval bv;
    LDAPDN parsed;
    ngx_array_t *shape;
    ngx_uint_t *n, i, j;

    if (ngx_strlchr(dn->data, dn->data + dn->len, '\0') != NULL) {
        return NULL;
    }

    bv.bv_val = (char *) dn->data;
    bv.bv_len = dn->len;
    parsed = NULL;
    if (ldap_bv2dn(&bv, &parsed, LDAP_DN_FORMAT_LDAPV3) != LDAP_SUCCESS) {
        return NULL;
    }

    shape = ngx_array_create(pool, 4, sizeof(ngx_uint_t));
    if (shape == NULL) {
        ldap_dnfree(parsed);
        return NULL;
    }

    for (i = 0; parsed != NULL && parsed[i] != NULL; i++) {
        n = ngx_array_push(shape);
        if (n == NULL) {
            ldap_dnfree(parsed);
            return NULL;
        }
        for (j = 0; parsed[i][j] != NULL; j++) { /* count */ }
        *n = j;
    }

    ldap_dnfree(parsed);
    return shape;
}
