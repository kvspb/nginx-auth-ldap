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

#ifndef _NGX_HTTP_AUTH_LDAP_H_INCLUDED_
#define _NGX_HTTP_AUTH_LDAP_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <nginx.h>
#include <ldap.h>


#ifndef LDAP_PROTO_EXT
/* Some OpenLDAP headers are accidentally missing ldap_init_fd() etc. */

#define LDAP_PROTO_TCP 1 /* ldap://  */
#define LDAP_PROTO_UDP 2 /* reserved */
#define LDAP_PROTO_IPC 3 /* ldapi:// */
#define LDAP_PROTO_EXT 4 /* user-defined socket/sockbuf */

extern int ldap_init_fd(ber_socket_t fd, int proto, const char *url, LDAP **ld);
#endif

#define OUTCOME_ERROR          -1 /* Some error occurred in the process */
#define OUTCOME_DENY            0
#define OUTCOME_ALLOW           1
#define OUTCOME_CACHED_DENY     2 /* Cached results */
#define OUTCOME_CACHED_ALLOW    3
#define OUTCOME_UNCERTAIN       4 /* Not yet decided */
#define OUTCOME_UNAVAILABLE     5 /* The server could not decide; not cached */

#define NGX_HTTP_AUTH_LDAP_MAX_SERVERS_SIZE 7


typedef struct {
    LDAPURLDesc *ludpp;
    ngx_str_t url;
    ngx_url_t parsed_url;
    ngx_str_t alias;
    ngx_flag_t resolve;             /* resolve the host name at run time */
    ngx_resolver_t *resolver;       /* the resolver of the http block */
    ngx_msec_t resolver_timeout;

    ngx_str_t bind_dn;
    ngx_str_t bind_dn_passwd;

    ngx_str_t group_attribute;
    ngx_flag_t group_attribute_dn;

    ngx_flag_t starttls;            /* StartTLS on an ldap:// url */
    ngx_flag_t ssl_check_cert;
    ngx_str_t ssl_ca_dir;
    ngx_str_t ssl_ca_file;
#if (NGX_OPENSSL)
    ngx_ssl_t ssl;                  /* ldaps:// or StartTLS, one per server */
#endif

    ngx_array_t *require_group;     /* array of ngx_http_complex_value_t */
    ngx_array_t *require_user;      /* array of ngx_http_complex_value_t */
    ngx_array_t *user_filter;       /* ngx_str_t: the parts of user_filter
                                       around each $remote_user; NULL when
                                       the url attribute finds the user */
    ngx_array_t *user_attributes;   /* ngx_str_t names, NUL-terminated;
                                       NULL when unset */
    char **search_attrs;            /* the same for ldap_search_ext() */
    ngx_http_complex_value_t require_valid_user_dn;
    ngx_array_t *user_dn_shape;     /* ngx_uint_t AVAs per RDN of the template,
                                       NULL when it is not a DN as written */
    ngx_uint_t remote_user_index;   /* $remote_user, with the DN template */
    ngx_flag_t satisfy_all;

    ngx_uint_t connections;
    ngx_flag_t so_keepalive;
    int keepidle;                   /* seconds; 0 for the system default */
    int keepintvl;
    int keepcnt;
    ngx_uint_t max_down_retries;
    ngx_msec_t connect_timeout;
    ngx_msec_t reconnect_timeout;
    ngx_msec_t bind_timeout;
    ngx_msec_t request_timeout;
    ngx_queue_t free_connections;
    ngx_queue_t waiting_requests;
    ngx_uint_t established;         /* connections bound as binddn, per worker */
    ngx_flag_t failing;             /* a connection failed to come up since
                                       the last one that did, per worker */
    struct ngx_http_auth_ldap_connection **conns;  /* all of them, per worker */
} ngx_http_auth_ldap_server_t;

typedef struct {
    ngx_array_t *servers;        /* array of ngx_http_auth_ldap_server_t* */
    ngx_flag_t cache_enabled;
    ngx_msec_t cache_expiration_time;
    size_t cache_size;
    ngx_int_t servers_size;
} ngx_http_auth_ldap_main_conf_t;

typedef struct {
    ngx_http_complex_value_t *realm;  /* NULL when unset; "off" turns it off */
    ngx_array_t *servers;       /* array of ngx_http_auth_ldap_server_t* */
} ngx_http_auth_ldap_loc_conf_t;

typedef struct {
    uint32_t small_hash;     /* murmur2 hash of username ^ &server       */
    uint32_t outcome;        /* OUTCOME_DENY or OUTCOME_ALLOW            */
    ngx_msec_t time;         /* ngx_current_msec when created            */
    u_char big_hash[16];     /* md5 of username, server alias and url,
                                password, expanded require templates */
    u_char *user;            /* an allow: the user DN and the values of
                                user_attributes, each a size_t length and
                                bytes (ngx_alloc); NULL for a deny */
} ngx_http_auth_ldap_cache_elt_t;

typedef struct {
    ngx_http_auth_ldap_cache_elt_t *buckets;
    ngx_uint_t num_buckets;
    ngx_uint_t elts_per_bucket;
    ngx_msec_t expiration_time;
} ngx_http_auth_ldap_cache_t;

typedef enum {
    PHASE_START,
    PHASE_SEARCH,
    PHASE_CHECK_USER,
    PHASE_CHECK_GROUP,
    PHASE_CHECK_BIND,
    PHASE_REBIND,
    PHASE_NEXT
} ngx_http_auth_ldap_request_phase_t;

typedef struct {
    ngx_http_request_t *r;
    ngx_uint_t server_index;
    ngx_http_auth_ldap_server_t *server;
    ngx_http_auth_ldap_request_phase_t phase;
    unsigned int iteration;
    int outcome;

    struct ngx_http_auth_ldap_connection *c;
    ngx_queue_t queue;
    int replied;
    int error_code;
    ngx_flag_t unavailable;  /* a server could not decide: answer 503 */
    ngx_str_t dn;
    ngx_uint_t search_entries;
    ngx_str_t referral;      /* first referral of the user search, if any */
    ngx_str_t challenge;     /* the WWW-Authenticate value of the request */
    ngx_str_t login;         /* the login escaped for the log, once set */
    ngx_str_t user_dn;

    ngx_str_t *search_attrs; /* values of user_attributes from the user
                                search of ctx->server, or NULL */
    ngx_http_auth_ldap_server_t *allowed_server;  /* NULL until allowed */
    ngx_str_t allowed_dn;    /* for $ldap_user_dn, safe for a header */
    ngx_str_t *allowed_attrs;  /* for $ldap_attr_*, per user_attributes of
                                  allowed_server, or NULL */

    ngx_http_auth_ldap_cache_elt_t *cache_bucket;
    ngx_http_auth_ldap_cache_elt_t *cache_hit;  /* entry of the last hit */
    u_char cache_big_hash[16];
    uint32_t cache_small_hash;
} ngx_http_auth_ldap_ctx_t;

typedef enum {
    STATE_DISCONNECTED,
    STATE_STARTTLS,          /* waiting for the StartTLS response */
    STATE_INITIAL_BINDING,
    STATE_CONNECTING,
    STATE_READY,
    STATE_BINDING,
    STATE_SEARCHING
} ngx_http_auth_ldap_connection_state_t;

typedef struct ngx_http_auth_ldap_connection {
    ngx_log_t *log;
    ngx_http_auth_ldap_server_t *server;
    ngx_peer_connection_t conn;
    ngx_event_t reconnect_event;

#if (NGX_OPENSSL)
    ngx_ssl_t *ssl;
#endif

    ngx_queue_t queue;
    ngx_http_auth_ldap_ctx_t *rctx;

    LDAP* ld;
    ngx_http_auth_ldap_connection_state_t state;
    int msgid;
    ngx_uint_t down_retries;    /* LDAP_SERVER_DOWN retries since the last
                                   successful initial bind */
    ngx_msec_t idle_reconnect;  /* when an idle close was last reconnected
                                   at once; 0 for never */
    ngx_resolver_ctx_t *resolving;  /* the host name being resolved */
    ngx_sockaddr_t sockaddr;    /* the address resolved for this connection */
    socklen_t socklen;
    ngx_str_t peer_name;
    u_char peer_text[NGX_SOCKADDR_STRLEN];
} ngx_http_auth_ldap_connection_t;


extern ngx_module_t ngx_http_auth_ldap_module;
extern ngx_http_auth_ldap_cache_t ngx_http_auth_ldap_cache;
extern Sockbuf_IO ngx_http_auth_ldap_sbio;

/* ngx_http_auth_ldap_conf.c */
char *ngx_http_auth_ldap_ldap_server_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_auth_ldap(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_http_auth_ldap_servers(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* ngx_http_auth_ldap_cache.c */
ngx_int_t ngx_http_auth_ldap_init_cache(ngx_cycle_t *cycle);
ngx_int_t ngx_http_auth_ldap_check_cache(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx, ngx_http_auth_ldap_cache_t *cache, ngx_http_auth_ldap_server_t *server);
void ngx_http_auth_ldap_update_cache(ngx_http_auth_ldap_ctx_t *ctx, ngx_http_auth_ldap_cache_t *cache, ngx_flag_t outcome);
ngx_int_t ngx_http_auth_ldap_restore_user(ngx_http_auth_ldap_ctx_t *ctx, ngx_http_auth_ldap_server_t *server);

/* ngx_http_auth_ldap_connection.c */
void ngx_http_auth_ldap_close_connection(ngx_http_auth_ldap_connection_t *c);
void ngx_http_auth_ldap_close_request_connection(ngx_http_auth_ldap_ctx_t *ctx);
int ngx_http_auth_ldap_get_connection(ngx_http_auth_ldap_ctx_t *ctx);
void ngx_http_auth_ldap_return_connection(ngx_http_auth_ldap_connection_t *c);
void ngx_http_auth_ldap_unqueue_request(ngx_http_auth_ldap_ctx_t *ctx);
void ngx_http_auth_ldap_wake_next(ngx_http_auth_ldap_server_t *server);
void ngx_http_auth_ldap_dummy_write_handler(ngx_event_t *wev);
void ngx_http_auth_ldap_connection_established(ngx_http_auth_ldap_connection_t *c);
void ngx_http_auth_ldap_read_handler(ngx_event_t *rev);
ngx_int_t ngx_http_auth_ldap_init_connections(ngx_cycle_t *cycle);
void ngx_http_auth_ldap_close_connections(ngx_cycle_t *cycle);

/* ngx_http_auth_ldap_ssl.c */
#if (NGX_OPENSSL)
void ngx_http_auth_ldap_ssl_handshake(ngx_http_auth_ldap_connection_t *c);
#endif

/* ngx_http_auth_ldap_auth.c */
ngx_int_t ngx_http_auth_ldap_handler(ngx_http_request_t *r);
void ngx_http_auth_ldap_entry_attributes(ngx_http_auth_ldap_ctx_t *ctx, LDAP *ld, LDAPMessage *entry);
ngx_int_t ngx_http_auth_ldap_user_dn_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t ngx_http_auth_ldap_attr_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

/* ngx_http_auth_ldap_filter.c */
ngx_int_t ngx_http_auth_ldap_escape_filter_value(ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst);
ngx_int_t ngx_http_auth_ldap_escape_dn_value(ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst);
ngx_array_t *ngx_http_auth_ldap_dn_shape(ngx_pool_t *pool, ngx_str_t *dn);

#endif /* _NGX_HTTP_AUTH_LDAP_H_INCLUDED_ */
