/**
 * Copyright (C) 2011 Valery Komarov <komarov@valerka.net>
 *
 * Based on nginx's 'ngx_http_auth_basic_module.c' by Igor Sysoev,
 * 'ngx_http_auth_pam_module.c' by Sergio Talens-Oliag and other more
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ldap.h>

typedef struct {
    ngx_str_t passwd;
} ngx_http_auth_ldap_ctx_t;

typedef struct {
    ngx_str_t username;
    ngx_str_t password;
} ngx_ldap_userinfo;

typedef struct {
    LDAPURLDesc *ludpp;
    ngx_str_t url;
    ngx_str_t realm;

    ngx_str_t bind_dn;
    ngx_str_t bind_dn_passwd;

    ngx_str_t group_attribute;
    ngx_flag_t group_attribute_dn;

    ngx_array_t *require_group;
    ngx_array_t *require_user;
    ngx_flag_t satisfy_all;
} ngx_http_auth_ldap_loc_conf_t;

static char * ngx_http_auth_ldap_url(ngx_conf_t *, ngx_command_t *, void *);
static char * ngx_http_auth_ldap_satisfy(ngx_conf_t *, ngx_command_t *, void *);
static char * ngx_http_auth_ldap_require(ngx_conf_t *, ngx_command_t *, void *);

static ngx_int_t ngx_http_auth_ldap_init(ngx_conf_t *cf);
static void * ngx_http_auth_basic_create_loc_conf(ngx_conf_t *);
static char * ngx_http_auth_ldap_merge_loc_conf(ngx_conf_t *, void *, void *);
static ngx_int_t ngx_http_auth_ldap_set_realm(ngx_http_request_t *r, ngx_str_t *realm);
static ngx_ldap_userinfo* ngx_http_auth_ldap_get_user_info(ngx_http_request_t *);
static ngx_int_t ngx_http_auth_ldap_authenticate(ngx_http_request_t *, ngx_http_auth_ldap_ctx_t *,
    ngx_str_t *, ngx_http_auth_ldap_loc_conf_t *);
static char * ngx_http_auth_ldap(ngx_conf_t *cf, void *post, void *data);
static ngx_conf_post_handler_pt ngx_http_auth_ldap_p = ngx_http_auth_ldap;

static ngx_command_t ngx_http_auth_ldap_commands[] = {
    {
        ngx_string("auth_ldap"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_ldap_loc_conf_t, realm),
        &ngx_http_auth_ldap_p },
    {
        ngx_string("auth_ldap_url"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
        ngx_http_auth_ldap_url,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
    {
        ngx_string("auth_ldap_binddn"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_ldap_loc_conf_t, bind_dn),
        NULL },
    {
        ngx_string("auth_ldap_binddn_passwd"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_ldap_loc_conf_t, bind_dn_passwd),
        NULL },
    {
        ngx_string("auth_ldap_require"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE2,
        ngx_http_auth_ldap_require,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
    {
        ngx_string("auth_ldap_satisfy"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
        ngx_http_auth_ldap_satisfy,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
    {
        ngx_string("auth_ldap_group_attribute"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_ldap_loc_conf_t, group_attribute),
        NULL },
    {
        ngx_string("auth_ldap_group_attribute_is_dn"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_ldap_loc_conf_t, group_attribute_dn),
        NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_auth_ldap_module_ctx = {
    NULL, /* preconfiguration */
    ngx_http_auth_ldap_init, /* postconfiguration */
    NULL, /* create main configuration */
    NULL, /* init main configuration */
    NULL, /* create server configuration */
    NULL, /* merge server configuration */
    ngx_http_auth_basic_create_loc_conf, /* create location configuration */
    ngx_http_auth_ldap_merge_loc_conf /* merge location configuration */
};

ngx_module_t ngx_http_auth_ldap_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_ldap_module_ctx, /* module context */
    ngx_http_auth_ldap_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING };

static char *
ngx_http_auth_ldap_url(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_auth_ldap_loc_conf_t *alcf = conf;
    ngx_str_t *value;
    u_char *p;

    value = cf->args->elts;

    int rc = ldap_url_parse((const char*) value[1].data, &alcf->ludpp);
    if (rc != LDAP_SUCCESS) {
	switch (rc) {
	case LDAP_URL_ERR_MEM:
	    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Cannot allocate memory space.");
	    break;

	case LDAP_URL_ERR_PARAM:
	    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Invalid parameter.");
	    break;

	case LDAP_URL_ERR_BADSCHEME:
	    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: URL doesnt begin with \"ldap[s]://\".");
	    break;

	case LDAP_URL_ERR_BADENCLOSURE:
	    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: URL is missing trailing \">\".");
	    break;

	case LDAP_URL_ERR_BADURL:
	    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Invalid URL.");
	    break;

	case LDAP_URL_ERR_BADHOST:
	    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Host port is invalid.");
	    break;

	case LDAP_URL_ERR_BADATTRS:
	    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Invalid or missing attributes.");
	    break;

	case LDAP_URL_ERR_BADSCOPE:
	    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Invalid or missing scope string.");
	    break;

	case LDAP_URL_ERR_BADFILTER:
	    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Invalid or missing filter.");
	    break;

	case LDAP_URL_ERR_BADEXTS:
	    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: Invalid or missing extensions.");
	    break;
	}
		return NGX_CONF_ERROR;
    }

    if (alcf->ludpp->lud_attrs == NULL) {
    	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "LDAP: No attrs in auth_ldap_url.");
    	return NGX_CONF_ERROR;
    }

    alcf->url.len=ngx_strlen(alcf->ludpp->lud_scheme) + ngx_strlen(alcf->ludpp->lud_host)+11; // 11 = len("://:/") + len("65535") + len("\0")
    alcf->url.data = ngx_pcalloc(cf->pool, alcf->url.len);
    p=ngx_sprintf(alcf->url.data, "%s://%s:%d/", (const char*)alcf->ludpp->lud_scheme,
    		(const char*)alcf->ludpp->lud_host, alcf->ludpp->lud_port);
    *p = 0;

    return NGX_CONF_OK;
}

static char *
ngx_http_auth_ldap_satisfy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_auth_ldap_loc_conf_t *alcf = conf;
    ngx_str_t *value;
    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "all") == 0) {
	alcf->satisfy_all = 1;
	return NGX_CONF_OK;
    }

    if (ngx_strcmp(value[1].data, "any") == 0) {
	alcf->satisfy_all = 0;
	return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Incorrect value for auth_ldap_satisfy ");
    return NGX_CONF_ERROR;
}

static char *
ngx_http_auth_ldap_require(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_auth_ldap_loc_conf_t *alcf = conf;

    ngx_str_t *value, *rule;
    value = cf->args->elts;

    if (alcf->require_user == NULL) {
	alcf->require_user = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
	if (alcf->require_user == NULL) {
	    return NGX_CONF_ERROR;
	}
    }

    if (alcf->require_group == NULL) {
	alcf->require_group = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
	if (alcf->require_group == NULL) {
	    return NGX_CONF_ERROR;
	}
    }

    if (ngx_strcmp(value[1].data, "user") == 0) {
	rule = ngx_array_push(alcf->require_user);
	if (rule == NULL) {
	    return NGX_CONF_ERROR;
	}
	rule->data = value[2].data;
	rule->len = value[2].len;
    }

    if (ngx_strcmp(value[1].data, "group") == 0) {
	rule = ngx_array_push(alcf->require_group);
	if (rule == NULL) {
	    return NGX_CONF_ERROR;
	}
	rule->data = value[2].data;
	rule->len = value[2].len;
    }

    return NGX_CONF_OK;
}

static void *
ngx_http_auth_basic_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_auth_ldap_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_ldap_loc_conf_t));
    if (conf == NULL) {
	return NULL;
    }
    conf->satisfy_all = NGX_CONF_UNSET;
    conf->group_attribute_dn = NGX_CONF_UNSET;
    return conf;
}

static char *
ngx_http_auth_ldap_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_auth_ldap_loc_conf_t *prev = parent;
    ngx_http_auth_ldap_loc_conf_t *conf = child;

    if (conf->realm.data == NULL) {
        conf->realm = prev->realm;
    }

    ngx_conf_merge_str_value(conf->url, prev->url, "ldap://localhost/");
    ngx_conf_merge_str_value(conf->bind_dn, prev->bind_dn, "");
    ngx_conf_merge_str_value(conf->bind_dn_passwd, prev->bind_dn_passwd, "");
    ngx_conf_merge_str_value(conf->group_attribute, prev->group_attribute, "member");

    ngx_conf_merge_value(conf->satisfy_all, prev->satisfy_all,0);
    ngx_conf_merge_value(conf->group_attribute_dn, prev->group_attribute_dn,1);

    if (conf->require_user == NULL) {
	conf->require_user = prev->require_user;
    }

    if (conf->require_group == NULL) {
	conf->require_group = prev->require_group;
    }

    if (conf->ludpp == NULL) {
	conf->ludpp = prev->ludpp;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_auth_ldap_handler(ngx_http_request_t *r) {
    int rc;
    ngx_http_auth_ldap_ctx_t *ctx;
    ngx_http_auth_ldap_loc_conf_t *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_ldap_module);

    if (alcf->realm.len == 0) {
	return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_auth_ldap_module);

    if (ctx) {
	return ngx_http_auth_ldap_authenticate(r, ctx, &ctx->passwd, alcf);
    }

    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {
	return ngx_http_auth_ldap_set_realm(r, &alcf->realm);
    }

    if (rc == NGX_ERROR) {
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_auth_ldap_authenticate(r, ctx, &ctx->passwd, alcf);
}

/**
 * Get login and password from http request.
 */
static ngx_ldap_userinfo*
ngx_http_auth_ldap_get_user_info(ngx_http_request_t *r) {
    size_t len;
    ngx_ldap_userinfo* uinfo;
    u_char *uname_buf, *p;

    uinfo = ngx_palloc(r->pool, sizeof(ngx_ldap_userinfo));

    for (len = 0; len < r->headers_in.user.len; len++) {
	if (r->headers_in.user.data[len] == ':') {
	    break;
	}
    }
    uname_buf = ngx_palloc(r->pool, len + 1);
    if (uname_buf == NULL) {
	return NULL;
    }
    p = ngx_cpymem(uname_buf, r->headers_in.user.data, len);
    *p = '\0';

    uinfo->username.data = uname_buf;
    uinfo->username.len = len;
    uinfo->password.data = r->headers_in.passwd.data;
    uinfo->password.len = r->headers_in.passwd.len;

    return uinfo;
}

static ngx_int_t
ngx_http_auth_ldap_authenticate(ngx_http_request_t *r, ngx_http_auth_ldap_ctx_t *ctx,
    ngx_str_t *passwd, ngx_http_auth_ldap_loc_conf_t *conf) {

    LDAP *ld;
    LDAPMessage *searchResult;
    LDAPURLDesc *ludpp = conf->ludpp;
    int version = LDAP_VERSION3;
    struct berval bvalue;
    struct timeval timeOut = {
	10,
	0 };
    int reqcert = LDAP_OPT_X_TLS_ALLOW;

    int rc;
    int isSecure = 0;
    ngx_uint_t i;
    ngx_str_t *value;
    ngx_ldap_userinfo *uinfo;
    ngx_uint_t pass = 0;
    char *dn;
    u_char *p, *filter;

    if (conf->ludpp == NULL) {
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uinfo = ngx_http_auth_ldap_get_user_info(r);
    if (uinfo == NULL) {
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /// Set LDAP version to 3 and set connection timeout.
    ldap_set_option(NULL, LDAP_OPT_PROTOCOL_VERSION, &version);
    ldap_set_option(NULL, LDAP_OPT_NETWORK_TIMEOUT, &timeOut);

    rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &reqcert);
    if (rc != LDAP_OPT_SUCCESS) {
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "LDAP: unable to set require cert option: %s",
	    ldap_err2string(rc));
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /// Get the URL scheme ( either ldap or ldaps )
    if (0 == ngx_strcmp(ludpp->lud_scheme, "ldaps"))
	isSecure = 1;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: URL: %s", conf->url.data);

    rc = ldap_initialize(&ld, (const char*)conf->url.data);
    if (rc != LDAP_SUCCESS) {
    	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "LDAP: Session initializing failed: %d, %s, (%s)",
    			rc, ldap_err2string(rc), (const char*)conf->url.data);
    	return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: Session initialized", NULL);

    /// Bind to the server
    rc = ldap_simple_bind_s(ld, (const char *) conf->bind_dn.data, (const char *) conf->bind_dn_passwd.data);
    if (rc != LDAP_SUCCESS) {
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "LDAP: ldap_simple_bind_s error: %d, %s", rc,
	    ldap_err2string(rc));
	ldap_unbind_s(ld);
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: Bind successful", NULL);

    /// Create filter for search users by uid
    filter = ngx_pcalloc(r->pool, ngx_strlen(ludpp->lud_filter)+ ngx_strlen("(&(=))")
	    + ngx_strlen(ludpp->lud_attrs[0]) + uinfo->username.len +1);
    p = ngx_sprintf(filter, "(&%s(%s=%s))", ludpp->lud_filter,ludpp->lud_attrs[0], uinfo->username.data);
    *p = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: filter %s", (const char*) filter);

    /// Search the directory
    rc = ldap_search_ext_s(ld, ludpp->lud_dn, ludpp->lud_scope, (const char*) filter, NULL, 0,
	NULL, NULL, &timeOut, 0, &searchResult);

    if (rc != LDAP_SUCCESS) {
	ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "LDAP: ldap_search_ext_s: %d, %s", rc,
	    ldap_err2string(rc));
	ldap_msgfree(searchResult);
	ldap_unbind_s(ld);
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ldap_count_entries(ld, searchResult) > 0) {
	dn = ldap_get_dn(ld, searchResult);
	if (dn != NULL) {
	    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: result DN %s", dn);

	    /// Check require user
	    value = conf->require_user->elts;
	    for (i = 0; i < conf->require_user->nelts; i++) {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: compare with: %s",
		    value[i].data);
		if (ngx_strncmp(value[i].data, dn, value[i].len) == 0) {
		    pass = 1;
		    if (conf->satisfy_all == 0) {
			break;
		    }
		} else {
		    if (conf->satisfy_all == 1) {
			ldap_memfree(dn);
			ldap_msgfree(searchResult);
			ldap_unbind_s(ld);
			return ngx_http_auth_ldap_set_realm(r, &conf->realm);
		    }
		}
	    }

	    /// Check require group
	    if (conf->group_attribute_dn == 1)
	    {
		bvalue.bv_val = dn;
		bvalue.bv_len = ngx_strlen(dn);
	    } else {
		bvalue.bv_val = (char*) uinfo->username.data;
		bvalue.bv_len = uinfo->username.len;
	    }

	    value = conf->require_group->elts;
	    for (i = 0; i < conf->require_group->nelts; i++) {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: compare with: %s",
		    value[i].data);

		rc = ldap_compare_ext_s(ld, (const char*) value[i].data,
			(const char*) conf->group_attribute.data,
			&bvalue, NULL, NULL);

		if (rc != LDAP_COMPARE_TRUE && rc != LDAP_COMPARE_FALSE) {
		    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "LDAP: ldap_search_ext_s: %d, %s", rc,
			ldap_err2string(rc));
		    ldap_memfree(dn);
		    ldap_msgfree(searchResult);
		    ldap_unbind_s(ld);
		    return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		if (rc == LDAP_COMPARE_TRUE) {
		    pass = 1;
		    if (conf->satisfy_all == 0) {
			break;
		    }
		} else {
		    if (conf->satisfy_all == 1) {
			pass = 0;
			break;
		    }
		}
	    }

	    if (pass == 1) {
		/// Bind user to the server
		rc = ldap_simple_bind_s(ld, dn, (const char *) uinfo->password.data);
		if (rc != LDAP_SUCCESS) {
		    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
			"LDAP: ldap_simple_bind_s error: %d, %s", rc, ldap_err2string(rc));
		    pass = 0;
		}
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "LDAP: User bind successful", NULL);
	    }
	}
	ldap_memfree(dn);
    }

    ldap_msgfree(searchResult);
    ldap_unbind_s(ld);

    if (pass == 0) {
	return ngx_http_auth_ldap_set_realm(r, &conf->realm);
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_ldap_set_realm(ngx_http_request_t *r, ngx_str_t *realm) {
    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->key.len = sizeof("WWW-Authenticate") - 1;
    r->headers_out.www_authenticate->key.data = (u_char *) "WWW-Authenticate";
    r->headers_out.www_authenticate->value = *realm;

    return NGX_HTTP_UNAUTHORIZED;
}

static char *
ngx_http_auth_ldap(ngx_conf_t *cf, void *post, void *data) {
    ngx_str_t *realm = data;

    size_t len;
    u_char *basic, *p;

    if (ngx_strcmp(realm->data, "off") == 0) {
	realm->len = 0;
	realm->data = (u_char *) "";

	return NGX_CONF_OK;
    }

    len = sizeof("Basic realm=\"") - 1 + realm->len + 1;

    basic = ngx_pcalloc(cf->pool, len);
    if (basic == NULL) {
	return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';

    realm->len = len;
    realm->data = basic;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_auth_ldap_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
	return NGX_ERROR;
    }

    *h = ngx_http_auth_ldap_handler;
    return NGX_OK;
}
