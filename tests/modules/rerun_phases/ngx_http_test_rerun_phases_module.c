/*
 * Test-only module: "test_rerun_phases <interval>;" runs the phase engine of
 * a request again every <interval> while the request is still in its phases
 * (r->write_event_handler is ngx_http_core_run_phases and no header was
 * sent). It stands in for events that stock HTTP/1 does not produce but
 * other transports and modules do, such as an HTTP/3 MAX_STREAM_DATA frame
 * or a module that calls ngx_http_core_run_phases() itself, so that the
 * suite can check that the access handler copes with being run while its
 * LDAP operation is in flight.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_msec_t           interval;
    ngx_flag_t           unwatch_read;
} ngx_http_test_rerun_phases_loc_conf_t;


typedef struct {
    ngx_event_t          event;
    ngx_http_request_t  *request;
} ngx_http_test_rerun_phases_ctx_t;


static ngx_int_t ngx_http_test_rerun_phases_handler(ngx_http_request_t *r);
static void ngx_http_test_rerun_phases_event(ngx_event_t *ev);
static void ngx_http_test_rerun_phases_cleanup(void *data);
static void *ngx_http_test_rerun_phases_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_test_rerun_phases_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_test_rerun_phases_init(ngx_conf_t *cf);


static ngx_command_t ngx_http_test_rerun_phases_commands[] = {

    { ngx_string("test_rerun_phases"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_test_rerun_phases_loc_conf_t, interval),
      NULL },

    { ngx_string("test_unwatch_read"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_test_rerun_phases_loc_conf_t, unwatch_read),
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_test_rerun_phases_module_ctx = {
    NULL,                                       /* preconfiguration */
    ngx_http_test_rerun_phases_init,            /* postconfiguration */
    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */
    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */
    ngx_http_test_rerun_phases_create_loc_conf, /* create location configuration */
    ngx_http_test_rerun_phases_merge_loc_conf   /* merge location configuration */
};


ngx_module_t ngx_http_test_rerun_phases_module = {
    NGX_MODULE_V1,
    &ngx_http_test_rerun_phases_module_ctx,
    ngx_http_test_rerun_phases_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_test_rerun_phases_handler(ngx_http_request_t *r)
{
    ngx_pool_cleanup_t                     *cln;
    ngx_http_test_rerun_phases_ctx_t       *ctx;
    ngx_http_test_rerun_phases_loc_conf_t  *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_test_rerun_phases_module);
    if (conf->unwatch_read && r == r->main) {
        /* Simulate a preceding module that suspended client I/O. */
        if (r->connection->read->active
            && ngx_del_event(r->connection->read, NGX_READ_EVENT, 0) != NGX_OK)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        r->connection->read->ready = 0;
    }

    if (conf->interval == 0 || r != r->main
        || ngx_http_get_module_ctx(r, ngx_http_test_rerun_phases_module))
    {
        return NGX_DECLINED;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_test_rerun_phases_ctx_t));
    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (ctx == NULL || cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;
    ctx->event.handler = ngx_http_test_rerun_phases_event;
    ctx->event.data = ctx;
    ctx->event.log = r->connection->log;
    cln->handler = ngx_http_test_rerun_phases_cleanup;
    cln->data = ctx;
    ngx_http_set_ctx(r, ctx, ngx_http_test_rerun_phases_module);

    ngx_add_timer(&ctx->event, conf->interval);
    return NGX_DECLINED;
}


static void
ngx_http_test_rerun_phases_event(ngx_event_t *ev)
{
    ngx_connection_t                       *c;
    ngx_http_request_t                     *r;
    ngx_http_test_rerun_phases_ctx_t       *ctx;
    ngx_http_test_rerun_phases_loc_conf_t  *conf;

    ctx = ev->data;
    r = ctx->request;
    c = r->connection;

    if (r->header_sent || r->write_event_handler != ngx_http_core_run_phases) {
        return;
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_test_rerun_phases_module);

    /* Armed first: the run may free the request, whose pool cleanup then
     * deletes the timer before the event memory goes away. */
    ngx_add_timer(ev, conf->interval);

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "test_rerun_phases: running the phases again");
    ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(c);
}


static void
ngx_http_test_rerun_phases_cleanup(void *data)
{
    ngx_http_test_rerun_phases_ctx_t  *ctx = data;

    if (ctx->event.timer_set) {
        ngx_del_timer(&ctx->event);
    }
}


static void *
ngx_http_test_rerun_phases_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_test_rerun_phases_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_test_rerun_phases_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->interval = NGX_CONF_UNSET_MSEC;
    conf->unwatch_read = NGX_CONF_UNSET;
    return conf;
}


static char *
ngx_http_test_rerun_phases_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_test_rerun_phases_loc_conf_t  *prev = parent;
    ngx_http_test_rerun_phases_loc_conf_t  *conf = child;

    ngx_conf_merge_msec_value(conf->interval, prev->interval, 0);
    ngx_conf_merge_value(conf->unwatch_read, prev->unwatch_read, 0);
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_test_rerun_phases_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_test_rerun_phases_handler;
    return NGX_OK;
}
