/*
 * Test-only module: "test_connect_sync on;" (http level) makes every
 * non-blocking connect() of the process wait until the connection is
 * established and return 0, as connect() may do on some systems (a
 * loopback connect on Solaris or the BSDs, a Unix socket). nginx then gets
 * NGX_OK from ngx_event_connect_peer() instead of NGX_AGAIN, and with the
 * select or poll event methods it does not add the write event, so the
 * caller has to go on by itself. Linux never completes a non-blocking TCP
 * connect at once; this lets the suite cover that path.
 *
 * The connect() defined here takes precedence over the C library's for the
 * whole nginx binary; while the directive is off it only passes the call on.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* ngx_config.h defines the feature macros that RTLD_NEXT needs. */
#include <dlfcn.h>
#include <poll.h>


static char *ngx_http_test_connect_sync(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_flag_t  ngx_http_test_connect_sync_on;


static ngx_command_t ngx_http_test_connect_sync_commands[] = {

    { ngx_string("test_connect_sync"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_http_test_connect_sync,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t ngx_http_test_connect_sync_module_ctx = {
    NULL,                                       /* preconfiguration */
    NULL,                                       /* postconfiguration */
    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */
    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */
    NULL,                                       /* create location configuration */
    NULL                                        /* merge location configuration */
};


ngx_module_t ngx_http_test_connect_sync_module = {
    NGX_MODULE_V1,
    &ngx_http_test_connect_sync_module_ctx,
    ngx_http_test_connect_sync_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_test_connect_sync(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t  *value;

    value = cf->args->elts;
    ngx_http_test_connect_sync_on =
        (ngx_strcmp(value[1].data, "on") == 0);

    return NGX_CONF_OK;
}


int
connect(int fd, const struct sockaddr *sa, socklen_t len)
{
    int             rc, err;
    socklen_t       errlen;
    struct pollfd   pfd;
    static int    (*real)(int, const struct sockaddr *, socklen_t);

    if (real == NULL) {
        real = (int (*)(int, const struct sockaddr *, socklen_t))
                   dlsym(RTLD_NEXT, "connect");
    }

    rc = real(fd, sa, len);

    if (rc == -1 && errno == EINPROGRESS && ngx_http_test_connect_sync_on) {
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;

        if (poll(&pfd, 1, 5000) == 1) {
            err = 0;
            errlen = sizeof(err);
            (void) getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
            if (err == 0) {
                return 0;
            }
            errno = err;
            return -1;
        }

        errno = EINPROGRESS;
    }

    return rc;
}
