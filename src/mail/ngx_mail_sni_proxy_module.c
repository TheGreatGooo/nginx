
/*
 * Copyright (C) Srujith Kudikala
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_mail.h>

static void *ngx_mail_sni_proxy_create_conf(ngx_conf_t *cf);
static char *ngx_mail_sni_proxy_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_mail_sni_proxy_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_command_t  ngx_mail_sni_proxy_commands[] = {

    { ngx_string("sni_proxy"),
      NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_mail_sni_proxy_enable,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_sni_proxy_conf_t, enable),
      NULL },

    ngx_null_command
};


static ngx_mail_module_t  ngx_mail_sni_proxy_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_mail_sni_proxy_create_conf,        /* create server configuration */
    ngx_mail_sni_proxy_merge_conf          /* merge server configuration */
};

typedef struct {
    size_t          left;
    size_t          size;
    size_t          ext;
    u_char         *pos;
    u_char         *dst;
    u_char          buf[4];
    u_char          version[2];
    ngx_str_t       host;
    ngx_str_t       alpn;
    ngx_log_t      *log;
    ngx_pool_t     *pool;
    ngx_uint_t      state;
} ngx_mail_sni_proxy_ctx_t;

ngx_module_t  ngx_mail_sni_proxy_module = {
    NGX_MODULE_V1,
    &ngx_mail_sni_proxy_module_ctx,        /* module context */
    ngx_mail_sni_proxy_commands,           /* module directives */
    NGX_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_mail_sni_proxy_create_conf(ngx_conf_t *cf)
{
    ngx_mail_sni_proxy_conf_t  *spcf;

    spcf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_sni_proxy_conf_t));
    if (spcf == NULL) {
        return NULL;
    }

    spcf->enable = NGX_CONF_UNSET;

    return spcf;
}


static char *
ngx_mail_sni_proxy_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_mail_sni_proxy_conf_t *prev = parent;
    ngx_mail_sni_proxy_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}


static char *
ngx_mail_sni_proxy_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    return NGX_CONF_OK;
}

static void
ngx_mail_init_sni_snoop(ngx_mail_session_t *s, ngx_connection_t *c)
{
    u_char                             *last, *p;
    size_t                              len;
    ngx_int_t                           rc;
    ngx_mail_sni_proxy_ctx_t           *ctx;
    ngx_mail_sni_proxy_conf_t          *conf;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "tls preread handler");

    conf = ngx_mail_get_module_srv_conf(s, ngx_mail_sni_proxy_module);

    if (!conf->enable) {
        return NGX_DECLINED;
    }

    if (c->type != SOCK_STREAM) {
        return NGX_DECLINED;
    }

    if (c->buffer == NULL) {
        return NGX_AGAIN;
    }

    ctx = ngx_mail_get_module_ctx(s, ngx_mail_sni_proxy_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_mail_sni_proxy_module));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_stream_set_ctx(s, ctx, ngx_mail_sni_proxy_module);

        ctx->pool = c->pool;
        ctx->log = c->log;
        ctx->pos = c->buffer->pos;
    }

    p = ctx->pos;
    last = c->buffer->last;

    while (last - p >= 5) {

        if ((p[0] & 0x80) && p[2] == 1 && (p[3] == 0 || p[3] == 3)) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: version 2 ClientHello");
            ctx->version[0] = p[3];
            ctx->version[1] = p[4];
            return NGX_OK;
        }

        if (p[0] != 0x16) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: not a handshake");
            ngx_stream_set_ctx(s, NULL, ngx_stream_ssl_preread_module);
            return NGX_DECLINED;
        }

        if (p[1] != 3) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "ssl preread: unsupported SSL version");
            ngx_stream_set_ctx(s, NULL, ngx_stream_ssl_preread_module);
            return NGX_DECLINED;
        }

        len = (p[3] << 8) + p[4];

        /* read the whole record before parsing */
        if ((size_t) (last - p) < len + 5) {
            break;
        }

        p += 5;

        rc = ngx_stream_ssl_preread_parse_record(ctx, p, p + len);

        if (rc == NGX_DECLINED) {
            ngx_stream_set_ctx(s, NULL, ngx_stream_ssl_preread_module);
            return NGX_DECLINED;
        }

        if (rc != NGX_AGAIN) {
            return rc;
        }

        p += len;
    }

    ctx->pos = p;

    return NGX_AGAIN;
}
