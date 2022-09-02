
/*
 * Copyright (C) Srujith Kudikala
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_mail.h>

static void *ngx_mail_sni_proxy_create_conf(ngx_conf_t *cf);
static char *ngx_mail_sni_proxy_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t
ngx_mail_init_sni_preread(ngx_mail_session_t *s, ngx_connection_t *c);

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
    ngx_peer_connection_t upstream;
    ngx_buf_t              *proxy_buffer;
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

static ngx_int_t
ngx_mail_sni_proxy_parse_record(ngx_mail_sni_proxy_ctx_t *ctx,
    u_char *pos, u_char *last);

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

ngx_int_t
ngx_mail_init_sni_snoop(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_int_t                          rc;
    ngx_mail_sni_proxy_ctx_t           *ctx;

    rc = ngx_mail_init_sni_preread(s, c);

    if (rc == NGX_AGAIN){
        return rc;
    }
    if (rc != NGX_OK){
        c->log->action = "bad tls client hello closing connection";
        ngx_mail_close_connection(c);
    }

    ctx = ngx_mail_get_module_ctx(s, ngx_mail_sni_proxy_module);

    if (ctx->host.len == 0){
        c->log->action = "tls sni not found";
        ngx_mail_close_connection(c);
    }

    s->host.data = ngx_pstrdup(c->pool, &ctx->host);
    s->host.len = ctx->host.len;
    ngx_mail_auth_http_init(s);
    return rc;
}

static ngx_int_t
ngx_mail_init_sni_preread(ngx_mail_session_t *s, ngx_connection_t *c)
{
    u_char                             *last, *p;
    size_t                              len;
    ngx_int_t                           rc;
    ngx_mail_sni_proxy_ctx_t           *ctx;
    ngx_mail_sni_proxy_conf_t          *conf;
    ssize_t                             n;

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "tls preread handler");

    conf = ngx_mail_get_module_srv_conf(s, ngx_mail_sni_proxy_module);

    if (!conf->enable) {
        return NGX_DECLINED;
    }

    if (c->type != SOCK_STREAM) {
        return NGX_DECLINED;
    }

    if (s->buffer == NULL) {
        return NGX_AGAIN;
    }

    if (s->buffer->last < s->buffer->end) {

        n = c->recv(c, s->buffer->last, s->buffer->end - s->buffer->last);

        if (n == NGX_ERROR || n == 0) {
            ngx_mail_close_connection(c);
            return NGX_ERROR;
        }

        if (n > 0) {
            s->buffer->last += n;
        }

        if (n == NGX_AGAIN) {
            if (s->buffer->pos == s->buffer->last) {
                return NGX_AGAIN;
            }
        }
    }

    ctx = ngx_mail_get_module_ctx(s, ngx_mail_sni_proxy_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_mail_sni_proxy_module));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_mail_set_ctx(s, ctx, ngx_mail_sni_proxy_module);

        ctx->pool = c->pool;
        ctx->log = c->log;
        ctx->pos = s->buffer->pos;
    }

    p = ctx->pos;
    last = s->buffer->last;

    while (last - p >= 5) {

        if ((p[0] & 0x80) && p[2] == 1 && (p[3] == 0 || p[3] == 3)) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "tls preread: version 2 ClientHello");
            ctx->version[0] = p[3];
            ctx->version[1] = p[4];
            return NGX_OK;
        }

        if (p[0] != 0x16) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "tls preread: not a handshake");
            ngx_mail_set_ctx(s, NULL, ngx_mail_sni_proxy_module);
            return NGX_DECLINED;
        }

        if (p[1] != 3) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "tls preread: unsupported SSL version");
            ngx_mail_set_ctx(s, NULL, ngx_mail_sni_proxy_module);
            return NGX_DECLINED;
        }

        len = (p[3] << 8) + p[4];

        /* read the whole record before parsing */
        if ((size_t) (last - p) < len + 5) {
            break;
        }

        p += 5;

        rc = ngx_mail_sni_proxy_parse_record(ctx, p, p + len);

        if (rc == NGX_DECLINED) {
            ngx_mail_set_ctx(s, NULL, ngx_mail_sni_proxy_module);
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

static ngx_int_t
ngx_mail_sni_proxy_parse_record(ngx_mail_sni_proxy_ctx_t *ctx,
    u_char *pos, u_char *last)
{
    size_t   left, n, size, ext;
    u_char  *dst, *p;

    enum {
        sw_start = 0,
        sw_header,          /* handshake msg_type, length */
        sw_version,         /* client_version */
        sw_random,          /* random */
        sw_sid_len,         /* session_id length */
        sw_sid,             /* session_id */
        sw_cs_len,          /* cipher_suites length */
        sw_cs,              /* cipher_suites */
        sw_cm_len,          /* compression_methods length */
        sw_cm,              /* compression_methods */
        sw_ext,             /* extension */
        sw_ext_header,      /* extension_type, extension_data length */
        sw_sni_len,         /* SNI length */
        sw_sni_host_head,   /* SNI name_type, host_name length */
        sw_sni_host,        /* SNI host_name */
        sw_alpn_len,        /* ALPN length */
        sw_alpn_proto_len,  /* ALPN protocol_name length */
        sw_alpn_proto_data, /* ALPN protocol_name */
        sw_supver_len       /* supported_versions length */
    } state;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                   "tls preread: state %ui left %z", ctx->state, ctx->left);

    state = ctx->state;
    size = ctx->size;
    left = ctx->left;
    ext = ctx->ext;
    dst = ctx->dst;
    p = ctx->buf;

    for ( ;; ) {
        n = ngx_min((size_t) (last - pos), size);

        if (dst) {
            dst = ngx_cpymem(dst, pos, n);
        }

        pos += n;
        size -= n;
        left -= n;

        if (size != 0) {
            break;
        }

        switch (state) {

        case sw_start:
            state = sw_header;
            dst = p;
            size = 4;
            left = size;
            break;

        case sw_header:
            if (p[0] != 1) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                               "tls preread: not a client hello");
                return NGX_DECLINED;
            }

            state = sw_version;
            dst = ctx->version;
            size = 2;
            left = (p[1] << 16) + (p[2] << 8) + p[3];
            break;

        case sw_version:
            state = sw_random;
            dst = NULL;
            size = 32;
            break;

        case sw_random:
            state = sw_sid_len;
            dst = p;
            size = 1;
            break;

        case sw_sid_len:
            state = sw_sid;
            dst = NULL;
            size = p[0];
            break;

        case sw_sid:
            state = sw_cs_len;
            dst = p;
            size = 2;
            break;

        case sw_cs_len:
            state = sw_cs;
            dst = NULL;
            size = (p[0] << 8) + p[1];
            break;

        case sw_cs:
            state = sw_cm_len;
            dst = p;
            size = 1;
            break;

        case sw_cm_len:
            state = sw_cm;
            dst = NULL;
            size = p[0];
            break;

        case sw_cm:
            if (left == 0) {
                /* no extensions */
                return NGX_OK;
            }

            state = sw_ext;
            dst = p;
            size = 2;
            break;

        case sw_ext:
            if (left == 0) {
                return NGX_OK;
            }

            state = sw_ext_header;
            dst = p;
            size = 4;
            break;

        case sw_ext_header:
            if (p[0] == 0 && p[1] == 0 && ctx->host.data == NULL) {
                /* SNI extension */
                state = sw_sni_len;
                dst = p;
                size = 2;
                break;
            }

            if (p[0] == 0 && p[1] == 16 && ctx->alpn.data == NULL) {
                /* ALPN extension */
                state = sw_alpn_len;
                dst = p;
                size = 2;
                break;
            }

            if (p[0] == 0 && p[1] == 43) {
                /* supported_versions extension */
                state = sw_supver_len;
                dst = p;
                size = 1;
                break;
            }

            state = sw_ext;
            dst = NULL;
            size = (p[2] << 8) + p[3];
            break;

        case sw_sni_len:
            ext = (p[0] << 8) + p[1];
            state = sw_sni_host_head;
            dst = p;
            size = 3;
            break;

        case sw_sni_host_head:
            if (p[0] != 0) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                               "tls preread: SNI hostname type is not DNS");
                return NGX_DECLINED;
            }

            size = (p[1] << 8) + p[2];

            if (ext < 3 + size) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                               "tls preread: SNI format error");
                return NGX_DECLINED;
            }
            ext -= 3 + size;

            ctx->host.data = ngx_pnalloc(ctx->pool, size);
            if (ctx->host.data == NULL) {
                return NGX_ERROR;
            }

            state = sw_sni_host;
            dst = ctx->host.data;
            break;

        case sw_sni_host:
            ctx->host.len = (p[1] << 8) + p[2];

            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "tls preread: SNI hostname \"%V\"", &ctx->host);

            state = sw_ext;
            dst = NULL;
            size = ext;
            break;

        case sw_alpn_len:
            ext = (p[0] << 8) + p[1];

            ctx->alpn.data = ngx_pnalloc(ctx->pool, ext);
            if (ctx->alpn.data == NULL) {
                return NGX_ERROR;
            }

            state = sw_alpn_proto_len;
            dst = p;
            size = 1;
            break;

        case sw_alpn_proto_len:
            size = p[0];

            if (size == 0) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                               "tls preread: ALPN empty protocol");
                return NGX_DECLINED;
            }

            if (ext < 1 + size) {
                ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                               "tls preread: ALPN format error");
                return NGX_DECLINED;
            }
            ext -= 1 + size;

            state = sw_alpn_proto_data;
            dst = ctx->alpn.data + ctx->alpn.len;
            break;

        case sw_alpn_proto_data:
            ctx->alpn.len += p[0];

            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "tls preread: ALPN protocols \"%V\"", &ctx->alpn);

            if (ext) {
                ctx->alpn.data[ctx->alpn.len++] = ',';

                state = sw_alpn_proto_len;
                dst = p;
                size = 1;
                break;
            }

            state = sw_ext;
            dst = NULL;
            size = 0;
            break;

        case sw_supver_len:
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "tls preread: supported_versions");

            /* set TLSv1.3 */
            ctx->version[0] = 3;
            ctx->version[1] = 4;

            state = sw_ext;
            dst = NULL;
            size = p[0];
            break;
        }

        if (left < size) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, ctx->log, 0,
                           "tls preread: failed to parse handshake");
            return NGX_DECLINED;
        }
    }

    ctx->state = state;
    ctx->size = size;
    ctx->left = left;
    ctx->ext = ext;
    ctx->dst = dst;

    return NGX_AGAIN;
}

void
ngx_mail_sni_proxy_connection_init(ngx_mail_session_t *s, ngx_addr_t *peer)
{
    ngx_int_t                  rc;
    ngx_mail_sni_proxy_ctx_t  *spc;
    ngx_mail_sni_proxy_conf_t *spf;
    ngx_mail_core_srv_conf_t  *cscf;

    s->connection->log->action = "connecting to upstream";

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    spc = ngx_mail_get_module_ctx(s, ngx_mail_sni_proxy_module);
    if (spc == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    spc->upstream.sockaddr = peer->sockaddr;
    spc->upstream.socklen = peer->socklen;
    spc->upstream.name = &peer->name;
    spc->upstream.get = ngx_event_get_peer;
    spc->upstream.log = s->connection->log;
    spc->upstream.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&spc->upstream);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    ngx_add_timer(spc->upstream.connection->read, cscf->timeout);

    spc->upstream.connection->data = s;
    spc->upstream.connection->pool = s->connection->pool;

    s->connection->read->handler = ngx_mail_proxy_block_read;
    spc->upstream.connection->write->handler = ngx_mail_sni_proxy_handle_upsteam_write;

    spf = ngx_mail_get_module_srv_conf(s, ngx_mail_sni_proxy_module);

    spc->proxy_buffer = ngx_create_temp_buf(s->connection->pool,
                                           spf->buffer_size);
    if (spc->proxy_buffer == NULL) {
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    s->out.len = 0;
    spc->upstream.connection->read->handler = ngx_mail_sni_proxy_handle_upsteam;
    s->state = ngx_smtp_start;

    if (rc == NGX_AGAIN) {
        return;
    }

    ngx_mail_sni_proxy_handle_upsteam_write(spc->upstream.connection->write);
}

static void
ngx_mail_sni_proxy_handle_upsteam_write(ngx_event_t *wev)
{
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;
    ngx_mail_sni_proxy_ctx_t  *spc;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, wev->log, 0, "mail proxy sni write handler upstream");

    c = wev->data;
    s = c->data;

    spc = ngx_mail_get_module_ctx(s, ngx_mail_sni_proxy_module);
    if (spc == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    switch (s->state)
    {
    case ngx_smtp_helo:
        ngx_mail_sni_proxy_send_hello_upstream(s, spc);
        break;
    
    default:
        break;
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_mail_proxy_internal_server_error(s);
    }

    if (c->read->ready) {
        ngx_post_event(c->read, &ngx_posted_events);
    }
}

static ngx_int_t
ngx_mail_sni_proxy_send_hello_upstream(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc)
{
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    s->connection->log->action = "sending SMTP HELO to upstream";

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                "mail sni proxy sending SMTP HELO to upstream");

    c = spc->upstream.connection;
    b = spc->proxy_buffer;
    b->pos = b->start;
    b->last = b->start;
    ngx_cpymem(b->last, "HELO ", 5);
    b->last += 5;
    //TODO validate buffer is atleast the size of host + 5
    ngx_cpymem(b->last, s->host.data, s->host.len);
    b->last += s->host.len;
    c->send(c, b->pos, b->last-b->pos);
}