
/*
 * Copyright (C) Srujith Kudikala
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_mail.h>



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
    ngx_buf_t       *tls_header;
} ngx_mail_sni_proxy_ctx_t;

static void *ngx_mail_sni_proxy_create_conf(ngx_conf_t *cf);
static char *ngx_mail_sni_proxy_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t
ngx_mail_init_sni_preread(ngx_mail_session_t *s, ngx_connection_t *c);

static char *ngx_mail_sni_proxy_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void
ngx_mail_sni_proxy_block_read(ngx_event_t *rev);
static void
ngx_mail_sni_proxy_handle_upsteam_read(ngx_event_t *wev);
static ngx_int_t
ngx_mail_sni_proxy_starttls_response(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc);
static ngx_int_t
ngx_mail_sni_proxy_read_helo_response(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc, ngx_uint_t next_state);
static ngx_int_t
ngx_mail_sni_proxy_read_uptream_greeting(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc, ngx_uint_t next_state);
static void
ngx_mail_sni_proxy_handle_upsteam_read(ngx_event_t *wev);
static void
ngx_mail_sni_proxy_handle_upsteam_write(ngx_event_t *wev);
static ngx_int_t
ngx_mail_sni_proxy_send_hello_upstream(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc);
static ngx_int_t
ngx_mail_sni_proxy_send_xclient(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc);
static ngx_int_t
ngx_mail_sni_proxy_send_starttls(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc);
static ngx_int_t
ngx_mail_sni_proxy_send_tls_handshake(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc);
static void
ngx_mail_sni_close_session(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc);
static void
ngx_mail_sni_proxy_handler(ngx_event_t *ev);
static void
ngx_mail_sni_proxy_handler_resolved(ngx_event_t *ev, ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc);


static ngx_command_t  ngx_mail_sni_proxy_commands[] = {

    { ngx_string("sni_proxy"),
      NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_mail_sni_proxy_enable,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_sni_proxy_conf_t, enable),
      NULL },
    { ngx_string("sni_proxy_buffer"),
      NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_size_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_sni_proxy_conf_t, buffer_size),
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
    spcf->buffer_size = NGX_CONF_UNSET_SIZE;

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

    ctx = ngx_mail_get_module_ctx(s, ngx_mail_sni_proxy_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_mail_sni_proxy_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_mail_set_ctx(s, ctx, ngx_mail_sni_proxy_module);

        ctx->pool = c->pool;
        ctx->log = c->log;
        ctx->pos = s->buffer->pos;
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
        ctx->tls_header = ngx_create_temp_buf(c->pool, n);
        ngx_memcpy(ctx->tls_header->start, s->buffer->pos, n);
        ctx->tls_header->last += n;
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
            ctx->pos = NULL;
            s->buffer->pos = s->buffer->start;
            s->buffer->last = s->buffer->start;
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

    spc->upstream.type = SOCK_STREAM;
    spc->upstream.sockaddr = peer->sockaddr;
    spc->upstream.socklen = peer->socklen;
    spc->upstream.name = &peer->name;
    spc->upstream.get = ngx_event_get_peer;
    spc->upstream.log = s->connection->log;
    spc->upstream.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&spc->upstream);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    ngx_add_timer(spc->upstream.connection->read, cscf->timeout);

    spc->upstream.connection->data = s;
    spc->upstream.connection->pool = s->connection->pool;

    s->connection->read->handler = ngx_mail_sni_proxy_block_read;
    spc->upstream.connection->write->handler = ngx_mail_sni_proxy_handle_upsteam_write;

    spf = ngx_mail_get_module_srv_conf(s, ngx_mail_sni_proxy_module);

    spc->proxy_buffer = ngx_create_temp_buf(s->connection->pool,
                                           spf->buffer_size);
    if (spc->proxy_buffer == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    s->out.len = 0;
    spc->upstream.connection->read->handler = ngx_mail_sni_proxy_handle_upsteam_read;
    s->state = ngx_smtp_start;

    if (rc == NGX_AGAIN) {
        return;
    }
}

static void
ngx_mail_sni_proxy_block_read(ngx_event_t *rev)
{
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy block read");

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c = rev->data;
        s = c->data;

        ngx_mail_session_internal_server_error(s);
    }
}

static void
ngx_mail_sni_proxy_handle_upsteam_read(ngx_event_t *wev)
{
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;
    ngx_mail_sni_proxy_ctx_t  *spc;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, wev->log, 0, "mail proxy sni read handler upstream");

    c = wev->data;
    s = c->data;

    spc = ngx_mail_get_module_ctx(s, ngx_mail_sni_proxy_module);
    if (spc == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    switch (s->state)
    {
        case ngx_smtp_start:
            ngx_mail_sni_proxy_read_uptream_greeting(s, spc, ngx_smtp_helo);
            break;
        case ngx_smtp_helo:
            ngx_mail_sni_proxy_read_helo_response(s, spc, ngx_smtp_helo_xclient);
            break;
        case ngx_smtp_helo_xclient:
            ngx_mail_sni_proxy_read_uptream_greeting(s, spc, ngx_smtp_xclient_helo);
            break;
        case ngx_smtp_xclient_helo:
            ngx_mail_sni_proxy_read_helo_response(s, spc, ngx_smtp_starttls);
            break;
        case ngx_smtp_starttls:
            if (ngx_mail_sni_proxy_starttls_response(s, spc) == NGX_OK ){
                ngx_str_null(&s->smtp_helo);
                ngx_str_null(&s->smtp_from);
                ngx_str_null(&s->smtp_to);
                s->connection->read->handler = ngx_mail_sni_proxy_handler;
                spc->upstream.connection->read->handler = ngx_mail_sni_proxy_handler;
            }
            break;
        default:
            break;
    }

    switch (s->state)
    {
        case ngx_smtp_helo:
            ngx_mail_sni_proxy_send_hello_upstream(s, spc);
            break;
        case ngx_smtp_helo_xclient:
            ngx_mail_sni_proxy_send_xclient(s, spc);
            break;
        case ngx_smtp_xclient_helo:
            ngx_mail_sni_proxy_send_hello_upstream(s, spc);
            break;
        case ngx_smtp_starttls:
            ngx_mail_sni_proxy_send_starttls(s, spc);
            break;
        case ngx_smtp_proxy_tls_handshake:
            ngx_mail_sni_proxy_send_tls_handshake(s, spc);
            s->state = ngx_smtp_proxy_tls;
            break;
        default:
            break;
    }
}

static ngx_int_t
ngx_mail_sni_proxy_send_tls_handshake(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc)
{
    ngx_connection_t  *c;

    s->connection->log->action = "sending TLS handshake to upstream";

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                "mail sni proxy sending TLS handshake to upstream");

    c = spc->upstream.connection;
    c->send(c, spc->tls_header->pos, spc->tls_header->last-spc->tls_header->pos);
    return NGX_OK;
}

static void
ngx_mail_sni_proxy_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;
    ngx_mail_sni_proxy_ctx_t  *spc;

    c = ev->data;
    s = c->data;

    spc = ngx_mail_get_module_ctx(s, ngx_mail_sni_proxy_module);
    if (spc == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    ngx_mail_sni_proxy_handler_resolved(ev, s, spc);
}

static void
ngx_mail_sni_proxy_handler_resolved(ngx_event_t *ev, ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc)
{
    char                   *action, *recv_action, *send_action;
    size_t                  size;
    ssize_t                 n;
    ngx_buf_t              *b;
    ngx_uint_t              do_write;
    ngx_connection_t       *c, *src, *dst;

    c = ev->data;

    if (ev->timedout || c->close) {
        c->log->action = "proxying";

        if (c->close) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "shutdown timeout");

        } else if (c == s->connection) {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "client timed out");
            c->timedout = 1;

        } else {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "upstream timed out");
        }

        ngx_mail_sni_close_session(s, spc);
        return;
    }

    if (c == s->connection) {
        if (ev->write) {
            recv_action = "proxying and reading from upstream";
            send_action = "proxying and sending to client";
            src = spc->upstream.connection;
            dst = c;
            b = spc->proxy_buffer;

        } else {
            recv_action = "proxying and reading from client";
            send_action = "proxying and sending to upstream";
            src = c;
            dst = spc->upstream.connection;
            b = s->buffer;
        }

    } else {
        if (ev->write) {
            recv_action = "proxying and reading from client";
            send_action = "proxying and sending to upstream";
            src = s->connection;
            dst = c;
            b = s->buffer;

        } else {
            recv_action = "proxying and reading from upstream";
            send_action = "proxying and sending to client";
            src = c;
            dst = s->connection;
            b = spc->proxy_buffer;
        }
    }

    do_write = ev->write ? 1 : 0;

    ngx_log_debug3(NGX_LOG_DEBUG_MAIL, ev->log, 0,
                   "mail proxy handler: %ui, #%d > #%d",
                   do_write, src->fd, dst->fd);

    for ( ;; ) {

        if (do_write) {

            size = b->last - b->pos;

            if (size && dst->write->ready) {
                c->log->action = send_action;

                n = dst->send(dst, b->pos, size);

                if (n == NGX_ERROR) {
                    ngx_mail_sni_close_session(s, spc);
                    return;
                }

                if (n > 0) {
                    b->pos += n;

                    if (b->pos == b->last) {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready) {
            c->log->action = recv_action;

            n = src->recv(src, b->last, size);

            if (n == NGX_AGAIN || n == 0) {
                break;
            }

            if (n > 0) {
                do_write = 1;
                b->last += n;

                continue;
            }

            if (n == NGX_ERROR) {
                src->read->eof = 1;
            }
        }

        break;
    }

    c->log->action = "proxying";

    if ((s->connection->read->eof && s->buffer->pos == s->buffer->last)
        || (spc->upstream.connection->read->eof
            && spc->proxy_buffer->pos == spc->proxy_buffer->last)
        || (s->connection->read->eof
            && spc->upstream.connection->read->eof))
    {
        action = c->log->action;
        c->log->action = NULL;
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "proxied session done");
        c->log->action = action;

        ngx_mail_sni_close_session(s, spc);
        return;
    }

    if (ngx_handle_write_event(dst->write, 0) != NGX_OK) {
        ngx_mail_sni_close_session(s, spc);
        return;
    }

    if (ngx_handle_read_event(dst->read, 0) != NGX_OK) {
        ngx_mail_sni_close_session(s, spc);
        return;
    }

    if (ngx_handle_write_event(src->write, 0) != NGX_OK) {
        ngx_mail_sni_close_session(s, spc);
        return;
    }

    if (ngx_handle_read_event(src->read, 0) != NGX_OK) {
        ngx_mail_sni_close_session(s, spc);
        return;
    }

    /*if (c == s->connection) {
        ngx_add_timer(c->read, pcf->timeout);
    }*/
}

static void
ngx_mail_sni_close_session(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc)
{
    if (spc->upstream.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       spc->upstream.connection->fd);

        ngx_close_connection(spc->upstream.connection);
    }

    ngx_mail_close_connection(s->connection);
}

static ngx_int_t
ngx_mail_sni_proxy_starttls_response(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc)
{
    ssize_t            n;
    u_char*            p;

    n = spc->upstream.connection->recv(
        spc->upstream.connection,
        spc->proxy_buffer->last,
        spc->proxy_buffer->end - spc->proxy_buffer->last);
    
    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(spc->upstream.connection->read, 0) != NGX_OK) {
            ngx_mail_session_internal_server_error(s);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (n == NGX_ERROR) {
        ngx_mail_session_internal_server_error(s);
        return NGX_ERROR;
    }

    p = spc->proxy_buffer->pos;

    if (p[0] == '2' && p[1] == '2' && p[2] == '0') {
        s->state = ngx_smtp_proxy_tls_handshake;
        return NGX_OK;
    }

    //unexpected state
    ngx_mail_session_internal_server_error(s);
    return NGX_ERROR;
}

static ngx_int_t
ngx_mail_sni_proxy_read_helo_response(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc, ngx_uint_t next_state)
{
    ssize_t            n;
    u_char*            p;

    n = spc->upstream.connection->recv(
        spc->upstream.connection,
        spc->proxy_buffer->last,
        spc->proxy_buffer->end - spc->proxy_buffer->last);
    
    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(spc->upstream.connection->read, 0) != NGX_OK) {
            ngx_mail_session_internal_server_error(s);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (n == NGX_ERROR) {
        ngx_mail_session_internal_server_error(s);
        return NGX_ERROR;
    }

    p = spc->proxy_buffer->pos;

    if (p[0] == '2' && p[1] == '5' && p[2] == '0') {
        s->state = next_state;
        return NGX_OK;
    }

    //unexpected state
    ngx_mail_session_internal_server_error(s);
    return NGX_ERROR;
}

static ngx_int_t
ngx_mail_sni_proxy_read_uptream_greeting(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc, ngx_uint_t next_state)
{
    ssize_t            n;
    u_char*            p;

    n = spc->upstream.connection->recv(
        spc->upstream.connection,
        spc->proxy_buffer->last,
        spc->proxy_buffer->end - spc->proxy_buffer->last);
    
    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(spc->upstream.connection->read, 0) != NGX_OK) {
            ngx_mail_session_internal_server_error(s);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (n == NGX_ERROR) {
        ngx_mail_session_internal_server_error(s);
        return NGX_ERROR;
    }

    if (n == 0) {
        return NGX_AGAIN;
    }

    p = spc->proxy_buffer->pos;

    if (p[0] == '2' && p[1] == '2' && p[2] == '0') {
        s->state = next_state;
        return NGX_OK;
    }

    //unexpected state
    ngx_mail_session_internal_server_error(s);
    return NGX_ERROR;
}

static void
ngx_mail_sni_proxy_handle_upsteam_write(ngx_event_t *wev)
{
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, wev->log, 0, "mail proxy sni write handler upstream");

    c = wev->data;
    s = c->data;

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_mail_session_internal_server_error(s);
    }

    if (c->read->ready) {
        ngx_post_event(c->read, &ngx_posted_events);
    }
}

static ngx_int_t
ngx_mail_sni_proxy_send_xclient(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc)
{
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    s->connection->log->action = "sending XCLIENT to upstream";

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                "mail sni proxy sending XCLIENT to upstream");

    c = spc->upstream.connection;
    b = spc->proxy_buffer;
    b->last = ngx_cpymem(b->last, "XCLIENT ADDR=", sizeof("XCLIENT ADDR=") - 1);
    b->last = ngx_copy(b->last, s->connection->addr_text.data,
                     s->connection->addr_text.len);
    b->last = ngx_cpymem(b->last, " NAME=", sizeof(" NAME=") - 1);
    b->last = ngx_copy(b->last, s->host.data, s->host.len);
    b->last = ngx_cpymem(b->last, "\n", 1);
    c->send(c, b->pos, b->last-b->pos);
    b->pos = b->start;
    b->last = b->start;
    return NGX_OK;
}

static ngx_int_t
ngx_mail_sni_proxy_send_starttls(ngx_mail_session_t *s, ngx_mail_sni_proxy_ctx_t  *spc)
{
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    s->connection->log->action = "sending STARTTLS to upstream";

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                "mail sni proxy sending STARTTLS to upstream");

    c = spc->upstream.connection;
    b = spc->proxy_buffer;
    b->last = ngx_cpymem(b->last, "STARTTLS\n", 9);
    c->send(c, b->pos, b->last-b->pos);
    b->pos = b->start;
    b->last = b->start;
    return NGX_OK;
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
    b->last = ngx_cpymem(b->last, s->smtp_helo.data, s->smtp_helo.len);
    b->last = ngx_cpymem(b->last, "\n", 1);
    c->send(c, b->pos, b->last-b->pos);
    b->pos = b->start;
    b->last = b->start;

    return NGX_OK;
}