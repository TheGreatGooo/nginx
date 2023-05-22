
/*
 * Copyright (C) Srujith Kudikala
 */


#ifndef _NGX_MAIL_SNI_PROXY_H_INCLUDED_
#define _NGX_MAIL_SNI_PROXY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_mail.h>

typedef struct {
    ngx_flag_t       enable;
    size_t      buffer_size;
} ngx_mail_sni_proxy_conf_t;

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

extern ngx_module_t  ngx_mail_sni_proxy_module;


#endif /* _NGX_MAIL_SNI_PROXY_H_INCLUDED__ */
