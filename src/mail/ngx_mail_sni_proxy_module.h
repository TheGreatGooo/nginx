
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
} ngx_mail_sni_proxy_conf_t;

extern ngx_module_t  ngx_mail_sni_proxy_module;


#endif /* _NGX_MAIL_SNI_PROXY_H_INCLUDED__ */
