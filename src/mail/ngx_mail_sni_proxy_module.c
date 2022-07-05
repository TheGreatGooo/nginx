
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

static ngx_command_t  ngx_mail_ssl_commands[] = {

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

    char                *mode;
    ngx_pool_cleanup_t  *cln;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}


static char *
ngx_mail_sni_proxy_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_mail_sni_proxy_conf_t  *spcf = conf;

    char  *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    return NGX_CONF_OK;
}
