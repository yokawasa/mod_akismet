/*
 * mod_akismet.c - Apache module that enables you to detect spam comments
 * before your application handler by Akismet anti-comment-spam service
 *
 * Copyright (C) 2009 Yoichi Kawasaki All rights reserved.
 * yk55.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"      // ap_log_rerror
#include "ap_config.h"
#include "apr_strings.h"
#include <assert.h>
#include <strings.h>
#include "akismet.h"
#include <curl/curl.h>

#define MODTAG "Akismet: "
#define PARAMS_TABLE_INIT_SIZE  10
#define KEYS_ARRAY_INIT_SIZE    5
#define KEYS_ARRAY_MAX_SIZE     10

#define IS_EMPTY(a) ( (a != 0 && *a != 0) ? 0 : 1 )

module AP_MODULE_DECLARE_DATA akismet_module;

typedef struct {
    int enabled;
    char* apikey;
    char* blogurl;
    char* comment_param_key;
    char* comment_author_param_key;
    char* comment_author_email_param_key;
    char* comment_author_url_param_key;
    char* comment_permalink_param_key;
} akismet_config;

static void dump_akismet_config(request_rec *r, akismet_config *conf )
{
    if (!conf||!r) return;

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
        "dump akismet_config: enabled=%d "
        "apikey=%s "
        "blogurl=%s "
        "comment_param_key=%s "
        "comment_author_param_key=%s "
        "comment_author_email_param_key=%s "
        "comment_author_url_param_key=%s "
        "comment_permalink_param_key=%s",
        conf->enabled, conf->apikey, conf->blogurl,
        conf->comment_param_key, conf->comment_author_param_key,
        conf->comment_author_email_param_key,
        conf->comment_author_url_param_key,
        conf->comment_permalink_param_key);
}

static void dump_table_stderr(request_rec *r, apr_table_t *table)
{
    int i;
    const apr_array_header_t *tarr;
    const apr_table_entry_t *telts;
    if(table) {
        tarr = apr_table_elts(table);
        telts = (const apr_table_entry_t*)tarr->elts;
        for (i = 0; i < tarr->nelts; i++) {
            if(r) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                        "%d: key=%s, val=%s", i, telts[i].key, telts[i].val );
            } else {
                fprintf(stderr,"%d: key=%s, val=%s", i, telts[i].key, telts[i].val );
            }
        }
    }
}

static const char *set_enabled(cmd_parms *parms,
                                    void *mconfig, int arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf = ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->enabled = arg;
    } else {                    /* per-directory config */
        dconf->enabled = arg;
    }
    return NULL;
}

static const char *set_apikey(cmd_parms *parms,
                                    void *mconfig, const char *arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf = ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->apikey = (char*)arg;
    } else {                    /* per-directory config */
        dconf->apikey = (char*)arg;
    }
    return NULL;
}

static const char *set_blogurl(cmd_parms *parms,
                                    void *mconfig, const char *arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf = ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->blogurl = (char*)arg;
    } else {                    /* per-directory config */
        dconf->blogurl = (char*)arg;
    }
    return NULL;
}

static const char *set_comment_param_key(cmd_parms *parms,
                                    void *mconfig, const char *arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf = ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->comment_param_key = (char*)arg;
    } else {                    /* per-directory config */
        dconf->comment_param_key = (char*)arg;
    }
    return NULL;
}

static const char *set_comment_author_param_key(cmd_parms *parms,
                                    void *mconfig, const char *arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf = ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->comment_author_param_key = (char*)arg;
    } else {                    /* per-directory config */
        dconf->comment_author_param_key = (char*)arg;
    }
    return NULL;
}

static const char *set_comment_author_email_param_key(cmd_parms *parms,
                                    void *mconfig, const char *arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf = ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->comment_author_email_param_key = (char*)arg;
    } else {                    /* per-directory config */
        dconf->comment_author_email_param_key = (char*)arg;
    }
    return NULL;
}

static const char *set_comment_author_url_param_key(cmd_parms *parms,
                                    void *mconfig, const char *arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf = ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->comment_author_url_param_key = (char*)arg;
    } else {                    /* per-directory config */
        dconf->comment_author_url_param_key = (char*)arg;
    }
    return NULL;
}

static const char *set_comment_permalink_param_key(cmd_parms *parms,
                                    void *mconfig, const char *arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf = ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->comment_permalink_param_key = (char*)arg;
    } else {                    /* per-directory config */
        dconf->comment_permalink_param_key = (char*)arg;
    }
    return NULL;
}

static void set_default(apr_pool_t *p, akismet_config *conf)
{
    if(!conf) {
        return;
    }
    conf->enabled = 0;
    conf->apikey =NULL;
    conf->blogurl =NULL;
    conf->comment_param_key =NULL;
    conf->comment_author_param_key =NULL;
    conf->comment_author_email_param_key =NULL;
    conf->comment_author_url_param_key =NULL;
    conf->comment_permalink_param_key =NULL;
}

static void* akismet_create_dir_config(apr_pool_t *p, char *d)
{
    akismet_config* conf = apr_pcalloc(p, sizeof(akismet_config));
    set_default(p, conf);
    return conf;
}

static void* akismet_create_server_config(apr_pool_t* p, server_rec* s)
{
    akismet_config* conf = apr_pcalloc(p, sizeof(*conf) );
    set_default(p, conf);
    return conf;
}

static int parse_request_params(request_rec *r,
                akismet_config *conf, apr_table_t *params_table )
{
    char* query_string = "";
    apr_uri_t *uri = &r->parsed_uri;

    if (r->method_number == M_POST) {
        apr_bucket_brigade *brigade;
        apr_bucket *bucket;
        apr_status_t ret;

        brigade = apr_brigade_create(r->pool,r->connection->bucket_alloc);
        ret = ap_get_brigade(r->input_filters,brigade,AP_MODE_READBYTES,APR_BLOCK_READ,HUGE_STRING_LEN);
        if (ret != APR_SUCCESS) {
            return ret;
        }

        for (bucket = APR_BRIGADE_FIRST(brigade);
                bucket != APR_BRIGADE_SENTINEL(brigade);
                bucket = APR_BUCKET_NEXT(bucket)) {

            const char *data = NULL;
            apr_size_t len = 0;
            if(APR_BUCKET_IS_EOS(bucket)) {
                break;
            }
            if (APR_BUCKET_IS_FLUSH(bucket)) {
                continue;
            }
            ret=apr_bucket_read(bucket,&data,&len,APR_BLOCK_READ);
            if(ret != APR_SUCCESS) {
                return ret;
            }
            query_string = apr_pstrcat(r->pool, query_string, data,NULL);
        }
        apr_brigade_cleanup(brigade);

    } else if (r->method_number == M_GET) {
        query_string = r->parsed_uri.query;
    }
    if (!query_string) {
        return APR_SUCCESS;
    }
    /*
    * split query_string and set params tables
    */
    int i=0;
    char *next, *last;
    next =  (char*)apr_strtok( query_string, "&", &last);
    while (next) {
        apr_collapse_spaces (next, next);
        char* k, *v;
        k =  (char*)apr_strtok( next, "=", &v);
        if (k) {
            if ( ( conf->comment_param_key
                    && strcasecmp( k, conf->comment_param_key)==0)
                || ( conf->comment_author_param_key
                    && strcasecmp( k, conf->comment_author_param_key)==0)
                || (conf->comment_author_email_param_key
                    && strcasecmp( k, conf->comment_author_email_param_key)==0)
                || (conf->comment_author_url_param_key
                    && strcasecmp( k, conf->comment_author_url_param_key)==0)
                || (conf->comment_permalink_param_key
                    && strcasecmp( k, conf->comment_permalink_param_key)==0)
             ) {
                apr_table_set(params_table, k, v);
            }
        }
        next = (char*)apr_strtok(NULL, "&", &last);
    }
    return APR_SUCCESS;
}

/*
 * akismet_fixups is called to perform any module-specific fixing of header
 * fields, et cetera.  It is invoked just before any content-handler.
 *
 * The return value is OK, DECLINED, or HTTP_mumble.  If we return OK, the
 * server will still call any remaining modules with an handler for this
 * phase.
 */
static int akismet_fixups(request_rec *r)
{
    akismet_config *conf = NULL;
    akismet_config *sconf =
                (akismet_config *)ap_get_module_config(r->server->module_config,&akismet_module);
    akismet_config *dconf =
                (akismet_config *)ap_get_module_config(r->per_dir_config, &akismet_module);
    conf = dconf;

    /*
    * configuration
    * use server level config if no directory level config not defined
    */
    if ( !dconf
        || (!dconf->enabled && !dconf->apikey && !dconf->blogurl) ){
        conf = sconf;
    }

    if (!conf || !conf->enabled ) {
        return DECLINED;
    }
#ifdef AKISMET_DEBUG
dump_akismet_config(r, conf);
#endif
    /*
    *  required configuration check
    */
    if (!conf->apikey) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                MODTAG "AkismetApiKey is not specified!");
        return DECLINED;
    }
    if (!conf->blogurl) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                MODTAG "AkismetBlogURL is not specified!");
        return DECLINED;
    }
    if (!conf->comment_param_key) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                MODTAG "AkismetCommentParamKey is not specified!");
        return DECLINED;
    }

    /*
    * parse request parameters
    */
    apr_status_t ret;
    apr_table_t *params_table;
    params_table = apr_table_make(r->pool, PARAMS_TABLE_INIT_SIZE);
    ret = parse_request_params(r, conf, params_table);
    if ( ret != APR_SUCCESS
          || !params_table
          || apr_table_elts(params_table)->nelts < 1) {
        return DECLINED;
    }
#ifdef AKISMET_DEBUG
dump_table_stderr(r, params_table);
#endif

    char* comment,comment_author,comment_author_email,comment_author_url,comment_permalink;
    /*
    * required akismet api params check
    */
    if (!apr_table_get(params_table, conf->comment_param_key)) {
        return DECLINED;
    }

    /*
    * send request to akismet verify-key API
    */
    AkismetCode apicode = AKISMET_OK;
    int key_verified = 0;
    apicode =  akismet_verify_key(r, conf->apikey, conf->blogurl);
    if ( apicode == AKISMET_OK ) {
        key_verified = 1;
    } else if ( apicode == AKISMET_KEY_INVALID ) {
        key_verified = 0;
    } else {
        return DECLINED;
    }
    if ( key_verified == 0 ) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                    "Apikey is invalid! Apikey=%s", conf->apikey);
        return DECLINED;
    }

    /*
    * set akismet_comment_check_request info
    */
    akismet_comment_check_request *accr = NULL;
    accr = apr_palloc(r->pool,sizeof(akismet_comment_check_request));
    assert(accr);
    memset(accr,0,sizeof(akismet_comment_check_request));
    accr->apikey = (char *)apr_pstrdup(r->pool,conf->apikey);
    accr->blogurl = (char *)apr_pstrdup(r->pool,conf->blogurl);
    char* server_addr = r->connection->local_ip;
    char* remote_addr = r->connection->remote_ip;
    if ( strcmp(remote_addr, server_addr)==0 ) {
        accr->ip = (char *)apr_pstrdup(r->pool,remote_addr);
    } else {
        accr->ip = (char *)apr_pstrdup(r->pool, apr_table_get(r->headers_in, "X-Forwarded-For"));
    }
    accr->ua = (char *)apr_pstrdup(r->pool, apr_table_get(r->headers_in, "User-Agent"));
    accr->ref = (char *)apr_pstrdup(r->pool, apr_table_get(r->headers_in, "Referer"));
    accr->comment =
        (char *)apr_pstrdup(r->pool, apr_table_get(params_table, conf->comment_param_key));
    if (apr_table_get(params_table, conf->comment_author_param_key)) {
        accr->comment_author =
        (char *)apr_pstrdup(r->pool, apr_table_get(params_table, conf->comment_author_param_key));
    }
    if (apr_table_get(params_table, conf->comment_author_email_param_key)) {
        accr->comment_author_email =
        (char *)apr_pstrdup(r->pool, apr_table_get(params_table, conf->comment_author_email_param_key));
    }
    if (apr_table_get(params_table, conf->comment_author_url_param_key)) {
        accr->comment_author_url =
        (char *)apr_pstrdup(r->pool, apr_table_get(params_table, conf->comment_author_url_param_key));
    }
    if (apr_table_get(params_table, conf->comment_permalink_param_key)) {
        accr->comment_permalink =
        (char *)apr_pstrdup(r->pool, apr_table_get(params_table, conf->comment_permalink_param_key));
    }

    /*
    * send request to akismet comment-check API
    */
    apicode = akismet_comment_check(r, accr);
ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "akismet_comment_check=========================%d", apicode);
    if (apicode == AKISMET_SPAM) {
        /* set akismet_detect_spam flag in subprocess_env table for script language */
        apr_table_setn(r->subprocess_env, "akismet_detect_spam", conf->comment_param_key);
        /* set akismet_detect_spam flag in http header */
        apr_table_set(r->headers_in, "akismet_detect_spam", conf->comment_param_key);
    }
   return OK;
}

static void akismet_register_hooks(apr_pool_t *p)
{
    ap_hook_fixups(akismet_fixups,NULL,NULL,APR_HOOK_REALLY_FIRST);
}

static const command_rec akismet_cmds[] =
{
    AP_INIT_FLAG("AkismetEnabled", set_enabled, NULL, RSRC_CONF|ACCESS_CONF,
        "[required] Set \"On\" to enable akismet engine, \"Off\" to disable."),
    AP_INIT_TAKE1("AkismetApiKey", set_apikey, NULL, RSRC_CONF|ACCESS_CONF,
        "[required] Set the wordpress API key. (required)"),
    AP_INIT_TAKE1("AkismetBlogURL", set_blogurl, NULL, RSRC_CONF|ACCESS_CONF,
        "[required] Set the front page or home URL of your blog or wiki, etc."),
    AP_INIT_TAKE1("AkismetCommentParamKey", set_comment_param_key, NULL, RSRC_CONF|ACCESS_CONF,
        "[required] Set the param key name of the submitted comment. (required)"),
    AP_INIT_TAKE1("AkismetCommentAuthorParamKey", set_comment_author_param_key, NULL, RSRC_CONF|ACCESS_CONF,
        "[optional] Set the param key name of the submitted name with the comment"),
    AP_INIT_TAKE1("AkismetCommentAuthorEmailParamKey", set_comment_author_email_param_key, NULL, RSRC_CONF|ACCESS_CONF,
        "[optional] Set the param key name of submitted email address"),
    AP_INIT_TAKE1("AkismetCommentAuthorURLParamKey", set_comment_author_url_param_key, NULL, RSRC_CONF|ACCESS_CONF,
        "[optional] Set the param key name of the commenter URL"),
    AP_INIT_TAKE1("AkismetCommentPermalinkParamKey", set_comment_permalink_param_key, NULL, RSRC_CONF|ACCESS_CONF,
        "[optional] Set the param key name of the permalink of the entry the comment was submitted to"),
    {NULL}
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA akismet_module = {
    STANDARD20_MODULE_STUFF,
    akismet_create_dir_config,     /* create per-dir    config structures */
    NULL,                          /* merge  per-dir    config structures */
    akismet_create_server_config,  /* create per-server config structures */
    NULL,                          /* merge  per-server config structures */
    akismet_cmds,                  /* table of config file commands       */
    akismet_register_hooks         /* register hooks                      */
};

/*
 * vim:ts=4 et
 */
