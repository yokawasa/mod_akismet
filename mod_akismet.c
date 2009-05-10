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

#include "apr_global_mutex.h"
#include "apr_shm.h"
#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#include <assert.h>
#include <strings.h>
#include "akismet.h"
#include <curl/curl.h>

#define MODTAG "Akismet: "
#define PARAMS_TABLE_INIT_SIZE       10
#define KEY_VERFIED_TABLE_INIT_SIZE   5

#define IS_EMPTY(a) ( (a != 0 && *a != 0) ? 0 : 1 )

static const char akismet_filter_name[] = "Akismet_Input_Filter";
module AP_MODULE_DECLARE_DATA akismet_module;

typedef struct {
    apr_bucket_brigade *tmp_brigade;
} AkismetFilterContext;

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

/* table definitions */
typedef struct {
    char key[1024];         /* key string of "apikey-blogurl" */
    int  status;            /* -1-not yet,  0-invalid, 1-verfied */
} key_verified_info;
static key_verified_info *key_verified_infos;

#define NUM_BUCKETS 10
#define API_CACHE_SHM_SIZE (apr_size_t)(NUM_BUCKETS * sizeof(key_verified_info))

static apr_shm_t      *api_cache_shm =  NULL;   /* the APR shared segment object */
static apr_global_mutex_t *global_lock = NULL;  /* the cross-thread/cross-process mutex */
static char api_cache_shm_file[1024];
static char global_lock_file[1024];

static apr_status_t
 cleanup_shm_resources(void *dummy)
{
    if (api_cache_shm) {
        apr_shm_destroy(api_cache_shm);
        api_cache_shm = NULL;
    }
    if (global_lock) {
        apr_global_mutex_destroy(global_lock);
        global_lock = NULL;
    }
    return APR_SUCCESS;
}

static int
 get_status_from_api_cache_shm(request_rec *r, const char* key, int* status)
{
    int v = 0; /*no record */
    int i;
    if (!api_cache_shm) {
        return -1;  /* some problem on shm init!! */
    }
    for (i = 0; i < NUM_BUCKETS; i++) {
        if (key_verified_infos[i].status!=-1) {
            if (strcmp(key_verified_infos[i].key, key)==0 ) {
                *status = key_verified_infos[i].status;
                v = 1;  /* has record */
                break;
            }
        }
    }
    return v;
}

static int
 set_status_to_api_cache_shm( request_rec *r, const char* key, int status)
{
    int i;
    int st;
    apr_status_t ret;
    if (status < 0) {
        return 0;  /* no record set or update */
    }
    if (!api_cache_shm) {
        return -1; /* some problem on shm init!! */
    }
    ret = apr_global_mutex_lock(global_lock);
    if (ret != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, ret, r, "apr_global_mutex_lock failed!");
        return -1; /* some problem on mutex */
    }
    if (get_status_from_api_cache_shm(r, key, &st) == 1) {
        return 0;  /* no record set or update */
    }
    for (i = 0; i < NUM_BUCKETS; i++) {
        if (key_verified_infos[i].status==-1) {
            apr_cpystrn( key_verified_infos[i].key, key, strlen(key)+1);
            key_verified_infos[i].status = status;
            break;
        }
    }
    ret = apr_global_mutex_unlock(global_lock);
    if (ret != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, ret, r, "apr_global_mutex_unlock failed!");
        return -1;
    }
    return 1; /* good */
}

static void
 dump_akismet_config(request_rec *r, akismet_config *conf )
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
                conf->enabled,
                conf->apikey,
                conf->blogurl,
                conf->comment_param_key,
                conf->comment_author_param_key,
                conf->comment_author_email_param_key,
                conf->comment_author_url_param_key,
                conf->comment_permalink_param_key);
}

static void
 dump_apr_table(request_rec *r, apr_table_t *table)
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

static const char*
 set_enabled(cmd_parms *parms, void *mconfig, int arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf =
            ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->enabled = arg;
    } else {                    /* per-directory config */
        dconf->enabled = arg;
    }
    return NULL;
}

static const char*
 set_shmfile(cmd_parms *parms, void *mconfig, const char *arg)
{
    akismet_config *sconf =
            ap_get_module_config(parms->server->module_config, &akismet_module);
    memset(api_cache_shm_file, 0, strlen(api_cache_shm_file) );
    apr_cpystrn( api_cache_shm_file,  arg, strlen(arg)+1);
    return NULL;
}

static const char*
 set_lockfile(cmd_parms *parms, void *mconfig, const char *arg)
{
    akismet_config *sconf =
            ap_get_module_config(parms->server->module_config, &akismet_module);
    memset(global_lock_file, 0, strlen(global_lock_file) );
    apr_cpystrn( global_lock_file,  arg, strlen(arg)+1);
    return NULL;
}

static const char*
 set_apikey(cmd_parms *parms, void *mconfig, const char *arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf =
            ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->apikey = (char*)arg;
    } else {                    /* per-directory config */
        dconf->apikey = (char*)arg;
    }
    return NULL;
}

static const char*
 set_blogurl(cmd_parms *parms, void *mconfig, const char *arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf =
            ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->blogurl = (char*)arg;
    } else {                    /* per-directory config */
        dconf->blogurl = (char*)arg;
    }
    return NULL;
}

static const char*
 set_comment_param_key(cmd_parms *parms, void *mconfig, const char *arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf =
            ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->comment_param_key = (char*)arg;
    } else {                    /* per-directory config */
        dconf->comment_param_key = (char*)arg;
    }
    return NULL;
}

static const char*
 set_comment_author_param_key(cmd_parms *parms, void *mconfig, const char *arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf =
            ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->comment_author_param_key = (char*)arg;
    } else {                    /* per-directory config */
        dconf->comment_author_param_key = (char*)arg;
    }
    return NULL;
}

static const char*
 set_comment_author_email_param_key(cmd_parms *parms, void *mconfig, const char *arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf =
            ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->comment_author_email_param_key = (char*)arg;
    } else {                    /* per-directory config */
        dconf->comment_author_email_param_key = (char*)arg;
    }
    return NULL;
}

static const char*
 set_comment_author_url_param_key(cmd_parms *parms, void *mconfig, const char *arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf =
            ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->comment_author_url_param_key = (char*)arg;
    } else {                    /* per-directory config */
        dconf->comment_author_url_param_key = (char*)arg;
    }
    return NULL;
}

static const char*
 set_comment_permalink_param_key(cmd_parms *parms, void *mconfig, const char *arg)
{
    akismet_config *dconf = mconfig;
    akismet_config *sconf =
            ap_get_module_config(parms->server->module_config, &akismet_module);
    if (parms->path == NULL) {  /* server config */
        sconf->comment_permalink_param_key = (char*)arg;
    } else {                    /* per-directory config */
        dconf->comment_permalink_param_key = (char*)arg;
    }
    return NULL;
}

static void
 set_default(apr_pool_t *p, akismet_config *conf)
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

static void*
 akismet_create_dir_config(apr_pool_t *p, char *d)
{
    akismet_config* conf = apr_pcalloc(p, sizeof(akismet_config));
    set_default(p, conf);
    return conf;
}

static void*
 akismet_create_server_config(apr_pool_t* p, server_rec* s)
{
    akismet_config* conf = apr_pcalloc(p, sizeof(*conf) );
    set_default(p, conf);
    return conf;
}

/*
* shm init. it should be called in ap_hook_post_config phase
* code partially from mod_auth_digest.c
*/
static int
 shm_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t ret;
    void *data;
    const char *userdata_key = "akismet_dummy_key";

    /* initialize_module() will be called twice, and if it's a DSO
     * then all static data from the first call will be lost. Only
     * set up our static data on the second call. */
    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        apr_pool_userdata_set((const void *)1, userdata_key,
                               apr_pool_cleanup_null, s->process->pool);
        return OK; /* This would be the first time through */
    }

    if ( ret = apr_shm_create(&api_cache_shm,
                            API_CACHE_SHM_SIZE,
                            api_cache_shm_file, p) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, ret, s,
                "Failed to create shared segment file '%s'", api_cache_shm_file );
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ret = apr_global_mutex_create(&global_lock,
                         global_lock_file, APR_LOCK_DEFAULT, p) != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, ret, s,
                "Failed to create global mutex file '%s'", global_lock_file);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

#ifdef AP_NEED_SET_MUTEX_PERMS
    if( ret = unixd_set_global_mutex_perms(global_lock) != APR_SUCCESS ) {
        ap_log_perror(APLOG_MARK, APLOG_CRIT, ret, p,
            "%s:Failed to set mutex permission. "
            "please check out parent process's privileges!");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
#endif

    key_verified_infos = apr_shm_baseaddr_get(api_cache_shm);
    if (!key_verified_infos) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, -1, s,
                        "failed to allocate shared memory" );
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    /* Clear all key_verified_info */
    int i;
    for (i = 0; i < NUM_BUCKETS; i++) {
        key_verified_infos[i].status = -1;
        memset(key_verified_infos[i].key, 0, 1024);
    }
    /* Register a cleanup function */
    apr_pool_cleanup_register(p, NULL, cleanup_shm_resources, apr_pool_cleanup_null);
    return OK;
}

static int
 akismet_post_config(apr_pool_t *p, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s) {
    return shm_init(p,s);
}

static void
 akismet_child_init(apr_pool_t *p, server_rec *s)
{
    apr_status_t ret;
    if (!api_cache_shm) {
        return;
    }
    ret = apr_global_mutex_child_init(&global_lock, global_lock_file, p);
    if (ret != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, ret, s,
                                   "failed to create lock (global_lock)");
        cleanup_shm_resources(NULL);
        return;
    }
    if(!api_cache_shm) {
        ret = apr_shm_attach( &api_cache_shm, api_cache_shm_file, p);
        if (ret != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, ret, s,
                 "Failed to attach to shared memory file '%s'", api_cache_shm_file);
            return;
        }
    }
    key_verified_infos = apr_shm_baseaddr_get(api_cache_shm);
}

static void
 akismet_insert_filter(request_rec *r)
{
    akismet_config *conf = NULL;
    akismet_config *sconf =NULL;
    akismet_config *dconf =NULL;

    /*
    * decide configuration
    * use server level config if no directory level config not defined
    */
    sconf =
        (akismet_config *)ap_get_module_config(r->server->module_config,&akismet_module);
    dconf =
        (akismet_config *)ap_get_module_config(r->per_dir_config, &akismet_module);
    conf = dconf;
    if ( !dconf
        || (!dconf->enabled && !dconf->apikey && !dconf->blogurl) ){
        conf = sconf;
    }

    if (!conf || !conf->enabled || !api_cache_shm_file || !global_lock_file) {
        return;
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
        return;
    }
    if (!conf->blogurl) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                MODTAG "AkismetBlogURL is not specified!");
        return;
    }
    if (!conf->comment_param_key) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                MODTAG "AkismetCommentParamKey is not specified!");
        return;
    }
    ap_add_input_filter(akismet_filter_name,NULL,r,r->connection);
}

static apr_status_t
 akismet_api_execute(request_rec *r, akismet_config *conf, apr_table_t *params_table )
{
    char *comment =NULL;
    char *comment_author =NULL;
    char *comment_author_email =NULL;
    char *comment_author_url = NULL;
    char *comment_permalink =NULL;
    int key_verified = -1;
    int shm_update_skip = 0;
    char *key_verified_s = NULL;
    AkismetCode apicode = AKISMET_OK;
    akismet_comment_check_request *accr = NULL;
    char *server_addr = NULL;
    char *remote_addr = NULL;

    /*
    * params_table check
    */
    if ( !params_table || apr_table_elts(params_table)->nelts < 1) {
        return APR_SUCCESS; //skip
    }
#ifdef AKISMET_DEBUG
dump_apr_table(r, params_table);
#endif

    /*
    * required akismet api params check
    */
    if (!apr_table_get(params_table, conf->comment_param_key)) {
        return APR_SUCCESS;
    }

    /*
    * send request to akismet verify-key API if needed
    */
    char* k = apr_psprintf(r->pool, "%s-%s", conf->apikey, conf->blogurl);
    shm_update_skip = (get_status_from_api_cache_shm(r, k, &key_verified) < 0) ? 1:0;
    if (key_verified == -1 ) {
        apicode =  akismet_verify_key(r, conf->apikey, conf->blogurl);
        if ( apicode == AKISMET_OK ) {
            key_verified = 1;
        } else if ( apicode == AKISMET_KEY_INVALID ) {
            key_verified = 0;
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                    "For some reason, akismet_verify_key check failed!! "
                    "So skip the rest of comment check process." );
            return APR_SUCCESS;
        }
        if (!shm_update_skip) {
            set_status_to_api_cache_shm(r, k, key_verified);
        }
    }
    if ( key_verified != 1 ) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                    "Apikey is invalid. Please check out api registration! "
                    "Apikey=%s", conf->apikey);
         return APR_SUCCESS;
    }

    /*
    * set akismet_comment_check_request info
    */
    accr = apr_palloc(r->pool,sizeof(akismet_comment_check_request));
    assert(accr);
    memset(accr,0,sizeof(akismet_comment_check_request));
    accr->apikey = (char *)apr_pstrdup(r->pool,conf->apikey);
    accr->blogurl = (char *)apr_pstrdup(r->pool,conf->blogurl);
    server_addr = r->connection->local_ip;
    remote_addr = r->connection->remote_ip;
    if ( strcmp(remote_addr, server_addr)==0 ) {
        accr->ip = (char *)apr_pstrdup(r->pool,remote_addr);
    } else {
        accr->ip = (char *)apr_pstrdup(r->pool,
                    apr_table_get(r->headers_in, "X-Forwarded-For"));
    }
    accr->ua = (char *)apr_pstrdup(r->pool,
                    apr_table_get(r->headers_in, "User-Agent"));
    accr->ref = (char *)apr_pstrdup(r->pool,
                    apr_table_get(r->headers_in, "Referer"));
    accr->comment = (char *)apr_pstrdup(r->pool,
                apr_table_get(params_table, conf->comment_param_key));
    if (apr_table_get(params_table, conf->comment_author_param_key)) {
        accr->comment_author = (char *)apr_pstrdup(r->pool,
                apr_table_get(params_table, conf->comment_author_param_key));
    }
    if (apr_table_get(params_table, conf->comment_author_email_param_key)) {
        accr->comment_author_email = (char *)apr_pstrdup(r->pool,
                apr_table_get(params_table, conf->comment_author_email_param_key));
    }
    if (apr_table_get(params_table, conf->comment_author_url_param_key)) {
        accr->comment_author_url = (char *)apr_pstrdup(r->pool,
                apr_table_get(params_table, conf->comment_author_url_param_key));
    }
    if (apr_table_get(params_table, conf->comment_permalink_param_key)) {
        accr->comment_permalink = (char *)apr_pstrdup(r->pool,
                apr_table_get(params_table, conf->comment_permalink_param_key));
    }
    /*
    * send request to akismet comment-check API
    */
    apicode = akismet_comment_check(r, accr);
    if (apicode == AKISMET_SPAM) {
        /* set akismet_detect_spam flag in subprocess_env table for script language */
        apr_table_setn(r->subprocess_env, "akismet_detect_spam", conf->comment_param_key);
        /* set akismet_detect_spam flag in http header */
        apr_table_set(r->headers_in, "akismet_detect_spam", conf->comment_param_key);
    }
    return APR_SUCCESS;
}

static apr_status_t
 akismet_filter(ap_filter_t *f,
                apr_bucket_brigade *out_brigade,
                ap_input_mode_t input_mode,
                apr_read_type_e read_type,
                apr_off_t nbytes)
{
    akismet_config *conf = NULL;
    akismet_config *sconf =NULL;
    akismet_config *dconf =NULL;
    request_rec *r = f->r;
    AkismetFilterContext *pctx;
    apr_status_t ret;
    apr_table_t *params_table;
    char* query_string=NULL;
    int i=0;
    char *next, *last;
    /*
    * decide configuration
    * use server level config if no directory level config not defined
    */
    sconf =
        (akismet_config *)ap_get_module_config(r->server->module_config,&akismet_module);
    dconf =
        (akismet_config *)ap_get_module_config(r->per_dir_config, &akismet_module);
    conf = dconf;
    if ( !dconf
        || (!dconf->enabled && !dconf->apikey && !dconf->blogurl) ){
        conf = sconf;
    }
    /*
    * parse request parameters
    */
    params_table = apr_table_make(r->pool, PARAMS_TABLE_INIT_SIZE);

    if (!(pctx = f->ctx)) {
        f->ctx = pctx = apr_palloc(r->pool, sizeof *pctx);
        pctx->tmp_brigade = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    }
    if (APR_BRIGADE_EMPTY(pctx->tmp_brigade)) {
        ret = ap_get_brigade(f->next, pctx->tmp_brigade, input_mode, read_type, nbytes);
        if (input_mode == AP_MODE_EATCRLF || ret != APR_SUCCESS) {
            return ret;
        }
    }
    while( !APR_BRIGADE_EMPTY(pctx->tmp_brigade) ) {
        apr_bucket *in_bucket = APR_BRIGADE_FIRST(pctx->tmp_brigade);
        apr_bucket *out_bucket;
        const char *data;
        apr_size_t len;
        char *buf;
        int n;
        if(APR_BUCKET_IS_EOS(in_bucket)) {
            APR_BUCKET_REMOVE(in_bucket);
            APR_BRIGADE_INSERT_TAIL(out_brigade, in_bucket);
            break;
        }
        ret=apr_bucket_read(in_bucket, &data, &len, read_type);
        if(ret != APR_SUCCESS){
            return ret;
        }
        if (query_string == NULL) {
            query_string = apr_pstrdup(r->pool, data);
        } else {
            query_string = apr_pstrcat(r->pool, query_string, data,NULL);
        }
        out_bucket = apr_bucket_heap_create(data, len, 0, r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(out_brigade, out_bucket);
        apr_bucket_delete(in_bucket);
    }
    if (!query_string) {
        return APR_SUCCESS;
    }
    /*
    * split query_string and set params tables
    */
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

    /*
    * comment spam check by akismet api
    */
    return akismet_api_execute(r,conf,params_table);
}

static void
 akismet_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(akismet_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(akismet_child_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_insert_filter(akismet_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_input_filter(akismet_filter_name, akismet_filter, NULL, AP_FTYPE_RESOURCE);
}

static const command_rec akismet_cmds[] =
{
    AP_INIT_TAKE1("AkismetApiCacheShmFile", set_shmfile,
        NULL, RSRC_CONF,
        "[required] Set filename of shm file for the API Cache. (required)"),
    AP_INIT_TAKE1("AkismetGlobalLockFile", set_lockfile,
        NULL, RSRC_CONF,
        "[required] Set filename of global mutex. (required)"),
    AP_INIT_FLAG("AkismetEnabled", set_enabled,
        NULL, RSRC_CONF|ACCESS_CONF,
        "[required] Set \"On\" to enable akismet engine, \"Off\" to disable."),
    AP_INIT_TAKE1("AkismetApiKey", set_apikey,
        NULL, RSRC_CONF|ACCESS_CONF,
        "[required] Set the wordpress API key. (required)"),
    AP_INIT_TAKE1("AkismetBlogURL", set_blogurl,
        NULL, RSRC_CONF|ACCESS_CONF,
        "[required] Set the front page or home URL of your blog or wiki, etc."),
    AP_INIT_TAKE1("AkismetCommentParamKey", set_comment_param_key,
        NULL, RSRC_CONF|ACCESS_CONF,
        "[required] Set the param key name of the submitted comment. (required)"),
    AP_INIT_TAKE1("AkismetCommentAuthorParamKey", set_comment_author_param_key,
        NULL, RSRC_CONF|ACCESS_CONF,
        "[optional] Set the param key name of the submitted name with the comment"),
    AP_INIT_TAKE1("AkismetCommentAuthorEmailParamKey", set_comment_author_email_param_key,
        NULL, RSRC_CONF|ACCESS_CONF,
        "[optional] Set the param key name of submitted email address"),
    AP_INIT_TAKE1("AkismetCommentAuthorURLParamKey", set_comment_author_url_param_key,
        NULL, RSRC_CONF|ACCESS_CONF,
        "[optional] Set the param key name of the commenter URL"),
    AP_INIT_TAKE1("AkismetCommentPermalinkParamKey", set_comment_permalink_param_key,
        NULL, RSRC_CONF|ACCESS_CONF,
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
