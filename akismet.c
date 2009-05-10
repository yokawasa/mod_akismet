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
#include <stdio.h>
#include <assert.h>
#include "akismet.h"
#include "http_log.h"      // ap_log_rerror
#include "apr_strings.h"
#include <curl/curl.h>

#define IS_EMPTY(a) ( (a != 0 && *a != 0) ? 0 : 1 )

struct akismet_curl_response{
    char *data;
    size_t size;
};

size_t
 akismet_write_response_callback(void *ptr,
        size_t size, size_t nmemb, void *data)
{
    register int rsize = 0;
    struct akismet_curl_response *res = NULL;
    rsize = size * nmemb;
    res = (struct akismet_curl_response *)data;
    res->data = (char *)realloc(res->data, res->size + rsize + 1);
    if (res->data) {
        memcpy(&(res->data[res->size]), ptr, rsize);
        res->size += rsize;
        res->data[res->size] = 0;
    }
    return rsize;
}

int
 akismet_http_post ( const char *url,
        const char *args, char* content, int* ret_code )
{
    CURL *ch;
    CURLcode retCode;
    // init struct
    struct akismet_curl_response res;
    res.data = NULL;
    res.size = 0;
    // curl init & set options
    curl_global_init(CURL_GLOBAL_ALL);
    ch = curl_easy_init();
    curl_easy_setopt(ch, CURLOPT_URL, url );
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, AKISMET_API_REQ_TIMEOUT );
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS, args );
    curl_easy_setopt(ch, CURLOPT_POST, 1);
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, akismet_write_response_callback );
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *)&res );
    curl_easy_setopt(ch, CURLOPT_USERAGENT, AKISMET_API_REQ_USERAGENT);
    // curl execute
    retCode = curl_easy_perform(ch);
    curl_easy_cleanup(ch);
    strncpy(content, res.data, res.size);
    *ret_code = retCode;
    free(res.data);

    if ( CURLE_OK != retCode || !content ) {
        return -1;
    }
    return 0;
}

char*
 url_encode( const char *src, char* dst )
{
    int s = 0;
    char *ch, *bk;
    char *p, *buf;
    static char escapechars[] = "<>{}#%|\"\\^~[]`@:\033";
    static char hex[16]  = "0123456789ABCDEF";
    bk = ch  = (char*)src;
    do{
        if( strchr( escapechars, *ch ))
            s += 2;
        ch++; s++;
    } while( *ch );

    buf = dst;
    p   = buf;
    ch  = bk;
    do{
        if( strchr( escapechars, *ch )){
            const char c = *ch;
            *p++ = '%';
            *p++ = hex[(c >> 4) & 0xf];
            *p++ = hex[c & 0xf];
        } else if(*ch == ' ') {
            *p++ = '+';
        } else{
            *p++ = *ch;
        }
        ch++;
    } while( *ch );
    *p = '\0';
    return( buf );
}

AkismetCode
 akismet_verify_key(request_rec *r,
            const char *apikey, const char* blogurl)
{
    int retcode;
    char api_res_content[100];
    char* apiurl;
    char* args;
    char blogurl_enc[200];

    if (!apikey||!blogurl) {
        return AKISMET_BAD_PARAM_ERROR;
    }
    memset(api_res_content,0,100);
    apiurl = apr_psprintf(r->pool, "http://%s/%s/%s",
                AKISMET_API_SERVER,AKISMET_API_VERSION,
                AKISMET_API_METHOD_VERIFY_KEY);
    args = apr_psprintf(r->pool, "key=%s&blog=%s",
                apikey, url_encode(blogurl, blogurl_enc));

    if (akismet_http_post(apiurl, args, api_res_content, &retcode ) ) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "akismet_verify_key FAILURE retcode=%d URL=%s ARGS=%s", retcode, apiurl, args);
        return AKISMET_HTTP_POST_ERROR;
    }
    if (strncmp(api_res_content,
            AKISMET_API_RES_VERIFY_KEY_OK,
            strlen(AKISMET_API_RES_VERIFY_KEY_OK)) != 0 ) {
        return AKISMET_KEY_INVALID;
    }
    return AKISMET_OK;
}

AkismetCode
 akismet_comment_check(request_rec *r, akismet_comment_check_request *acc_req )
{
    assert(acc_req);
    if (IS_EMPTY(acc_req->apikey)
        || IS_EMPTY(acc_req->blogurl)
        || IS_EMPTY(acc_req->comment)) {
        return AKISMET_BAD_PARAM_ERROR;
    }
    int retcode;
    char api_res_content[100];
    char* apiurl;
    char* args;
    size_t blogurl_enc_size= strlen(acc_req->blogurl) * 2 + 1;
    size_t ip_enc_size= (!IS_EMPTY(acc_req->ip)) ? strlen(acc_req->ip) * 2 + 1 : 1;
    size_t ua_enc_size= (!IS_EMPTY(acc_req->ua)) ? strlen(acc_req->ua) * 2 + 1 : 1;
    size_t ref_enc_size= (!IS_EMPTY(acc_req->ref)) ? strlen(acc_req->ref) * 2 + 1 : 1;
    char blogurl_enc[blogurl_enc_size];
    char ip_enc[ip_enc_size];
    char ua_enc[ua_enc_size];
    char ref_enc[ref_enc_size];

    memset(blogurl_enc, 0, blogurl_enc_size);
    memset(ip_enc, 0, ip_enc_size);
    memset(ua_enc, 0, ua_enc_size);
    memset(ref_enc, 0, ref_enc_size);
    memset(api_res_content,0,100);

    apiurl = apr_psprintf(r->pool, "http://%s.%s/%s/%s",
            acc_req->apikey,
            AKISMET_API_SERVER,
            AKISMET_API_VERSION,
            AKISMET_API_METHOD_COMMENT_CHECK);

    args = apr_psprintf( r->pool,
           "key=%s&blog=%s&user_ip=%s&user_agent=%s&referrer=%s"
           "&comment_content=%s&comment_author=%s&comment_author_email=%s"
           "&comment_author_url=%s&permalink=%s",
            acc_req->apikey,
            url_encode(acc_req->blogurl, blogurl_enc),
            !IS_EMPTY(acc_req->ip) ? url_encode(acc_req->ip, ip_enc) : "",
            !IS_EMPTY(acc_req->ua) ? url_encode(acc_req->ua, ua_enc) : "",
            !IS_EMPTY(acc_req->ref) ? url_encode(acc_req->ref, ua_enc) : "",
            acc_req->comment,
            !IS_EMPTY(acc_req->comment_author) ? acc_req->comment_author : "",
            !IS_EMPTY(acc_req->comment_author_email) ? acc_req->comment_author_email : "",
            !IS_EMPTY(acc_req->comment_author_url) ? acc_req->comment_author_url : "",
            !IS_EMPTY(acc_req->comment_permalink) ? acc_req->comment_permalink : "");
#ifdef AKISMET_DEBUG
ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "akismet_http_post ARGS->%s", args);
#endif
    if ( akismet_http_post(apiurl, args, api_res_content, &retcode ) ) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,  "FAILURE retcode->%d", retcode );
        return AKISMET_HTTP_POST_ERROR;
    }
    if ( strncmp( api_res_content,
            AKISMET_API_RES_COMMENT_IS_SPAM ,
            strlen(AKISMET_API_RES_COMMENT_IS_SPAM)
            ) == 0) {
        return AKISMET_SPAM;
    }
    return AKISMET_OK;
}

/*
 * vim:ts=4 et
 */

