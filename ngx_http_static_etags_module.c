/* 
 *  Copyright (c) 2009 Adrian Jung ( http://me2day.net/kkung, kkungkkung@gmail.com ).
 *  All rights reserved.
 *  All original code was written by Mike West ( http://mikewest.org/ )
 *
 *  Copyright 2008 Mike West ( http://mikewest.org/ )
 *
 *  The following is released under the Creative Commons BSD license,
 *  available for your perusal at `http://creativecommons.org/licenses/BSD/`
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/stat.h>

#if (NGX_HAVE_OPENSSL_MD5_H)
#include <openssl/md5.h>
#else
#include <md5.h>
#endif

#if (NGX_OPENSSL_MD5)
#define  MD5Init    MD5_Init
#define  MD5Update  MD5_Update
#define  MD5Final   MD5_Final
#endif

#if (NGX_HAVE_OPENSSL_SHA1_H)
#include <openssl/sha.h>
#else
#include <sha.h>
#endif

#define MD5_HEX_DIGEST_LENGTH MD5_DIGEST_LENGTH*2
#define SHA_HEX_DIGEST_LENGTH SHA_DIGEST_LENGTH*2
/*
 *  Two configuration elements: `enable_etags` and `etag_format`, specified in
 *  the `Location` block.
 */
typedef struct {
    ngx_flag_t  enable;
    ngx_flag_t  enable_hash;
    ngx_str_t   hash_method;
    
} ngx_http_static_etags_loc_conf_t;

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
/*static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;*/

static void * ngx_http_static_etags_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_static_etags_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_static_etags_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_static_etags_header_filter(ngx_http_request_t *r);
static char *ngx_http_static_etags_hash_method(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_static_etags_commands[] = {
    { ngx_string( "etags" ),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof( ngx_http_static_etags_loc_conf_t, enable ),
      NULL },
    { ngx_string( "etag_hash"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof ( ngx_http_static_etags_loc_conf_t, enable_hash),
      NULL },
    { ngx_string( "etag_hash_method"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_static_etags_hash_method,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
      ngx_null_command
};

static ngx_http_module_t  ngx_http_static_etags_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_static_etags_init,             /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_static_etags_create_loc_conf,  /* create location configuration */
    ngx_http_static_etags_merge_loc_conf,   /* merge location configuration */
};

ngx_module_t  ngx_http_static_etags_module = {
    NGX_MODULE_V1,
    &ngx_http_static_etags_module_ctx,  /* module context */
    ngx_http_static_etags_commands,     /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *ngx_http_static_etags_hash_method(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
   ngx_http_static_etags_loc_conf_t    *l_conf = conf;
   ngx_str_t  *value;

   if (l_conf->hash_method.len) {
     return "is duplicate"; 
   } 
   
   value = cf->args->elts;
   
   if ( ngx_strcmp(value[1].data,"md5") == 0 ) {
     l_conf->hash_method = value[1];
   } else if ( ngx_strcmp(value[1].data,"sha1") == 0 ) {
     l_conf->hash_method = value[1];
   } else {
     return "invalid value. md5 or sha1 allowed";
   }
   
   return NGX_CONF_OK;
   
}
static void * ngx_http_static_etags_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_static_etags_loc_conf_t    *conf;

    conf = ngx_pcalloc( cf->pool, sizeof( ngx_http_static_etags_loc_conf_t ) );
    if ( NULL == conf ) {
        return NGX_CONF_ERROR;
    }
    conf->enable   = NGX_CONF_UNSET_UINT;
    conf->enable_hash = NGX_CONF_UNSET_UINT;
    return conf;
}

static char * ngx_http_static_etags_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_static_etags_loc_conf_t *prev = parent;
    ngx_http_static_etags_loc_conf_t *conf = child;

    ngx_conf_merge_value( conf->enable, prev->enable, 0 );
    ngx_conf_merge_value( conf->enable_hash, prev->enable_hash, 1);
    ngx_conf_merge_str_value( conf->hash_method, prev->hash_method, "md5");
    
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_static_etags_init(ngx_conf_t *cf) {
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_static_etags_header_filter;

    return NGX_OK;
}

static ngx_int_t ngx_http_static_etags_header_filter(ngx_http_request_t *r) {
//    int                                 status;
    ngx_log_t                          *log;
    u_char                             *p;
    size_t                              root;
    ngx_str_t                           path;
    ngx_http_static_etags_loc_conf_t   *loc_conf;
//    struct stat                         stat_result;
    ngx_str_t                           str_buffer;
    ngx_str_t                           etag;
    
    uint i;
    static u_char hex[] = "0123456789abcdef";
    
    u_char *hashed_etag;
    u_char *hash = NULL;
    
    // for nginx_open_file_cache
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;
    
    log = r->connection->log;
    
    loc_conf = ngx_http_get_module_loc_conf( r, ngx_http_static_etags_module );
    
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log,0 ,"[etag] working? \"%d\"",loc_conf->enable);
    
    // Is the module active?
    if ( loc_conf->enable ) {
      
        p = ngx_http_map_uri_to_path( r, &path, &root, 0 );
        if ( NULL == p ) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }


        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                        "[etag] http filename: \"%s\"", path.data);
    

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        of.test_dir = 0;
        of.valid = clcf->open_file_cache_valid;
        of.min_uses = clcf->open_file_cache_min_uses;
        of.errors = clcf->open_file_cache_errors;
        of.events = clcf->open_file_cache_events;
        
        
        // status = stat( (char *) path.data, &stat_result );
        //       ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
        //         "[etag] stat returned: \"%d\"", status);
        //         
        // Did the `stat` succeed?
      //  if ( 0 == status) {
        if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool) == NGX_OK ) {
            
            str_buffer.data = ngx_palloc(r->pool,
              3 + r->uri.len + sizeof(of.size) + sizeof(of.mtime)  
            );
            if ( str_buffer.data == NULL ) {
              ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                              "[etag] failed memory allocation");
              return NGX_ERROR;
            } 
            
            str_buffer.len = ngx_sprintf(str_buffer.data, "%V_%T_%z",&r->uri,of.mtime,of.size) - str_buffer.data;
           
    
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                         "[etag] st_size: '%d'", of.size);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                         "[etag] st_mtime: '%d'", of.mtime);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                         "[etag] Concatted: '%V'", &str_buffer );
            
            r->headers_out.etag = ngx_list_push(&r->headers_out.headers);
            if (r->headers_out.etag == NULL) {
              return NGX_ERROR;
            }
            r->headers_out.etag->hash = 1;
            r->headers_out.etag->key.len = sizeof("Etag") - 1;
            r->headers_out.etag->key.data = (u_char *) "Etag";
            
            if ( loc_conf->enable_hash) {
              
              uint digest_length = 0;
              uint hex_digest_length = 0;
              
              if ( ngx_strcmp(loc_conf->hash_method.data,"md5") == 0) {
                digest_length = MD5_DIGEST_LENGTH;
                hex_digest_length = MD5_HEX_DIGEST_LENGTH;
                
                hash = ngx_palloc(r->pool, digest_length);
                if ( hash == NULL ) {
                   ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                                    "[etag] failed memory allocation");
                   return NGX_ERROR;
                }
                
                MD5_CTX md5_ctx;
                MD5Init(&md5_ctx);
                MD5Update(&md5_ctx,str_buffer.data,str_buffer.len);
                MD5Final(hash,&md5_ctx);
                
              } else if ( ngx_strcmp(loc_conf->hash_method.data,"sha1") == 0 ) {
                digest_length = SHA_DIGEST_LENGTH;
                hex_digest_length = SHA_HEX_DIGEST_LENGTH;
                
                hash = ngx_palloc(r->pool, digest_length);
                if ( hash == NULL ) {
                  ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                                    "[etag] failed memory allocation");
                  return NGX_ERROR;
                }
                
                SHA_CTX sha1_ctx;
                SHA1_Init(&sha1_ctx);
                SHA1_Update(&sha1_ctx,str_buffer.data,str_buffer.len);
                SHA1_Final(hash,&sha1_ctx);
              } else {
                // ??
              }
              
              
            
              etag.data = ngx_palloc(r->pool, hex_digest_length);
              if ( etag.data == NULL ) {
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0,
                  "[etag] failed memory allocation(hash)");
                return NGX_ERROR;
              }
            
              etag.len = hex_digest_length;
              hashed_etag = etag.data;
              for ( i = 0 ; i < hex_digest_length; i++ ) {
                *hashed_etag++ = hex[hash[i] >> 4];
                *hashed_etag++ = hex[hash[i] & 0xf];
              }
            
              *hashed_etag = '\0';
            
              ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "[etag] hash result \"%V\"",&etag);
              r->headers_out.etag->value.len = etag.len;
              r->headers_out.etag->value.data = etag.data;
            } else {
              r->headers_out.etag->value.len = str_buffer.len;
              r->headers_out.etag->value.data = str_buffer.data;
            }
            
            ngx_uint_t      found=0;
            ngx_list_part_t *part;
            ngx_table_elt_t *header;
            ngx_table_elt_t if_none_match;

            part = &r->headers_in.headers.part;
            header = part->elts;

            for ( i = 0 ; ; i++ ) {
                    if ( i >= part->nelts) {
                            if ( part->next == NULL ) {
                                    break;
                            }

                            part = part->next;
                            header = part->elts;
                            i = 0;
                    }

                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0 , "[Etag] Header %V: %V", &header[i].key, &header[i].value );

                    if ( ngx_strcmp(header[i].key.data, "If-None-Match") == 0 ) {
                            if_none_match = header[i];
                            found = 1;
                            break;
                    }
            }

            if ( found ) {
                    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                    "[Etag] If-None-Match: \"%V\" // Hash: \"%V\"", &if_none_match.value, &r->headers_out.etag->value );

                    if ( ngx_strncmp(r->headers_out.etag->value.data, if_none_match.value.data, r->headers_out.etag->value.len) == 0 ) {
                            r->headers_out.status = NGX_HTTP_NOT_MODIFIED;
                            r->headers_out.content_type.len = 0;

                            ngx_http_clear_content_length(r);
                            ngx_http_clear_accept_ranges(r);
                    }
            }
            
        }
    }

    return ngx_http_next_header_filter(r);
}
