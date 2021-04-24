#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
/**
 * 解析配置项、合并父子配置项
 * */ 
static char *ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_mytest_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_mytest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
 
 
typedef struct {
	ngx_str_t str;
}ngx_http_mytest_loc_conf_t;
 
static ngx_command_t  ngx_http_mytest_commands[] = {
	{ 
		ngx_string("mytest"),
		NGX_HTTP_LOC_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
		ngx_http_mytest,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_mytest_loc_conf_t, str),
		NULL 
	},
	ngx_null_command
};
 
static ngx_http_module_t  ngx_http_mytest_module_ctx = {
	NULL,                                  
	NULL,                                 
	NULL,                               
	NULL,                                
	NULL,                                 
	NULL,                                 
	ngx_http_mytest_create_loc_conf,        
	ngx_http_mytest_merge_loc_conf 
};
 
ngx_module_t  ngx_http_helloworld_module = {
	NGX_MODULE_V1,
	&ngx_http_mytest_module_ctx,            
	ngx_http_mytest_commands,             
	NGX_HTTP_MODULE,                   				
	NULL,								   			
	NULL,                                  			
	NULL,                  							
	NULL,                                  		
	NULL,                                  			
	NULL,                                  			
	NULL,                                  		
	NGX_MODULE_V1_PADDING
};
 
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r)
{
	ngx_http_mytest_loc_conf_t *elcf;
	elcf = ngx_http_get_module_loc_conf(r, ngx_http_helloworld_module);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, ngx_errno, "ngx_http_mytest_handler...");
 
	if(!(r->method & (NGX_HTTP_PUT|NGX_HTTP_HEAD|NGX_HTTP_POST|NGX_HTTP_DELETE|NGX_HTTP_GET)))
	{
		return NGX_HTTP_NOT_ALLOWED;
	}
	
	ngx_int_t rc = ngx_http_discard_request_body(r);
	if(rc != NGX_OK)
	{
		return rc;
	}
 
	ngx_str_t type = ngx_string("text/html");
	ngx_str_t response = ngx_string(elcf->str.data);
	response.len = elcf->str.len;
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = response.len;
	r->headers_out.content_type = type;
 
	rc = ngx_http_send_header(r);
	if(rc == NGX_ERROR || rc >NGX_OK || r->header_only)
	{
		return rc;
	}
 
	ngx_buf_t* b;
	b = ngx_create_temp_buf(r->pool, response.len);
	if(b == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
 
	ngx_memcpy(b->pos, response.data, response.len);
	b->last = b->pos + response.len;
	b->last_buf = 1;
 
	ngx_chain_t out;
	out.buf = b;
	out.next = NULL;
	
	return ngx_http_output_filter(r, &out);
}
 
static char *ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t  *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_http_mytest_handler;
	ngx_conf_set_str_slot(cf,cmd,conf);
	return NGX_CONF_OK;
}
 
static void *ngx_http_mytest_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_mytest_loc_conf_t  *conf;
	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mytest_loc_conf_t));
	if (conf == NULL) {
		return NGX_CONF_ERROR;
	}
 
	return conf;
}
 
static char *ngx_http_mytest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_mytest_loc_conf_t *prev = parent;
	ngx_http_mytest_loc_conf_t *conf = child;
	ngx_conf_merge_str_value(conf->str, prev->str, "hello world!");
    ngx_log_error(NGX_LOG_ALERT, cf->log, 0, "conf->str:%V", &conf->str);
	return NGX_CONF_OK;
}