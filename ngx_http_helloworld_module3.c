#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
/**
 * 把向nginx服务器的请求转化为向百度服务器的搜索请求
*/
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *);
static char *ngx_http_mytest(ngx_conf_t*, ngx_command_t*, void*);
static void *ngx_http_mytest_create_loc_conf(ngx_conf_t*);
static char *ngx_http_mytest_merge_loc_conf(ngx_conf_t*, void*, void*);
static void mytest_upstream_finalize_request(ngx_http_request_t*, ngx_int_t);
static ngx_int_t mytest_upstream_process_header(ngx_http_request_t*);
static ngx_int_t mytest_process_status_line(ngx_http_request_t*);
static ngx_int_t mytest_upstream_create_request(ngx_http_request_t*);

static ngx_str_t  ngx_http_proxy_hide_headers[] = {
    ngx_string("Date"),
    ngx_string("Server"),
    ngx_string("X-Pad"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};

typedef struct {
    ngx_http_status_t status;
    struct {
        u_char* data;
        ngx_uint_t len;
    } backendServer;
} ngx_http_mytest_ctx_t;

static ngx_http_module_t ngx_http_mytest_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_mytest_create_loc_conf,
    ngx_http_mytest_merge_loc_conf
};

typedef struct {
  ngx_http_upstream_conf_t upstream;
} ngx_http_mytest_conf_t;

static ngx_command_t ngx_http_mytest_commands[] = {
    {
        ngx_string("mytest"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        ngx_http_mytest,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

ngx_module_t ngx_http_mytest_module = {
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

static ngx_int_t
ngx_http_mytest_handler(ngx_http_request_t *r) {
    // 首先建立HTTP上下文结构体ngx_http_mytest_ctx_t
    ngx_http_mytest_ctx_t* myctx = ngx_http_get_module_ctx(r,ngx_http_mytest_module);
    if (myctx == NULL) {
        myctx = ngx_palloc(r->pool, sizeof(ngx_http_mytest_ctx_t));
        if (myctx == NULL) {
            return NGX_ERROR;
        }
        // 将新建的上下文与请求关联起来
        ngx_http_set_ctx(r,myctx,ngx_http_mytest_module);
    }
    /*对每1个要使用upstream的请求, 必须调用且只能调用1次ngx_http_upstream_create方法, 它会初始化r->upstream成员*/
    if (ngx_http_upstream_create(r) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"ngx_http_upstream_create() failed");
        return NGX_ERROR;
    }
    // 得到配置结构体ngx_http_mytest_conf_t
    ngx_http_mytest_conf_t  *mycf = (ngx_http_mytest_conf_t  *) ngx_http_get_module_loc_conf(r, ngx_http_mytest_module);
    ngx_http_upstream_t *u = r->upstream;
    // 这里用配置文件中的结构体来赋给r->upstream->conf成员
    u->conf = &mycf->upstream;
    // 决定转发包体时使用的缓冲区
    u->buffering = mycf->upstream.buffering;
    // 以下代码开始初始化resolved结构体, 用来保存上游服务器的地址
    u->resolved = (ngx_http_upstream_resolved_t*) ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
        "ngx_pcalloc resolved error. %s.", strerror(errno));
        return NGX_ERROR;
    }
    // 这里的上游服务器就是www.google.com
    static struct sockaddr_in backendSockAddr;
    struct hostent *pHost = gethostbyname((char*) "www.baidu.com");
    if (pHost == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "gethostbyname fail. %s", strerror(errno));
        return NGX_ERROR;
    }
    // 访问上游服务器的80端口
    backendSockAddr.sin_family = AF_INET;
    backendSockAddr.sin_port = htons((in_port_t) 80);
    char* pDmsIP = inet_ntoa(*(struct in_addr*) (pHost->h_addr_list[0]));
    backendSockAddr.sin_addr.s_addr = inet_addr(pDmsIP);
    myctx->backendServer.data = (u_char*)pDmsIP;
    myctx->backendServer.len = strlen(pDmsIP);
    // 将地址设置到resolved成员中
    u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
    u->resolved->socklen = sizeof(struct sockaddr_in);
    u->resolved->naddrs = 1;
    u->resolved->port = 80;
    // 设置3个必须实现的回调方法, 也就是5.3.3节~5.3.5节中实现的3个方法
    u->create_request = mytest_upstream_create_request;
    u->process_header = mytest_process_status_line;
    u->finalize_request = mytest_upstream_finalize_request;
    // 这里必须将count成员加1, 参见5.1.5节
    r->main->count++;
    // 启动upstream
    ngx_http_upstream_init(r);
    // 必须返回NGX_DONE
    return NGX_DONE;
}

static char *
ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_mytest_handler;
    return NGX_CONF_OK;
}

static void *
ngx_http_mytest_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_mytest_conf_t  *mycf;
    mycf = (ngx_http_mytest_conf_t  *)ngx_pcalloc(cf->pool, sizeof(ngx_http_mytest_conf_t));
    if (mycf == NULL) {
        return NULL;
    }
    /*以下简单的硬编码ngx_http_upstream_conf_t结构中的各成员, 如超时时间, 都设为1分钟, 这也是HTTP反向代理模块的默认值*/
    mycf->upstream.connect_timeout = 60000;
    mycf->upstream.send_timeout = 60000;
    mycf->upstream.read_timeout = 60000;
    mycf->upstream.store_access = 0600;
    /*实际上, buffering已经决定了将以固定大小的内存作为缓冲区来转发上游的响应包体, 这块固定缓冲区的大小就是buffer_size。如果buffering为1, 就会使用更多的内存缓存来不及发往下游的响应。例如, 最多使用bufs.num个缓冲区且每个缓冲区大小为bufs.size。另外, 还会使用临时文件, 临时文件的最大长度为max_temp_file_size*/
    mycf->upstream.buffering = 0;
    mycf->upstream.bufs.num = 8;
    mycf->upstream.bufs.size = ngx_pagesize;
    mycf->upstream.buffer_size = ngx_pagesize;
    mycf->upstream.busy_buffers_size = 2*ngx_pagesize;
    mycf->upstream.temp_file_write_size = 2 * ngx_pagesize;
    mycf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    /*upstream模块要求hide_headers成员必须要初始化(upstream在解析完上游服务器返回的包头时, 会调用ngx_http_upstream_process_headers方法按照hide_headers成员将本应转发给下游的一些HTTP头部隐藏), 这里将它赋为NGX_CONF_UNSET_PTR , 这是为了在merge合并配置项方法中使用upstream模块提供的ngx_http_upstream_hide_headers_hash方法初始化hide_headers 成员*/
    mycf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    mycf->upstream.pass_headers = NGX_CONF_UNSET_PTR;
    return mycf;
}

static char *
ngx_http_mytest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_mytest_conf_t *prev = (ngx_http_mytest_conf_t *)parent;
    ngx_http_mytest_conf_t *conf = (ngx_http_mytest_conf_t *)child;
    ngx_hash_init_t             hash;
    hash.max_size = 100;
    hash.bucket_size = 1024;
    hash.name = "proxy_headers_hash";
    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream,
            &prev->upstream, ngx_http_proxy_hide_headers, &hash)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static void
mytest_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "mytest_upstream_finalize_request");
}

static ngx_int_t
mytest_upstream_process_header(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_table_elt_t                *h;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;
    /*这里将upstream模块配置项ngx_http_upstream_main_conf_t取出来, 目的只有一个, 就是对将要转发给下游客户端的HTTP响应头部进行统一处理。该结构体中存储了需要进行统一处理的HTTP头部名称和回调方法*/
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    // 循环地解析所有的HTTP头部
    for ( ;; ) {
        /* HTTP框架提供了基础性的ngx_http_parse_header_line方法, 它用于解析HTTP头部*/
        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
        // 返回NGX_OK时, 表示解析出一行HTTP头部
        if (rc == NGX_OK) {
            // 向headers_in.headers这个ngx_list_t链表中添加HTTP头部
            h = ngx_list_push(&r->upstream->headers_in.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }
            // 下面开始构造刚刚添加到headers链表中的HTTP头部
            h->hash = r->header_hash;
            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;
            // 必须在内存池中分配存放HTTP头部的内存空间
            h->key.data = ngx_pnalloc(r->pool,
            h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                return NGX_ERROR;
            }
            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;
            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';
            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }
            // upstream模块会对一些HTTP头部做特殊处理
            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);
            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return NGX_ERROR;
            }
            continue;
        }
    /*返回NGX_HTTP_PARSE_HEADER_DONE时, 表示响应中所有的HTTP头部都解析完毕, 接下来再接收到的都将是HTTP包体*/
        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            /*如果之前解析HTTP头部时没有发现server和date头部, 那么下面会根据HTTP协议规范添加这两个头部*/
            if (r->upstream->headers_in.server == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }
                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(
                                    ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');
                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "server";
            }
            if (r->upstream->headers_in.date == NULL) {
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }
                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');
                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "date";
            }
            return NGX_OK;
        }
        /*如果返回NGX_AGAIN, 则表示状态机还没有解析到完整的HTTP头部, 此时要求upstream模块继续接收新的字符流, 然后交由process_header回调方法解析*/
        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }
        // 其他返回值都是非法的
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header");
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

static ngx_int_t
mytest_process_status_line(ngx_http_request_t *r)
{
    size_t len;
    ngx_int_t rc;
    ngx_http_upstream_t *u;
    ngx_http_mytest_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    u = r->upstream;
    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);
    if (rc == NGX_AGAIN) {
        return rc;
    }
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent no valid HTTP/1.0 header");
        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;
        return NGX_OK;
    }
    if (u->state) {
        u->state->status = ctx->status.code;
    }
    u->headers_in.status_n = ctx->status.code;
    len = ctx->status.end - ctx->status.start;
    u->headers_in.status_line.len = len;
    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);
    u->process_header = mytest_upstream_process_header;
    return mytest_upstream_process_header(r);
}

static ngx_int_t
mytest_upstream_create_request(ngx_http_request_t *r)
{
    static ngx_str_t backendQueryLine = ngx_string("GET /search?q=%V HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n");
    ngx_int_t queryLineLen = backendQueryLine.len + r->args.len - 2;
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, queryLineLen);
    if (b == NULL) {
        return NGX_ERROR;
    }
    b->last = b->pos + queryLineLen;
    ngx_snprintf(b->pos, queryLineLen, (char*) backendQueryLine.data, &r->args);
    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if (r->upstream->request_bufs == NULL) {
        return NGX_ERROR;
    }
    r->upstream->request_bufs->buf = b;
    r->upstream->request_bufs->next = NULL;
    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;
    r->header_hash = 1;
    return NGX_OK;
}
