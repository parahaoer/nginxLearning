#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <string.h>
/*
* 将磁盘文件作为包体发送
*/
static ngx_int_t ngx_http_helloworld_handler(ngx_http_request_t *r);
static char *ngx_http_helloworld(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

//定义模块配置文件的处理
static ngx_command_t ngx_http_helloworld_commands[] = {
    {//配置项名称
     ngx_string("helloworld"),
     //配置项类型，即定义他可以出现的位置
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_NOARGS,
     //处理配置项参数的函数，函数在下面定义
     ngx_http_helloworld,
     //在配置文件中的偏移量
     NGX_HTTP_LOC_CONF_OFFSET,
     //预设的解析方法配置项
     0,
     //配置项读取后的处理方法
     NULL},
    //command数组要以ngx_null_command结束
    //#define ngx_null_command {ngx_null_string,0,NULL,0,0,NULL}
    ngx_null_command};

//helloworld模块上下文,都为NULL即是说在http框架初始化时没有什么要做
static ngx_http_module_t ngx_http_helloworld_module_ctx = {
    NULL, //preconfiguration
    NULL, //postconfiguration
    NULL, //create main configuration
    NULL, //init main configuration
    NULL, //create server configuration
    NULL, //merge server configuration
    NULL, //create location configuration
    NULL  //merge location configuration
};
//对自己helloworld模块的定义，在编译时加入到全局的ngx_modules数组中，这样在Nginx初始化时会调用模块的所有初始化方法，（上面的ngx_http_module_t类型的ngx_http_helloworld_module_ctx）

ngx_module_t ngx_http_helloworld_module = {
    NGX_MODULE_V1,                   //由Nginx定义的宏来初始化前七个成员
    &ngx_http_helloworld_module_ctx, //模块的上下文结构体，指向特定模块的公共方法
    ngx_http_helloworld_commands,    //处理配置项的结构体数组
    NGX_HTTP_MODULE,                 //模块类型
    //Nginx在启动停止过程中七个执行点的函数指针
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,

    NGX_MODULE_V1_PADDING //由Nginx定义的宏定义剩下的8个保留字段
};

//配置项对应的回调函数，当配置项中出现helloworld配置项时将调用这个函数
static char *ngx_http_helloworld(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{ //ckcf并不是指特定的location块内的数据结构，他可以是mian、srv、loc级别的配置项
    //每个http{},sever{},location{}都有一个ngx_http_core_loc_conf_t类型的数据结构
    ngx_http_core_loc_conf_t *clcf;

    //找到helloworld配置项所在的配置块
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    //http框架在处理用户请求进行到NGX_HTTP_CONTENT_PHASE阶段是，如果请求的主机名，URI与配置项所在的配置块相匹配时，就调用
    //clcf中的handle方法处理这个请求
    //NGX_HTTP_CONTENT_PHASE用于处理http请求内容的阶段，这是大部分http模块通常介入的阶段
    clcf->handler = ngx_http_helloworld_handler;

    return NGX_CONF_OK;
}

//实际完成处理的回调函数
static ngx_int_t ngx_http_helloworld_handler(ngx_http_request_t *r)
{
    //请求方法
    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))
    {
        return NGX_HTTP_NOT_ALLOWED;
    }
    //不处理请求的包体，直接丢弃。但这一步也是不可省略的，他是接受包体的一种方法，只不过是简单的丢弃，
    //如果不接受，客户端可能会再次试图发送包体，而服务器不接受就会造成客户端发送超时
    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK)
    {
        return rc;
    }

    ngx_buf_t *b;
    b = ngx_palloc(r->pool, sizeof(ngx_buf_t));

    u_char *filename = (u_char *)"/tmp/test.txt"; // 要打开的文件名
    b->in_file = 1;                               // 设置为1表示缓冲区中发送的是文件

    // 分配代表文件的结构体空间，file成员表示缓冲区引用的文件
    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    b->file->fd = ngx_open_file(filename, NGX_FILE_RDONLY | NGX_FILE_NONBLOCK, NGX_FILE_OPEN, 0);
    b->file->log = r->connection->log; // 日志对象
    b->file->name.data = filename;     // name成员表示文件名称
    b->file->name.len = sizeof(filename) - 1;
    if (b->file->fd <= 0)
        return NGX_HTTP_NOT_FOUND;

    r->allow_ranges = 1; //支持断点续传

    // 获取文件长度，ngx_file_info方法封装了stat系统调用
    // info成员就表示stat结构体
    if (ngx_file_info(filename, &b->file->info) == NGX_FILE_ERROR)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    // 设置缓冲区指向的文件块
    b->file_pos = 0;                      // 文件起始位置
    b->file_last = b->file->info.st_size; // 文件结束为止

    // 用于告诉HTTP框架，请求结束时调用cln->handler成员函数
    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln == NULL)
        return NGX_ERROR;

    cln->handler = ngx_pool_cleanup_file; // ngx_pool_cleanup_file专用于关闭文件句柄

    ngx_pool_cleanup_file_t *clnf = cln->data; // cln->data为上述回调函数的参数
    clnf->fd = b->file->fd;
    clnf->name = b->file->name.data;
    clnf->log = r->pool->log;

    // 设置返回的Content-Type
    // 注意，ngx_str_t有一个很方便的初始化宏
    // ngx_string，它可以把ngx_str_t的data和len成员都设置好
    ngx_str_t type = ngx_string("text/plain");

    //设置返回状态码
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->file->info.st_size; // 正文长度
    r->headers_out.content_type = type;

    // 发送http头部
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
        return rc;

    // 构造发送时的ngx_chain_t结构体
    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    //最后一步发送包体，http框架会调用ngx_http_finalize_request方法
    return ngx_http_output_filter(r, &out);
}