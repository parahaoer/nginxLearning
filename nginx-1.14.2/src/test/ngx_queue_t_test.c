/**
 * ngx_queue_t test
 */
 
#include <stdio.h>
#include "ngx_config.h"
#include "ngx_conf_file.h"
#include "nginx.h"
#include "ngx_core.h"
#include "ngx_palloc.h"
#include "ngx_queue.h"

typedef struct 
{
    char *str;
    ngx_queue_t qElm;
    int num;
} TestNode;

volatile ngx_cycle_t  *ngx_cycle;
 
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
            const char *fmt, ...)
{
}
 
int main()
{
    ngx_queue_t myQueue;
    ngx_queue_init(&myQueue);

    TestNode nodes[5];
    int i;
    for (i = 0; i < 5; i++) {
        nodes[i].num = i;
    }

    ngx_queue_insert_tail(&myQueue, &nodes[0].qElm);
    ngx_queue_insert_head(&myQueue, &nodes[1].qElm);
    ngx_queue_insert_tail(&myQueue, &nodes[2].qElm);
    ngx_queue_insert_after(&nodes[0].qElm, &nodes[3].qElm);
    ngx_queue_insert_tail(&myQueue, &nodes[4].qElm);

    ngx_queue_t *q;
    for (q = ngx_queue_head(&myQueue); q != ngx_queue_sentinel(&myQueue); q = ngx_queue_next(q)) {
        TestNode *node = ngx_queue_data(q, TestNode, qElm);
        printf("%d ", node->num);
    }
    return 0;
}