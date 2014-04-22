/*
 * zje_stack.c
 *
 *  Created on: 2012-12-21
 *      Author: mingshun
 */

#include "zje_stack.h"

#include "zje_log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/*
 * 新建栈
 */
zje_stack_t zje_stack_new(void)
{
    zje_stack_t s = (zje_stack_t) malloc(sizeof(struct zje_stack));
    if (s == NULL) {
        ZJE_LOG_ERROR("fail to allocate memory for stack tail: %s", strerror(errno));
        return NULL;
    }

    s->data = NULL;
    s->next = NULL;
    return s;
}

/*
 * 入栈
 */
int zje_stack_push(zje_stack_t *stack, void *data)
{
    if (*stack == NULL) {
        ZJE_LOG_ERROR("stack object is NULL");
        return -1;
    }

    zje_stack_t n = (zje_stack_t) malloc(sizeof(struct zje_stack));
    if (n == NULL) {
        ZJE_LOG_ERROR("fail to allocate memory for stack node: %s", strerror(errno));
        return -1;
    }

    n->data = data;
    n->next = *stack;
    *stack = n;
    return 0;
}

/*
 * 出栈
 */
int zje_stack_pop(zje_stack_t *stack, void **data)
{
    *data = NULL;

    if (*stack == NULL) {
        ZJE_LOG_ERROR("stack object is NULL");
        return -1;
    }

    zje_stack_t n = *stack;
    if (n->next == NULL) {
        ZJE_LOG_ERROR("stack is empty");
        return 0;
    }

    *data = n->data;
    *stack = n->next;
    free(n);
    return 0;
}

/*
 * 清空栈
 */
void zje_stack_clear(zje_stack_t *stack, zje_stack_ddfunc_t data_destructor)
{
    if (*stack == NULL) {
        return;
    }

    zje_stack_t n = *stack;
    while (n->next != NULL) {
        zje_stack_t c = n;
        if (data_destructor != NULL) {
            data_destructor(c->data);
        }
        n = c->next;
        free(c);
    }

    *stack = n;
}

/*
 * 销毁栈
 */
void zje_stack_destroy(zje_stack_t *stack, zje_stack_ddfunc_t data_destructor)
{
    if (*stack == NULL) {
        return;
    }

    zje_stack_clear(stack, data_destructor);
    free(*stack);

    *stack = NULL;
}
