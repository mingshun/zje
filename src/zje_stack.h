/*
 * zje_stack.h
 *
 *  Created on: 2012-12-21
 *      Author: mingshun
 */

#ifndef ZJE_STACK_H_
#define ZJE_STACK_H_

typedef struct zje_stack * zje_stack_t;

struct zje_stack {
    void *data;
    zje_stack_t next;
};

/*
 * 新建栈
 */
zje_stack_t zje_stack_new(void);

/*
 * 销毁栈数据函数指针
 */
typedef void (*zje_stack_ddfunc_t)(void *data);

/*
 * 入栈
 */
int zje_stack_push(zje_stack_t *stack, void *data);

/*
 * 出栈
 */
int zje_stack_pop(zje_stack_t *stack, void **data);

/*
 * 清空栈
 */
void zje_stack_clear(zje_stack_t *stack, zje_stack_ddfunc_t data_destructor);

/*
 * 销毁栈
 */
void zje_stack_destroy(zje_stack_t *stack, zje_stack_ddfunc_t data_destructor);

#endif /* ZJE_STACK_H_ */
