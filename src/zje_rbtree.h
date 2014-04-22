/*
 * zje_rbtree.h
 *
 *  Created on: 2012-3-1
 *      Author: mingshun
 */

#ifndef ZJE_RBTREE_H_
#define ZJE_RBTREE_H_

/*
 * 红黑树的键值类型
 */
typedef char *zje_rb_key_t;
typedef char *zje_rb_value_t;

/*
 * 红黑树颜色类型
 */
typedef enum zje_rb_color_e {
    RED = 0, BLACK = 1
} zje_rb_color_t;

/*
 * 红黑树结点类型
 */
typedef struct zje_rb_node_s *zje_rb_node_t;

/*
 * 红黑树结点结构体
 */
struct zje_rb_node_s {
    zje_rb_node_t parent;
    zje_rb_node_t left;
    zje_rb_node_t right;
    zje_rb_key_t key;
    zje_rb_value_t value;
    zje_rb_color_t color;
};

/*
 * 红黑树类型
 */
typedef struct zje_rb_tree_s *zje_rb_tree_t;

/*
 * 红黑树结构体
 */
struct zje_rb_tree_s {
    zje_rb_node_t root;
};

/*
 * 红黑树 - 创建树
 */
zje_rb_tree_t zje_rb_create(void);

/*
 * 红黑树 － 插入指定key的结点
 */
int zje_rb_put(zje_rb_tree_t tree, zje_rb_key_t key, zje_rb_value_t value);

/*
 * 红黑树 - 搜索
 */
zje_rb_node_t zje_rb_get(const zje_rb_tree_t tree, const zje_rb_key_t key);

/*
 * 红黑树 - 删除指定key的结点
 */
int zje_rb_erase(zje_rb_tree_t tree, zje_rb_key_t key);

/*
 * 红黑树 - 先序遍历
 */
void zje_rb_pre_order_traverse(zje_rb_tree_t tree, void (*operate)(zje_rb_node_t node));

/*
 * 红黑树 - 中序遍历
 */
void zje_rb_in_order_traverse(zje_rb_tree_t tree, void (*operate)(zje_rb_node_t node));

/*
 * 红黑树 - 后序遍历
 */
void zje_rb_post_order_traverse(zje_rb_tree_t tree, void (*operate)(zje_rb_node_t node));

/*
 * 红黑树 - 删除树
 */
void zje_rb_delete(zje_rb_tree_t tree);

#endif /* ZJE_RBTREE_H_ */
