/*
 * zje_rbtree.c
 *
 *  Created on: 2012-3-1
 *      Author: mingshun
 */

#include "zje_rbtree.h"

#include "zje_log.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static zje_rb_node_t zje_rb_create_node(zje_rb_key_t key, zje_rb_value_t value);
static zje_rb_node_t zje_rb_rotate_left(zje_rb_node_t root, zje_rb_node_t node);
static zje_rb_node_t zje_rb_rotate_right(zje_rb_node_t root, zje_rb_node_t node);
static zje_rb_node_t zje_rb_search_auxiliary(const zje_rb_tree_t tree, const zje_rb_key_t key, zje_rb_node_t *save);
static void zje_rb_insert_rebalance(zje_rb_tree_t tree, zje_rb_node_t node);
static void zje_rb_erase_rebalance(zje_rb_tree_t tree, zje_rb_node_t parent, zje_rb_node_t node);
static void zje_rb_pre_order_visit(zje_rb_node_t node, void (*operate)(zje_rb_node_t node));
static void zje_rb_in_order_visit(zje_rb_node_t node, void (*operate)(zje_rb_node_t node));
static void zje_rb_post_order_visit(zje_rb_node_t node, void (*operate)(zje_rb_node_t node));
static void zje_rb_delete_node(zje_rb_node_t node);
static int zje_rb_comparator(const zje_rb_key_t x, const zje_rb_key_t y);

/*
 * 红黑树 - 创建结点
 */
static zje_rb_node_t zje_rb_create_node(zje_rb_key_t key, zje_rb_value_t value)
{
    if (key == NULL) {
        ZJE_LOG_ERROR( "'key' should not be NULL");
        return NULL;
    }
    
    zje_rb_node_t node = (zje_rb_node_t) malloc(sizeof(struct zje_rb_node_s));
    if (!node) {
        ZJE_LOG_ERROR( "fail to allocate memory for a zje_rb_node_t: %s.", strerror(errno));
        return NULL;
    }
    
    size_t key_size = strlen(key);
    node->key = (zje_rb_key_t) malloc(key_size + 1);
    if (node->key == NULL) {
        ZJE_LOG_ERROR( "fail to allocate a zje_rb_key_t: %s.", strerror(errno));
        // 清理前面开辟的空间
        free(node);
        return NULL;
    }
    strncpy(node->key, key, key_size);
    node->key[key_size] = '\0';
    
    if (value != NULL) {
        size_t value_size = strlen(value);
        node->value = (zje_rb_value_t) malloc(value_size + 1);
        if (node->value == NULL) {
            ZJE_LOG_ERROR( "fail to allocate a zje_rb_value_t: %s.", strerror(errno));
            // 清理前面开辟的空间
            free(node->key);
            free(node);
            return NULL;
        }
        strncpy(node->value, value, value_size);
        node->value[value_size] = '\0';
    } else {
        // 一定要设置为NULL，否则zje_rb_get函数会出错，而导致程序无故中止
        node->value = NULL;
    }
    
    return node;
}

/*
 * 红黑树 - 左旋
 */
static zje_rb_node_t zje_rb_rotate_left(zje_rb_node_t root, zje_rb_node_t node)
{
    zje_rb_node_t right = node->right;
    if ((node->right = right->left)) {
        right->left->parent = node;
    }
    right->left = node;
    if ((right->parent = node->parent)) {
        if (node == node->parent->right) {
            node->parent->right = right;
        } else {
            node->parent->left = right;
        }
    } else {
        root = right;
    }
    node->parent = right;
    return root;
}

/*
 * 红黑树 - 右旋
 */
static zje_rb_node_t zje_rb_rotate_right(zje_rb_node_t root, zje_rb_node_t node)
{
    zje_rb_node_t left = node->left;
    if ((node->left = left->right)) {
        left->right->parent = node;
    }
    left->right = node;
    if ((left->parent = node->parent)) {
        if (node == node->parent->right) {
            node->parent->right = left;
        } else {
            node->parent->left = left;
        }
    } else {
        root = left;
    }
    node->parent = left;
    return root;
}

/*
 * 红黑树 - 搜索结点的辅助函数
 */
static zje_rb_node_t zje_rb_search_auxiliary(const zje_rb_tree_t tree, const zje_rb_key_t key, zje_rb_node_t *save)
{
    zje_rb_node_t node = tree->root;
    zje_rb_node_t parent = NULL;
    while (node) {
        parent = node;
        int ret = zje_rb_comparator(node->key, key);
        if (0 < ret) {
            node = node->left;
        } else if (0 > ret) {
            node = node->right;
        } else {
            return node;
        }
    }
    if (save) {
        *save = parent;
    }
    
    return NULL;
}

/*
 * 红黑树 - 插入调整
 */
static void zje_rb_insert_rebalance(zje_rb_tree_t tree, zje_rb_node_t node)
{
    zje_rb_node_t parent;
    while ((parent = node->parent) && parent->color == RED) {
        zje_rb_node_t gparent = parent->parent;
        if (parent == gparent->left) {
            zje_rb_node_t uncle = gparent->right;
            if (uncle && uncle->color == RED) {
                uncle->color = BLACK;
                parent->color = BLACK;
                gparent->color = RED;
                node = gparent;
            } else {
                if (parent->right == node) {
                    tree->root = zje_rb_rotate_left(tree->root, parent);
                    zje_rb_node_t tmp = parent;
                    parent = node;
                    node = tmp;
                }
                parent->color = BLACK;
                gparent->color = RED;
                tree->root = zje_rb_rotate_right(tree->root, gparent);
            }
        } else {
            zje_rb_node_t uncle = gparent->left;
            if (uncle && uncle->color == RED) {
                uncle->color = BLACK;
                parent->color = BLACK;
                gparent->color = RED;
                node = gparent;
            } else {
                if (parent->left == node) {
                    tree->root = zje_rb_rotate_right(tree->root, parent);
                    zje_rb_node_t tmp = parent;
                    parent = node;
                    node = tmp;
                }
                parent->color = BLACK;
                gparent->color = RED;
                tree->root = zje_rb_rotate_left(tree->root, gparent);
            }
        }
    }
    tree->root->color = BLACK;
}

/*
 * 红黑树 - 删除调整
 */
static void zje_rb_erase_rebalance(zje_rb_tree_t tree, zje_rb_node_t parent, zje_rb_node_t node)
{
    while ((!node || node->color == BLACK) && node != tree->root) {
        if (parent->left == node) {
            zje_rb_node_t other = parent->right;
            if (other->color == RED) {
                other->color = BLACK;
                parent->color = RED;
                tree->root = zje_rb_rotate_left(tree->root, parent);
                other = parent->right;
            }
            if ((!other->left || other->left->color == BLACK) && (!other->right || other->right->color == BLACK)) {
                other->color = RED;
                node = parent;
                parent = node->parent;
            } else {
                if (!other->right || other->right->color == BLACK) {
                    zje_rb_node_t o_left = other->left;
                    if ((o_left)) {
                        o_left->color = BLACK;
                    }
                    other->color = RED;
                    tree->root = zje_rb_rotate_right(tree->root, other);
                    other = parent->right;
                }
                other->color = parent->color;
                parent->color = BLACK;
                if (other->right) {
                    other->right->color = BLACK;
                }
                tree->root = zje_rb_rotate_left(tree->root, parent);
                node = tree->root;
                break;
            }
        } else {
            zje_rb_node_t other = parent->left;
            if (other->color == RED) {
                other->color = BLACK;
                parent->color = RED;
                tree->root = zje_rb_rotate_right(tree->root, parent);
                other = parent->left;
            }
            if ((!other->left || other->left->color == BLACK) && (!other->right || other->right->color == BLACK)) {
                other->color = RED;
                node = parent;
                parent = node->parent;
            } else {
                if (!other->left || other->left->color == BLACK) {
                    zje_rb_node_t o_right = other->right;
                    if ((o_right)) {
                        o_right->color = BLACK;
                    }
                    other->color = RED;
                    tree->root = zje_rb_rotate_left(tree->root, other);
                    other = parent->left;
                }
                other->color = parent->color;
                parent->color = BLACK;
                if (other->left) {
                    other->left->color = BLACK;
                }
                tree->root = zje_rb_rotate_right(tree->root, parent);
                node = tree->root;
                break;
            }
        }
    }
    if (node) {
        node->color = BLACK;
    }
}

/*
 * 红黑树 - 先序访问指定的结点
 */
static void zje_rb_pre_order_visit(zje_rb_node_t node, void (*operate)(zje_rb_node_t node))
{
    if (node) {
        operate(node);
        zje_rb_pre_order_visit(node->left, operate);
        zje_rb_pre_order_visit(node->right, operate);
    }
}

/*
 * 红黑树 - 中序访问指定的结点
 */
static void zje_rb_in_order_visit(zje_rb_node_t node, void (*operate)(zje_rb_node_t node))
{
    if (node) {
        zje_rb_in_order_visit(node->left, operate);
        operate(node);
        zje_rb_in_order_visit(node->right, operate);
    }
}

/*
 * 红黑树 - 后序访问指定的结点
 */
static void zje_rb_post_order_visit(zje_rb_node_t node, void (*operate)(zje_rb_node_t node))
{
    if (node) {
        zje_rb_post_order_visit(node->left, operate);
        zje_rb_post_order_visit(node->right, operate);
        operate(node);
    }
}

/*
 * 红黑树 - 删除指定的结点
 */
static void zje_rb_delete_node(zje_rb_node_t node)
{
    free(node->key);
    free(node->value);
    free(node);
}

/*
 * 红黑树 - key的比较函数(key为字符串的情况)
 */
static int zje_rb_comparator(const zje_rb_key_t x, const zje_rb_key_t y)
{
    size_t xSize = strlen(x);
    size_t ySize = strlen(y);
    size_t minSize = xSize < ySize ? xSize : ySize;
    return strncmp(x, y, minSize + 1);
}

/*
 * 红黑树 - 创建树
 */
zje_rb_tree_t zje_rb_create(void)
{
    zje_rb_tree_t tree = (zje_rb_tree_t) malloc(sizeof(struct zje_rb_tree_s));
    if (tree == NULL) {
        ZJE_LOG_ERROR( "fail to allocate memory for a zje_rb_tree_t");
        return NULL;
    }
    tree->root = NULL;
    return tree;
}

/*
 * 红黑树 － 插入指定key的结点
 */
int zje_rb_put(zje_rb_tree_t tree, zje_rb_key_t key, zje_rb_value_t value)
{
    if (tree == NULL) {
        ZJE_LOG_ERROR( "'tree' should not be NULL");
        return -1;
    }
    
    zje_rb_node_t parent = NULL;
    zje_rb_node_t node;
    if ((node = zje_rb_search_auxiliary(tree, key, &parent))) {
        // key已存在，不再插入，而是直接更新value
        free(node->value);
        if (value != NULL) {
            size_t size = strlen(value);
            node->value = (zje_rb_value_t) malloc(size + 1);
            if (node->value == NULL) {
                ZJE_LOG_ERROR( "fail to allocate a zje_rb_value_t: %s", strerror(errno));
                return -1;
            }
            strncpy(node->value, value, strlen(value));
            node->value[size] = '\0';
        } else {
            node->value = NULL;
        }
        return 0;
    }
    
    node = zje_rb_create_node(key, value);
    if (node == NULL) {
        ZJE_LOG_ERROR( "fail to create a zje_rb_node_t");
        return -1;
    }
    
    node->parent = parent;
    node->left = node->right = NULL;
    node->color = RED;
    if (parent) {
        if (zje_rb_comparator(parent->key, key) > 0) {
            parent->left = node;
        } else {
            parent->right = node;
        }
    } else {
        tree->root = node;
    }
    zje_rb_insert_rebalance(tree, node);
    
    return 0;
}

/*
 * 红黑树 - 搜索
 */
zje_rb_node_t zje_rb_get(const zje_rb_tree_t tree, const zje_rb_key_t key)
{
    if (tree == NULL) {
        ZJE_LOG_ERROR( "'tree' should not be NULL");
        return NULL;
    }
    return zje_rb_search_auxiliary(tree, key, NULL);
}

/*
 * 红黑树 - 删除指定key的结点
 */
int zje_rb_erase(zje_rb_tree_t tree, zje_rb_key_t key)
{
    if (tree == NULL) {
        ZJE_LOG_ERROR( "'tree' should not be NULL");
        return -1;
    }
    
    zje_rb_node_t child;
    zje_rb_node_t parent;
    zje_rb_node_t old;
    zje_rb_node_t left;
    zje_rb_node_t node;
    zje_rb_color_t color;
    if (!(node = zje_rb_search_auxiliary(tree, key, NULL))) {
        ZJE_LOG_INFO( "the specific zje_rb_node_t is not existed");
        return -1;
    }
    old = node;
    if (node->left && node->right) {
        node = node->right;
        while ((left = node->left) != NULL) {
            node = left;
        }
        child = node->right;
        parent = node->parent;
        color = node->color;
        if (child) {
            child->parent = parent;
        }
        if (parent) {
            if (parent->left == node) {
                parent->left = child;
            } else {
                parent->right = child;
            }
        } else {
            tree->root = child;
        }
        if (node->parent == old) {
            parent = node;
        }
        node->parent = old->parent;
        node->color = old->color;
        node->right = old->right;
        node->left = old->left;
        if (old->parent) {
            if (old->parent->left == old) {
                old->parent->left = node;
            } else {
                old->parent->right = node;
            }
        } else {
            tree->root = node;
        }
        old->left->parent = node;
        if (old->right) {
            old->right->parent = node;
        }
    } else {
        if (!node->left) {
            child = node->right;
        } else if (!node->right) {
            child = node->left;
        }
        parent = node->parent;
        color = node->color;
        if (child) {
            child->parent = parent;
        }
        if (parent) {
            if (parent->left == node) {
                parent->left = child;
            } else {
                parent->right = child;
            }
        } else {
            tree->root = child;
        }
    }
    free(old);
    if (color == BLACK) {
        zje_rb_erase_rebalance(tree, parent, child);
    }
    
    return 0;
}

/*
 * 红黑树 - 先序遍历
 */
void zje_rb_pre_order_traverse(zje_rb_tree_t tree, void (*operate)(zje_rb_node_t node))
{
    if (tree == NULL) {
        ZJE_LOG_ERROR( "'tree' should not be NULL");
        return;
    }
    if (operate == NULL) {
        ZJE_LOG_ERROR( "'operate' should not be NULL");
        return;
    }
    zje_rb_pre_order_visit(tree->root, operate);
}

/*
 * 红黑树 - 中序遍历
 */
void zje_rb_in_order_traverse(zje_rb_tree_t tree, void (*operate)(zje_rb_node_t node))
{
    if (tree == NULL) {
        ZJE_LOG_ERROR( "'tree' should not be NULL");
        return;
    }
    if (operate == NULL) {
        ZJE_LOG_ERROR( "'operate' should not be NULL");
        return;
    }
    zje_rb_in_order_visit(tree->root, operate);
    
}

/*
 * 红黑树 - 后序遍历
 */
void zje_rb_post_order_traverse(zje_rb_tree_t tree, void (*operate)(zje_rb_node_t node))
{
    if (tree == NULL) {
        ZJE_LOG_ERROR( "'tree' should not be NULL");
        return;
    }
    if (operate == NULL) {
        ZJE_LOG_ERROR( "'operate' should not be NULL");
        return;
    }
    zje_rb_post_order_visit(tree->root, operate);
    
}

/*
 * 红黑树 - 删除树
 */
void zje_rb_delete(zje_rb_tree_t tree)
{
    if (tree == NULL) {
        ZJE_LOG_ERROR( "'tree' should not be NULL");
        return;
    }
    zje_rb_post_order_traverse(tree, zje_rb_delete_node);
}
