/*
 * zje_path.c
 *
 *  Created on: 2013-1-9
 *      Author: mingshun
 */

#include "zje_path.h"

#include "zje_log.h"
#include "zje_utils.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>

static char *normalize_path(const char *path);

static char *normalize_path(const char *path)
{
    struct part {
        char *data;
        struct part *last;
        struct part *next;
    };

    struct part *head = NULL;
    int left = 0;

    for (int i = 0; i < strlen(path); ++i) {
        if (path[i] == '/') {
            struct part *node = (struct part *) malloc(sizeof(struct part));
            if (node == NULL) {
                ZJE_LOG_ERROR("fail to allocate memory: %s", strerror(errno));
                return NULL;
            }

            head = node;
            node->last = node->next = NULL;
            if (i == 0) {
                node->data = NULL;
            } else {
                char *temp = (char *) malloc((i + 1) * sizeof(char));
                if (temp == NULL) {
                    free(node);
                    return NULL;
                }
                temp[0] = '\0';
                strncat(temp, path, i);
                node->data = temp;
            }

            // left 处于第一个 “/” 处
            left = i;
            break;
        }
    }

    // 如果没有 “/” 就直接返回路径
    if (head == NULL) {
        char *temp = NULL;
        if (asprintf(&temp, "%s", path) == -1) {
            ZJE_LOG_ERROR("fail to print to allocated string: %s", strerror(errno));
            return NULL;
        }
        return temp;
    }

    int failure = 0;
    // right 处于第一个 “/” 右边
    int right = left + 1;
    struct part *current = head;
    while (right < strlen(path)) {
        if (path[right] == '/') {

            // 处理两个 “/” 相连或 “.” 的情况
            if (right - left == 1 || (right - left == 2 && path[left + 1] == '.')) {
                left = right;
                right = left + 1;
                continue;
            }

            // 其他情况
            struct part *node = (struct part *) malloc(sizeof(struct part));
            if (node == NULL) {
                ZJE_LOG_ERROR("fail to allocate memory: %s", strerror(errno));
                failure = 1;
                goto FINALLY;
            }

            node->data = (char *) malloc((right - left) * sizeof(char));
            if (node->data == NULL) {
                ZJE_LOG_ERROR("fail to allocate memory: %s", strerror(errno));
                failure = 1;
                free(node);
                goto FINALLY;
            }
            node->data[0] = '\0';
            strncat(node->data, path + left + 1, right - left - 1);
            node->last = current;
            node->next = NULL;
            current->next = node;

            left = right;
            current = node;
        }
        ++right;
    }

    // 处理最后一个 “/” 右边且不是 “.”的内容
    if (right - left > 1 && !(right - left == 2 && path[left + 1] == '.')) {
        struct part *node = (struct part *) malloc(sizeof(struct part));
        if (node == NULL) {
            ZJE_LOG_ERROR("fail to allocate memory: %s", strerror(errno));
            failure = 1;
            goto FINALLY;
        }

        node->data = (char *) malloc((right - left) * sizeof(char));
        if (node->data == NULL) {
            ZJE_LOG_ERROR("fail to allocate memory: %s", strerror(errno));
            failure = 1;
            free(node);
            goto FINALLY;
        }
        node->data[0] = '\0';
        strncat(node->data, path + left + 1, right - left - 1);
        node->last = current;
        node->next = NULL;
        current->next = node;

        current = node;
    }

    // 处理 “.” 开头的情况
    current = head;
    if (current != NULL && zje_string_equality(current->data, ".")) {
        free(current->data);

        head = current->next;
        free(current);

        current = head;
        if (current != NULL) {
            current->last = NULL;
        }
    }

    // 如果简化后的路径为空，返回空字符串
    if (head == NULL) {
        char *temp = NULL;
        if (asprintf(&temp, "") == -1) {
            ZJE_LOG_ERROR("fail to print to allocated string: %s", strerror(errno));
            return NULL;
        }
        return temp;
    }

    // 从左向右处理 “..” 的情况
    current = head->next;
    while (current != NULL) {
        // printf("%s\n", current->data);
        if (zje_string_equality(current->data, "..") && current->last != NULL) {
            // printf("%s-%s\n", current->last->data, current->data);
            if (current->last->data == NULL) {
                current->last->next = current->next;
                if (current->next != NULL) {
                    current->next->last = current->last;
                }

                struct part *c = current->next;
                free(current->data);
                free(current);

                current = c;
                continue;

            } else if (!zje_string_equality(current->last->data, "..")) {
                struct part *l = current->last;
                struct part *r = current->next;

                if (l->last == NULL) {
                    head = r;
                } else {
                    l->last->next = r;
                }

                if (r != NULL) {
                    r->last = l->last;
                }

                free(l->data);
                free(l);

                free(current->data);
                free(current);

                current = r;
                continue;
            }
        }
        current = current->next;
    }

    char *result = (char *) malloc(1 * sizeof(char));
    result[0] = '\0';
    current = head;

    while (current != NULL) {
        if (current->data != NULL) {
            char *temp = NULL;
            if (asprintf(&temp, "%s%s", result, current->data) == -1) {
                ZJE_LOG_ERROR("fail to print to allocated string: %s", strerror(errno));
                free(result);
                failure = 1;
                goto FINALLY;
            }

            free(result);
            result = temp;
        }

        if (current->data == NULL || current->next != NULL) {
            char *temp = NULL;
            if (asprintf(&temp, "%s/", result) == -1) {
                ZJE_LOG_ERROR("fail to print to allocated string: %s", strerror(errno));
                free(result);
                failure = 1;
                goto FINALLY;
            }

            free(result);
            result = temp;
        }

        current = current->next;
    }

    FINALLY:
    // 清理链表
    while (head != NULL) {
        struct part *next = head->next;
        free(head->data);
        free(head);
        head = next;
    }
    // 如果出错返回 NULL
    if (failure) {
        fprintf(stderr, "failure\n");
        return NULL;
    }

    return result;
}

char *zje_resolve_path(const char *path)
{
    char *t = normalize_path(path);
    if (t == NULL) {
        ZJE_LOG_ERROR("normalize_path: error occurs while tidying path before getcwd()");
        return NULL;
    }

    if (t[0] == '/') {
        return t;
    }
    // printf("normalize_path: %s\n", t);

    char *r = getcwd(NULL, 0);
    if (r == NULL) {
        ZJE_LOG_ERROR("fail to get current work directory: %s", strerror(errno));
        free(t);
        return NULL;
    }

    char *n = NULL;
    if (asprintf(&n, "%s/%s", r, t) == -1) {
        ZJE_LOG_ERROR("fail to allocate memory: %s", strerror(errno));
        free(r);
        free(t);
        return NULL;
    }
    free(r);
    free(t);
    // printf("getcwd:%s\n", n);

    char *f = normalize_path(n);
    if (f == NULL) {
        ZJE_LOG_ERROR("normalize_path: error occurs while tidying path after getcwd()");
        free(n);
        return NULL;
    }

    free(n);
    return f;
}

