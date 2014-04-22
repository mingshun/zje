/*
 * zje_review.c
 *
 *  Created on: 2012-1-29
 *      Author: mingshun
 */

#include "zje_review.h"

#include "zje_log.h"
#include "zje_path.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline int zje_is_blank(int ch);
static int zje_is_same_completely(FILE * const f1, FILE * const f2);
static int zje_is_same_except_blanks(FILE * const f1, FILE * const f2);

// 判断指定字符是否是空白字符
static inline int zje_is_blank(int ch)
{
    if (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t' || ch == '\v' || ch == '\f' || ch == '\0') {
        return 1;
    }
    return 0;
}

// 判断两个文件内容是否完全相同
static int zje_is_same_completely(FILE * const f1, FILE * const f2)
{
    if (f1 == NULL) {
        ZJE_LOG_ERROR( "'f1' should not be NULL");
        return -1;
    }
    if (f2 == NULL) {
        ZJE_LOG_ERROR( "'f2' should not be NULL");
        return -1;
    }
    
    int c1 = fgetc(f1);
    int c2 = fgetc(f2);
    
    while (c1 != EOF && c2 != EOF) {
        if (c1 != c2) {
            return 1;
        }
        
        c1 = fgetc(f1);
        c2 = fgetc(f2);
    }
    
    // 检查是否出错
    if (ferror(f1) != 0) {
        ZJE_LOG_ERROR( "error occurs while reading 'f1'");
        return -1;
    }
    if (ferror(f2) != 0) {
        ZJE_LOG_ERROR( "error occurs while reading 'f2'");
        return -1;
    }
    
    // 如果只有其中一个为EOF，则不相同
    if (c1 != c2) {
        return 1;
    }
    
    return 0;
}

// 判断两个文件除了空白字符外，文件内容是否相同
static int zje_is_same_except_blanks(FILE * const f1, FILE * const f2)
{
    if (f1 == NULL) {
        ZJE_LOG_ERROR( "'f1' should not be NULL");
        return -1;
    }
    if (f2 == NULL) {
        ZJE_LOG_ERROR( "'f2' should not be NULL");
        return -1;
    }
    
    int c1 = fgetc(f1);
    int c2 = fgetc(f2);
    
    while (c1 != EOF && c2 != EOF) {
        // 忽略空白字符
        while (c1 != EOF && zje_is_blank(c1)) {
            c1 = fgetc(f1);
        }
        while (c2 != EOF && zje_is_blank(c2)) {
            c2 = fgetc(f2);
        }
        
        // 检查是否出错
        if (ferror(f1) != 0) {
            ZJE_LOG_ERROR( "error occurs while reading 'f1'");
            return -1;
        }
        if (ferror(f2) != 0) {
            ZJE_LOG_ERROR( "error occurs while reading 'f2'");
            return -1;
        }
        
        if (c1 != c2) {
            return 1;
        }
        
        c1 = fgetc(f1);
        c2 = fgetc(f2);
    }
    
    // 检查是否出错
    if (ferror(f1) != 0) {
        ZJE_LOG_ERROR( "error occurs while reading 'f1'");
        return -1;
    }
    if (ferror(f2) != 0) {
        ZJE_LOG_ERROR( "error occurs while reading 'f2'");
        return -1;
    }
    
    // 如果只有其中一个为EOF，则不相同
    if (c1 != c2) {
        return 1;
    }
    
    return 0;
}

// 评审
int zje_review(zje_review_t *info)
{
    if (info == NULL) {
        ZJE_LOG_ERROR( "'info' should not be NULL");
        return -1;
    }
    if (info->output_path == NULL) {
        ZJE_LOG_ERROR( "'info->output_path' should not be NULL");
        return -1;
    }
    if (info->answer_path == NULL) {
        ZJE_LOG_ERROR( "'info->answer_path' should not be NULL");
        return -1;
    }
    
    int failure = 0;
    
    FILE *output_path = fopen(info->output_path, "r");
    FILE *answer_path = fopen(info->answer_path, "r");
    if (output_path == NULL) {
        char *rp = zje_resolve_path(info->output_path);
        ZJE_LOG_ERROR( "fail to open the output file '%s': %s", rp, strerror(errno));
        free(rp);

        failure = 1;
        goto finally;
    }
    
    if (answer_path == NULL) {
        char *rp = zje_resolve_path(info->answer_path);
        ZJE_LOG_ERROR( "fail to open the answer file '%s': %s", rp, strerror(errno));
        free(rp);

        failure = 1;
        goto finally;
    }
    
    // 第一次对比：完全逐个字节对比
    int ret1 = zje_is_same_completely(output_path, answer_path);
    if (ret1 == -1) {
        ZJE_LOG_ERROR( "error occurs while comparing files completely");
        failure = 1;
        goto finally;
    }
    if (ret1 == 0) {
        info->result = ZJE_REVIEW_CORRECT;
        goto finally;
    }
    
    // 复位文件指针为第二次对比准备
    rewind(output_path);
    rewind(answer_path);
    
    // 第二次对比：忽略空白字符的逐个字节对比
    int ret2 = zje_is_same_except_blanks(output_path, answer_path);
    if (ret2 == -1) {
        ZJE_LOG_ERROR( "error occurs while comparing files neglecting blanks");
        failure = 1;
        goto finally;
    }
    if (ret2 == 0) {
        info->result = ZJE_REVIEW_WFORMAT;
        goto finally;
    }
    
    info->result = ZJE_REVIEW_WRONG;
    
    finally:
    // 关闭文件
    fclose(output_path);
    fclose(answer_path);
    // 检查是否出错
    if (failure == 1) {
        return -1;
    }
    
    return 0;
}

