/*
 * zje_review.h
 *
 *  Created on: 2012-1-29
 *      Author: mingshun
 */

#ifndef ZJE_REVIEW_H_
#define ZJE_REVIEW_H_

// 评审结果
#define ZJE_REVIEW_CORRECT  0
#define ZJE_REVIEW_WFORMAT  1
#define ZJE_REVIEW_WRONG    2

// 评审信息结构体
typedef struct {
    // 输入
    int id;                 // 测试数据编号
    char *output_path;      // 执行答案文件路径
    char *answer_path;    // 标准答案文件路径
    
    // 输出
    int result;             // 评审结果
} zje_review_t;

// 评审
int zje_review(zje_review_t *info);

#endif /* ZJE_REVIEW_H_ */
