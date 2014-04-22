/*
 * zje_sj.h
 *
 *  Created on: 2012-10-12
 *      Author: mingshun
 */

#ifndef ZJE_SJ_H_
#define ZJE_SJ_H_

/*
 * Special Judge 信息结构体
 */
typedef struct {
    // 输入
    char *judger_path;      // Special Judge 程序路径
    char *input_path;       // 输入数据文件路径
    char *answer_path;      // 答案数据文件路径
    char *output_path;      // 用户程序输出数据文件路径
    int weight;             // 总分

    // 输出
    int score;              // 得分
    char *comment;          // Special Judge 备注信息
} zje_special_judge_t;

/*
 * 运行 Special Judge 程序对用户程序输出的数据进行评分
 */
int zje_special_judge(zje_special_judge_t *info);

#endif /* ZJE_SJ_H_ */
