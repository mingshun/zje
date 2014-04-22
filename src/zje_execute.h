/*
 * zje_execute.h
 *
 *  Created on: 2012-1-29
 *      Author: mingshun
 */

#ifndef ZJE_EXECUTE_H_
#define ZJE_EXECUTE_H_

// 程序退出状态
#define ZJE_EXECUTE_NORMAL   0
#define ZJE_EXECUTE_TLE      1
#define ZJE_EXECUTE_MLE      2
#define ZJE_EXECUTE_OLE      3
#define ZJE_EXECUTE_RF       4
#define ZJE_EXECUTE_RTE      5

/*
 * 运行信息结构体
 */
typedef struct {
    // 输入
    int id;                 // 测试数据编号
    char *input_path;       // 输入文件路径
    char *output_path;      // 输出文件路径
    char *executable_path;  // 可执行文件路径
    int time_limit;         // 时间限制(s)
    int memory_limit;       // 空间限制(MiB)
    int output_limit;       // 输出长度限制(MiB)
    
    // 输出
    int status;             // 程序退出状态
    int comment;            // 当status=EXECUTE_NORMAL时，为程序退出返回值
                            // 当status=EXECUTE_RF时，为程序异常中止时所使用的系统调用
    int time_used;          // 消耗的CPU时间(ms)
    int memory_used;        // 消耗的内存量(KiB)
} zje_execute_t;

/*
 * 跟踪运行单个测试用例
 */
int zje_execute(zje_execute_t *info);

/*
 * 设置受监视用户的uid和gid
 */
int zje_set_watched_user(const char *user);

#endif /* ZJE_EXECUTE_H_ */
