/*
 * zje_utils.h
 *
 *  Created on: 2012-1-29
 *      Author: mingshun
 */

#ifndef ZJE_UTILS_H_
#define ZJE_UTILS_H_

#include <stdio.h>

// 特殊设备文件
#define ZJE_NULL_FILE       "/dev/null"
#define ZJE_ZERO_FILE       "/dev/zero"
#define ZJE_FULL_FILE       "/dev/full"

/*
 * 求最大值
 */
extern int zje_max(int a, int b);

/*
 * 求最小值
 */
extern int zje_min(int a, int b);

/*
 * 获取信号详细信息
 */
const char *zje_signal_detail(int signal);

/*
 * 获取系统调用名称
 */
const char *zje_syscall_detail(int syscall);

/*
 * 从指定的输入流中读取一行数据，行结束符为"\n"。函数会为字符串分配内存空间，调用者需要负责释放。
 *  > 如果参数 stream 为 NULL，则返回 NULL。
 *  > 如果读取过程中无法分配内存，则返回 NULL。
 */
char *zje_readline(FILE *stream);

/*
 * 从指定的路径以字符流形式读取整个文件的内容到字符缓冲区中。函数会为字符缓冲区分配内存空间，调用者需要负责释放。
 *  > 如果参数 path 为 NULL，则返回 NULL。
 *  > 如果打开文件出错，则返回 NULL。
 *  > 如果读取过程中无法分配内存，则返回 NULL。
 */
char *zje_read_file(const char *path);

/*
 * 寻找指定的字符在给定的字符串中第一次出现的位置。如果没找到指定的字符，返回 -1。
 */
int zje_split_sign_pos(const char *line, int character);

/*
 * 将容量值解析成数值
 */
size_t zje_parse_bytes(const char *string);

/*
 * 判断两个字符串是否相等
 * > 相等返回 1
 * > 不等返回 0
 */
int zje_string_equality(const char *str1, const char *str2);

/*
 * 将指定的字符串转换成相应的数值
 */
int zje_parse_int(const char *s, int *value);

#endif /* ZJE_UTILS_H_ */

