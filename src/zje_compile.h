/*
 * zje_compile.h
 *
 *  Created on: 2012-1-29
 *      Author: mingshun
 */

#ifndef ZJE_COMPILE_H_
#define ZJE_COMPILE_H_

/*
 * 编译信息结构体
 */
typedef struct {
    // 输入
    char *compiler;         // 编译器
    char *source_path;      // 源文件路径
    char *output_path;      // 编译输出路径
    
    // 输出
    int status;             // 编译器退出状态
    char *compiler_message; // 编译器信息
} zje_compile_t;

/*
 * 向编译命令行映射表添加编译命令行
 */
int zje_add_compile_command(char *compiler, char *command);

/*
 * 编译源程序
 */
int zje_compile(zje_compile_t *info);

#endif /* ZJE_COMPILE_H_ */
