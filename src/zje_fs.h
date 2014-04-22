/*
 * zje_fs.h
 *
 *  Created on: 2012-12-29
 *      Author: mingshun
 */

#ifndef ZJE_FS_H_
#define ZJE_FS_H_

#include <sys/stat.h>

/*
 * 给进程中所有打开的文件描述符添加 CLOSE-ON-EXEC 标志
 */
int zje_set_all_close_on_exec(void);

/*
 * 创建目录
 * > 创建成功或指定的路径已存在且为目录，返回 0
 * > 其他情况返回 -1
 */
int zje_create_directory(const char *path, mode_t mode);

/*
 * 清空目录中的所有文件及目录
 */
int zje_clear_directory(const char *path);

/*
 * 删除指定的目录
 */
int zje_remove_directory(const char *path);

/*
 * 字符串连接
 */
char *zje_string_append(char *source, const char *appendage);

/*
 * 获取文件大小
 */
int zje_file_size(const char *path);

#endif /* ZJE_FS_H_ */
