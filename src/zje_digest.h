/*
 * zje_digest.h
 *
 *  Created on: 2012-9-26
 *      Author: mingshun
 */

#ifndef ZJE_DIGEST_H_
#define ZJE_DIGEST_H_

/*
 * 计算指定路径文件的 md5 摘要信息
 *
 * > 成功返回 md5 摘要信息字符串的首指针，此函数会为 md5 摘要信息分配内存空间，需要调用者自行释放
 * > 失败返回 NULL
 */
char *zje_file_md5(const char *path);

/*
 * 计算指定路径文件的 sha1 摘要信息
 *
 * > 成功返回 sha1 摘要信息字符串的首指针，此函数会为 sha1 摘要信息分配内存空间，需要调用者自行释放
 * > 失败返回 NULL
 */
char *zje_file_sha1(const char *path);

#endif /* ZJE_DIGEST_H_ */
