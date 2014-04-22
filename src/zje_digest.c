/*
 * zje_digest.c
 *
 *  Created on: 2012-9-26
 *      Author: mingshun
 */

#include "zje_digest.h"

#include "zje_log.h"
#include "zje_path.h"
#include "zje_utils.h"

#include <errno.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include <openssl/evp.h>

/*
 * 计算指定路径文件的 md5 摘要信息
 *
 * > 成功返回 md5 摘要信息字符串的首指针，此函数会为 md5 摘要信息分配内存空间，需要调用者自行释放
 * > 失败返回 NULL
 */
char *zje_file_md5(const char *path)
{
    if (path == NULL) {
        ZJE_LOG_ERROR("'path' should not be NULL");
        return NULL;
    }
    
    const size_t BUFFER_SIZE = 1024;
    unsigned char buffer[BUFFER_SIZE];
    
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to open file '%s': %s", rp, strerror(errno));
        free(rp);

        return NULL;
    }
    
    // 创建信息摘要上下文对象
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (mdctx == NULL) {
        close(fd);
        ZJE_LOG_ERROR("fail to create EVP_MD_CTX");
        return NULL;
    }
    // 设置 md5 摘要算法
    if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) == 0) {
        close(fd);
        EVP_MD_CTX_destroy(mdctx);
        ZJE_LOG_ERROR("fail to initialize digest");
        return NULL;
    }
    
    // 添加数据
    int ret = 0;
    while ((ret = read(fd, buffer, BUFFER_SIZE)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, ret) == 0) {
            close(fd);
            EVP_MD_CTX_destroy(mdctx);
            ZJE_LOG_ERROR("fail to update digest");
            return NULL;
        }
    }
    if (ret == -1) {
        close(fd);
        EVP_MD_CTX_destroy(mdctx);
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to read file '%s': %s", rp, strerror(errno));
        free(rp);

        return NULL;
    }
    close(fd);
    
    // 计算信息摘要
    unsigned char md_value[EVP_MAX_MD_SIZE];
    int md_len;
    if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) == 0) {
        EVP_MD_CTX_destroy(mdctx);
        ZJE_LOG_ERROR("fail to calculate digest");
        return NULL;
    }
    EVP_MD_CTX_destroy(mdctx);
    
    int md5_length = md_len * 2 + 1;
    char *md5 = (char *) calloc(md5_length, sizeof(char));
    if (md5 == NULL) {
        ZJE_LOG_ERROR("fail to allocate menory: %s", strerror(errno));
        return NULL;
    }
    char *temp = md5;
    for (int i = 0; i < md_len; ++i, temp += 2) {
        snprintf(temp, 3, "%02x", md_value[i]);
    }
    
    return md5;
}

/*
 * 计算指定路径文件的 sha1 摘要信息
 *
 * > 成功返回 sha1 摘要信息字符串的首指针，此函数会为 sha1 摘要信息分配内存空间，需要调用者自行释放
 * > 失败返回 NULL
 */
char *zje_file_sha1(const char *path)
{
    if (path == NULL) {
        ZJE_LOG_ERROR("'path' should not be NULL");
        return NULL;
    }
    
    const size_t BUFFER_SIZE = 1024;
    unsigned char buffer[BUFFER_SIZE];
    
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to open file '%s': %s", rp, strerror(errno));
        free(rp);

        return NULL;
    }
    
    // 创建信息摘要上下文对象
    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (mdctx == NULL) {
        close(fd);
        ZJE_LOG_ERROR("fail to create EVP_MD_CTX");
        return NULL;
    }
    // 设置 sha1 摘要算法
    if (EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL) == 0) {
        close(fd);
        EVP_MD_CTX_destroy(mdctx);
        ZJE_LOG_ERROR("fail to initialize digest");
        return NULL;
    }
    
    // 添加数据
    int ret = 0;
    while ((ret = read(fd, buffer, BUFFER_SIZE)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, ret) == 0) {
            close(fd);
            EVP_MD_CTX_destroy(mdctx);
            ZJE_LOG_ERROR("fail to update digest");
            return NULL;
        }
    }
    if (ret == -1) {
        close(fd);
        EVP_MD_CTX_destroy(mdctx);
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to read file '%s': %s", rp, strerror(errno));
        free(rp);

        return NULL;
    }
    close(fd);
    
    // 计算信息摘要
    unsigned char md_value[EVP_MAX_MD_SIZE];
    int md_len;
    if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) == 0) {
        EVP_MD_CTX_destroy(mdctx);
        ZJE_LOG_ERROR("fail to calculate digest");
        return NULL;
    }
    EVP_MD_CTX_destroy(mdctx);
    
    int sha1_length = md_len * 2 + 1;
    char *sha1 = (char *) calloc(sha1_length, sizeof(char));
    if (sha1 == NULL) {
        ZJE_LOG_ERROR("fail to allocate memory: %s", strerror(errno));
        return NULL;
    }
    char *temp = sha1;
    for (int i = 0; i < md_len; ++i, temp += 2) {
        snprintf(temp, 3, "%02x", md_value[i]);
    }
    
    return sha1;
}
