/*
 * zje_workdir.c
 *
 *  Created on: 2012-12-17
 *      Author: mingshun
 */

#include "zje_workdir.h"

#include "zje_fs.h"
#include "zje_log.h"
#include "zje_path.h"
#include "zje_utils.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <sched.h>
#include <unistd.h>

#include <sys/mount.h>

// 工作目录
#define WORK_DIR "work"

// 目录权限
#define DIR_MODE S_IRWXU | S_IRWXG | S_IRWXO

// 是否加载了虚拟文件系统
static int is_fs_mounted = 0;

static void remove_workdir(void);
static int is_fs_supported(const char *fs);

/*
 * 卸载虚拟文件系统并删除工作目录，使用atexit()注册，在 zje 正常退出时调用
 */
static void remove_workdir(void)
{
    if (is_fs_mounted) {
        // 卸载已加载的虚拟文件系统
        if (umount(WORK_DIR) == -1) {
            char *rp = zje_resolve_path(WORK_DIR);
            ZJE_LOG_ERROR("fail to unmount target '%s': %s", rp, strerror(errno));
            free(rp);
        }
    }
    
    // 删除工作目录
    if (zje_remove_directory(WORK_DIR) == -1) {
        char *rp = zje_resolve_path(WORK_DIR);
        ZJE_LOG_ERROR("fail to remove directory '%s': %s", rp, strerror(errno));
        free(rp);
    }
}

/*
 * 通过 /proc/filesystems 判断指定的虚拟文件系统是否被当前系统内核支持
 */
static int is_fs_supported(const char *fs)
{
    if (fs == NULL || strlen(fs) == 0) {
        ZJE_LOG_ERROR("'fs' should not be NULL or empty");
        return -1;
    }
    
    const char *path = "/proc/filesystems";
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        ZJE_LOG_ERROR("fail to open file '%s': %s", path, strerror(errno));
        return -1;
    }
    
    int fs_len = strlen(fs);
    char *line;
    while ((line = zje_readline(fp)) != NULL) {
        int line_len = strlen(line);
        if (line_len == 0) {
            break;
        }
        if (line_len < fs_len) {
            continue;
        }
        for (int i = 0; i <= line_len - fs_len; ++i) {
            int flag = 1;
            for (int j = 0; j < fs_len; ++j) {
                if (line[i + j] != fs[j]) {
                    flag = 0;
                    break;
                }
            }
            
            if (flag) {
                fclose(fp);
                return 1;
            }
        }
    }
    fclose(fp);
    return 0;
}

int zje_init_workdir(void)
{
    // 创建工作目录
    if (zje_create_directory(WORK_DIR, DIR_MODE) == -1) {
        char *rp = zje_resolve_path(WORK_DIR);
        ZJE_LOG_ERROR("fail to create directory of path: %s", rp);
        free(rp);

        return -1;
    }
    
    // 向 atexit 注册程序退出时删除工作目录函数
    if (atexit(remove_workdir) != 0) {
        ZJE_LOG_ERROR("fail to register remove_workdir() function with atexit: %s", strerror(errno));
        remove_workdir();
        return -1;
    }
    
    if (is_fs_supported("tmpfs") == 1) {
        // 创建私有 mount 命名空间
        if (unshare(CLONE_NEWNS) == -1) {
            ZJE_LOG_ERROR("fail to disassociate parts of the process execution context: %s", strerror(errno));
            return -1;
        }
        
        if (mount(NULL, WORK_DIR, "tmpfs", 0, NULL) == -1) {
            char *rp = zje_resolve_path(WORK_DIR);
            ZJE_LOG_ERROR("fail to mount tmpfs to directory '%s': %s", rp, strerror(errno));
            free(rp);

            return -1;
        }
        
        {
            char *rp = zje_resolve_path(WORK_DIR);
            ZJE_LOG_INFO("tmpfs has been attached to directory '%s'", rp);
            free(rp);
        }
        is_fs_mounted = 1;
    } else if (is_fs_supported("ramfs") == 1) {
        // 创建私有 mount 命名空间
        if (unshare(CLONE_NEWNS) == -1) {
            ZJE_LOG_ERROR("fail to disassociate parts of the process execution context: %s", strerror(errno));
            return -1;
        }
        
        if (mount(NULL, WORK_DIR, "ramfs", 0, NULL) == -1) {
            char *rp = zje_resolve_path(WORK_DIR);
            ZJE_LOG_ERROR("fail to mount ramfs to directory '%s': %s", rp, strerror(errno));
            free(rp);

            return -1;
        }
        
        {
            char *rp = zje_resolve_path(WORK_DIR);
            ZJE_LOG_INFO("ramfs has been attached to directory '%s'", rp);
            free(rp);
        }
        is_fs_mounted = 1;
    }
    
    return 0;
}

const char *zje_get_workdir(void)
{
    return WORK_DIR;
}
