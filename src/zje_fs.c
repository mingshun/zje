/*
 * zje_fs.c
 *
 *  Created on: 2012-12-29
 *      Author: mingshun
 */

#include "zje_fs.h"

#include "zje_log.h"
#include "zje_path.h"
#include "zje_utils.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

static int zje_close_on_exec(int fd);

/*
 * 给指定的文件描述符添加 CLOSE-ON-EXEC 标志
 */
static int zje_close_on_exec(int fd)
{
    // 设置 close-on-exec
    int flags = fcntl(fd, F_GETFD);
    if (flags == -1) {
        ZJE_LOG_ERROR("fail to get file descriptor flags: %s", strerror(errno));
        return -1;
    }
    flags |= FD_CLOEXEC;
    if (fcntl(fd, F_SETFD, flags) == -1) {
        ZJE_LOG_ERROR("fail to set file descriptor flags: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * 给进程中所有打开的文件描述符添加 CLOSE-ON-EXEC 标志，除了标准 I/O，即 0、1、2
 */
int zje_set_all_close_on_exec(void)
{
    int fd_dir_len = 1 + snprintf(NULL, 0, "/proc/%d/fd", getpid());
    char fd_dir[fd_dir_len];
    snprintf(fd_dir, fd_dir_len, "/proc/%d/fd", getpid());

    DIR *dir = opendir(fd_dir);
    if (dir == NULL) {
        ZJE_LOG_ERROR("fail to open directory '%s': %s", fd_dir, strerror(errno));
        return -1;
    }

    while (1) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (entry == NULL) {
            if (errno != 0) {
                ZJE_LOG_ERROR("fail to read directory '%s': %s", fd_dir, strerror(errno));
                closedir(dir);
                return -1;
            }

            // 目录的内容已经遍历完
            break;
        }

        struct stat file_status;

        int abs_path_len = 1 + snprintf(NULL, 0, "%s/%s", fd_dir, entry->d_name);
        char abs_path[abs_path_len];
        snprintf(abs_path, abs_path_len, "%s/%s", fd_dir, entry->d_name);

        if (lstat(abs_path, &file_status) == -1) {
            ZJE_LOG_ERROR("fail to retrieve status of '%s': %s", abs_path, strerror(errno));
            closedir(dir);
            return -1;
        }

        errno = 0;
        if (S_ISLNK(file_status.st_mode)) {
            int fd;
            int ret = sscanf(entry->d_name, "%d", &fd);
            if (ret == 0) {
                continue;
            } else if (ret == EOF && errno != 0) {
                ZJE_LOG_ERROR("fail to match format conversion: %s", strerror(errno));
                closedir(dir);
                return -1;
            }

            if (fd > 2) {
                if (zje_close_on_exec(fd) == -1) {
                    ZJE_LOG_ERROR("fail to set close-on-exec to file descriptor(%d)", fd);
                    closedir(dir);
                    return -1;
                }
            }
        }
    }

    closedir(dir);
    return 0;
}

/*
 * 创建目录
 * > 创建成功或指定的路径已存在且为目录，返回 0
 */
int zje_create_directory(const char *path, mode_t mode)
{
    if (path == NULL || strlen(path) == 0) {
        ZJE_LOG_ERROR("'path' should not be NULL or empty");
        return -1;
    }

    struct stat status;
    if (stat(path, &status) == -1) {
        if (errno != ENOENT) {
            // 除不存在的其他错误
            char *rp = zje_resolve_path(path);
            ZJE_LOG_ERROR("fail to get status of '%s': %s", rp, strerror(errno));
            free(rp);

            return -1;
        }
    } else {
        // 如果存在 path，但不是目录
        if (!S_ISDIR(status.st_mode)) {
            char *rp = zje_resolve_path(path);
            ZJE_LOG_ERROR("path '%s' existed, but not a directory", rp);
            free(rp);

            return -1;
        }
        // 已存在 path，且为目录
        return 0;
    }

    if (mkdir(path, mode) == -1) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to create directory '%s': %s", rp, strerror(errno));
        free(rp);

        return -1;
    }
    return 0;
}

/*
 * 清空目录中的所有文件及目录
 */
int zje_clear_directory(const char *path)
{
    DIR *dir = opendir(path);
    if (dir == NULL) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to open directory '%s': %s", rp, strerror(errno));
        free(rp);

        return -1;
    }

    while (1) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (entry == NULL) {
            if (errno != 0) {
                char *rp = zje_resolve_path(path);
                ZJE_LOG_ERROR("fail to read directory '%s': %s", rp, strerror(errno));
                free(rp);

                closedir(dir);
                return -1;
            }

            // 目录的内容已经遍历完
            break;
        }

        struct stat file_status;

        char *abs_path = NULL;
        if (asprintf(&abs_path, "%s/%s", path, entry->d_name) == -1) {
            ZJE_LOG_ERROR("fail to print to allocated string: %s", strerror(errno));
            closedir(dir);
            return -1;
        }

        if (stat(abs_path, &file_status) == -1) {
            char *rp = zje_resolve_path(abs_path);
            ZJE_LOG_ERROR("fail to retrieve status of '%s': %s", rp, strerror(errno));
            free(rp);

            free(abs_path);
            closedir(dir);
            return -1;
        }

        // 遇到目录，递归删除其中的内容
        if (S_ISDIR(file_status.st_mode)) {
            if (!zje_string_equality(entry->d_name, ".") && !zje_string_equality(entry->d_name, "..")) {
                if (zje_remove_directory(abs_path) == -1) {
                    free(abs_path);
                    closedir(dir);
                    return -1;
                }
            }
        } else {
            {
                char *rp = zje_resolve_path(abs_path);
                ZJE_LOG_INFO("removing file '%s'", rp);
                free(rp);
            }
            if (remove(abs_path) == -1) {
                char *rp = zje_resolve_path(abs_path);
                ZJE_LOG_ERROR("fail to remove file '%s': %s", rp, strerror(errno));
                free(rp);

                free(abs_path);
                closedir(dir);
                return -1;
            }
        }
    }

    closedir(dir);
    return 0;
}

/*
 * 删除指定的目录
 */
int zje_remove_directory(const char *path)
{
    {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_INFO("removing directory '%s'", rp);
        free(rp);
    }

    if (zje_clear_directory(path) == -1) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to clear directory '%s': %s", rp, strerror(errno));
        free(rp);

        return -1;
    }

    if (remove(path) == -1) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to remove directory '%s': %s", rp, strerror(errno));
        free(rp);

        return -1;
    }

    return 0;
}

/*
 * 获取文件大小
 */
int zje_file_size(const char *path)
{
    struct stat file_status;

    if (stat(path, &file_status) == -1) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to get files status of '%s': %s", rp, strerror(errno));
        free(rp);

        return -1;
    }

    return (int) file_status.st_size;
}
