/*
 * zje_sj.c
 *
 *  Created on: 2012-10-12
 *      Author: mingshun
 */

#include "zje_sj.h"

#include "zje_fs.h"
#include "zje_log.h"
#include "zje_path.h"
#include "zje_utils.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

static int parse_result(const char *output, zje_special_judge_t *info);

static int parse_result(const char *output, zje_special_judge_t *info)
{
    // 获取分数
    int pos = 0;
    for (int i = 0; i < strlen(output); ++i) {
        if (output[i] == '\n') {
            pos = i;
            break;
        }
    }

    char *_score = (char *) malloc((pos + 1) * sizeof(char));
    if (_score == NULL) {
        ZJE_LOG_ERROR("fail to allocate memory: %s", strerror(errno));
        return -1;
    }
    _score[0] = '\0';
    strncat(_score, output, pos);

    int score = -1;
    if (zje_parse_int(_score, &score) == -1) {
        ZJE_LOG_ERROR("fail to parse score");
        return -1;
    }
    if (score < 0) {
        ZJE_LOG_ERROR("expect score not to be less than 0, actual %d", score);
        return -1;
    }
    info->score = score;

    int len = strlen(output) - pos;
    char *comment = (char *) malloc(len * sizeof(char));
    if (comment == NULL) {
        ZJE_LOG_ERROR("fail to allocate memory: %s", strerror(errno));
        return -1;
    }
    comment[0] = '\0';
    strncat(comment, output + pos + 1, len - 1);

    for (int i = 0; i < strlen(comment); ++i) {
        if (comment[i] == '\n') {
            comment[i] = '\0';
            break;
        }
    }
    info->comment = comment;

    return 0;
}

/*
 * 运行 Special Judge 程序对用户程序输出的数据进行评分
 */
int zje_special_judge(zje_special_judge_t *info)
{
    if (info == NULL) {
        ZJE_LOG_ERROR("'info' should not be NULL.");
        return -1;
    }

    if (info->judger_path == NULL || strlen(info->judger_path) == 0) {
        ZJE_LOG_ERROR("'info->judger_path' should not be NULL or empty.");
        return -1;
    }
    if (info->input_path == NULL || strlen(info->input_path) == 0) {
        ZJE_LOG_ERROR("'info->input_path' should not be NULL or empty.");
        return -1;
    }
    if (info->answer_path == NULL || strlen(info->answer_path) == 0) {
        ZJE_LOG_ERROR("'info->answer_path' should not be NULL or empty.");
        return -1;
    }
    if (info->output_path == NULL || strlen(info->output_path) == 0) {
        ZJE_LOG_ERROR("'info->output_path' should not be NULL or empty.");
        return -1;
    }
    if (info->weight <= 0) {
        ZJE_LOG_ERROR("'info->weight' should not be greater than 0.");
        return -1;
    }
    
    int fd[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == -1) {
        ZJE_LOG_ERROR("fail to create socket pair: %s", strerror(errno));
        return -1;
    }
    
    pid_t pid = fork();
    
    if (pid < 0) {
        ZJE_LOG_ERROR("fail to create child process for special judge: %s", strerror(errno));
        close(fd[0]);
        close(fd[1]);
        return -1;
    }
    
    if (pid == 0) {
        int fd_null = open(ZJE_NULL_FILE, O_WRONLY);
        if (fd_null == -1) {
            ZJE_LOG_ERROR("fail to open file '%s': %s", ZJE_NULL_FILE, strerror(errno));
            abort();
        }

        // 重定向标准 I/O
        if (dup2(fd_null, STDIN_FILENO) == -1) {
            ZJE_LOG_ERROR("fail to duplicate the file descriptor for standard input stream: %s", strerror(errno));
            abort();
        }
        if (dup2(fd[1], STDOUT_FILENO) == -1) {
            ZJE_LOG_ERROR("fail to duplicate the file descriptor of the socket stream: %s", strerror(errno));
            abort();
        }
        if (dup2(fd_null, STDERR_FILENO) == -1) {
            ZJE_LOG_ERROR("fail to duplicate the file descriptor for standard error output stream: %s",
                    strerror(errno));
            abort();
        }
        
        // 给子进程所有打开文件描述符添加 CLOSE-ON-EXEC 标志
        if (zje_set_all_close_on_exec() == -1) {
            ZJE_LOG_ERROR( "fail to set close-on-exec to all file descriptors of the current process");
            abort();
        }

        const size_t but_size = 256;
        char buf[but_size];
        snprintf(buf, but_size, "%d", info->weight);
        if (execl(info->judger_path, info->judger_path, info->input_path, info->answer_path, info->output_path, buf,
                NULL) == -1) {
            char *rp = zje_resolve_path(info->judger_path);
            ZJE_LOG_ERROR( "fail to execute '%s': %s", rp, strerror(errno));
            free(rp);

            abort();
        }
        
        // 无法到达
        abort();
    }
    
    close(fd[1]);
    
    const size_t buffer_size = 256;
    char buffer[buffer_size];
    
    size_t resultSize = 1;
    char *result = (char *) calloc(resultSize, sizeof(char));
    
    size_t size = 0;
    pid_t wpid = 0;
    int status;
    int read_failure = 0;
    int malloc_failure = 0;
    while ((wpid = waitpid(pid, &status, WNOHANG)) == 0) {
        if ((size = read(fd[0], buffer, buffer_size)) == -1) {
            if (read_failure == 0) {
                read_failure = 1;
                ZJE_LOG_ERROR("fail to read data from pipe: %s", strerror(errno));
            }
            continue;
        }
        
        if (malloc_failure == 0 && size > 0) {
            size_t newSize = resultSize + size;
            char *temp = (char *) realloc(result, newSize * sizeof(char));
            if (temp == NULL) {
                malloc_failure = 1;
                ZJE_LOG_ERROR("fail to reallocate memory: %s", strerror(errno));
                free(result);
                result = NULL;
                resultSize = 0;
                continue;
            }
            
            result = temp;
            resultSize = newSize;
            strncat(result, buffer, size);
            result[resultSize] = '\0';
        }
    }
    close(fd[0]);
    
    if (wpid == -1) {
        ZJE_LOG_ERROR("fail to wait the specific child process terminating: %s", strerror(errno));
        free(result);
        return -1;
    }
    
    if (read_failure == 1 || malloc_failure == 1) {
        free(result);
        return -1;
    }
    
    if (!WIFEXITED(status)) {
        ZJE_LOG_ERROR("child process for special judge terminated abnormally", strerror(errno));
        free(result);
        return -1;
    }
    
    if (parse_result(result, info) == -1) {
        free(result);
        return -1;
    }

    free(result);
    return 0;
}
