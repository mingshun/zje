/*
 * zje_compile.c
 *
 *  Created on: 2012-1-29
 *      Author: mingshun
 */

#include "zje_compile.h"

#include "zje_fs.h"
#include "zje_log.h"
#include "zje_rbtree.h"
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

// 源文件标记
#define SRC_MARK "%SRC%"

// 目标文件标记
#define DEST_MARK "%DEST%"

/*
 * 编译命令行映射表
 */
static zje_rb_tree_t compile_commands_map = NULL;

static void empty_signal_handler(int signo);
static int create_compile_commands_map(void);
static void delete_compile_commands_map(void);
static char **create_compile_args_array(zje_compile_t *info);
static void free_compile_args_array(char **args);

/*
 * 空白信号处理函数，用于子进程进入 pause 后等待父进程发出 SIGINT 时的信号处理函数
 */
static void empty_signal_handler(int signo)
{
    return;
}

/*
 * 建立编译命令行映射表
 */
static int create_compile_commands_map(void)
{
    compile_commands_map = zje_rb_create();
    if (compile_commands_map == NULL) {
        return -1;
    }
    return 0;
}

/*
 * 删除编译命令行映射表，使用atexit()注册，在zje正常退出时调用
 */
static void delete_compile_commands_map(void)
{
    zje_rb_delete(compile_commands_map);
}

/*
 * 构建编译命令行的参数数组
 */
static char **create_compile_args_array(zje_compile_t *info)
{
    zje_rb_node_t compile_command_line_node = zje_rb_get(compile_commands_map, info->compiler);
    if (compile_command_line_node == NULL) {
        ZJE_LOG_ERROR("no compile command line for compiler: %s", info->compiler);
        return NULL;
    }

    const char *compile_command_line = compile_command_line_node->value;
    int command_length = strlen(compile_command_line);
    char command[command_length + 1];
    strncpy(command, compile_command_line, command_length);
    command[command_length] = '\0';
    
    char *buffer = command;
    char *token = NULL;
    int args_length = 0;
    // 计算参数数组长度
    while ((token = strsep(&buffer, " ")) != NULL) {
        ++args_length;
    }
    
    // 填充参数数组内容
    int failure = 0;
    char **args = (char **) calloc(args_length + 1, sizeof(char *));
    if (args == NULL) {
        ZJE_LOG_ERROR("fail to allocate memory for compile arguments array: %s", strerror(errno));
        return NULL;
    }
    strncpy(command, compile_command_line, command_length);
    command[command_length] = '\0';
    buffer = command;
    token = NULL;
    for (int i = 0; i < args_length; ++i) {
        token = strsep(&buffer, " ");
        if (strcmp(token, SRC_MARK) == 0) {
            int length = strlen(info->source_path);
            char *arg = (char*) calloc(length + 1, sizeof(char));
            if (arg == NULL) {
                ZJE_LOG_ERROR("fail to allocate memory for compile argument: %s", strerror(errno));
                failure = 1;
                goto finally;
            }
            strncpy(arg, info->source_path, length);
            args[i] = arg;

        } else if (strcmp(token, DEST_MARK) == 0) {
            int length = strlen(info->output_path);
            char *arg = (char *) calloc(length + 1, sizeof(char));
            if (arg == NULL) {
                ZJE_LOG_ERROR("fail to allocate memory for compile argument: %s", strerror(errno));
                failure = 1;
                goto finally;
            }
            strncpy(arg, info->output_path, length);
            args[i] = arg;

        } else {
            int length = strlen(token);
            char *arg = (char *) calloc(length + 1, sizeof(char));
            if (arg == NULL) {
                ZJE_LOG_ERROR("fail to allocate memory for compile argument: %s", strerror(errno));
                failure = 1;
                goto finally;
            }
            strncpy(arg, token, length);
            args[i] = arg;
        }
    }
    // 数组以NULL结束
    args[args_length] = NULL;
    
    finally:
    // 创建失败，释放已经分配的空间
    if (failure == 1) {
        for (int i = 0; i < args_length; ++i) {
            free(args[i]);
        }
        free(args);
        return NULL;
    }
    
    // 将编译命令行写入日志
    char compile_command[2048] = { 0 };
    for (int i = 0; i < args_length; ++i) {
        if (i > 0) {
            strncat(compile_command, " ", 1);
        }
        strncat(compile_command, args[i], strlen(args[i]));
    }
    
    ZJE_LOG_INFO("execute compile command: %s", compile_command);
    
    return args;
}

/*
 * 释放参数数组
 */
static void free_compile_args_array(char **args)
{
    for (int i = 0; args[i] != NULL; ++i) {
        free(args[i]);
    }
    free(args);
}

/*
 * 向编译命令行映射表添加编译命令行
 */
int zje_add_compile_command(char *compiler, char *command)
{
    // 如果编译命令行映射表不存在，则建立一个
    if (compile_commands_map == NULL) {
        if (create_compile_commands_map() == -1) {
            return -1;
        }
        // 在zje退出时删除编译命令行映射表
        if (atexit(delete_compile_commands_map) != 0) {
            return -1;
        }
    }
    
    // 向编译命令行映射表添加编译命令行
    zje_rb_put(compile_commands_map, compiler, command);
    return 0;
}

/*
 * 编译源程序
 */
int zje_compile(zje_compile_t *info)
{
    if (info == NULL) {
        ZJE_LOG_ERROR("'info' should not be NULL");
        return -1;
    }
    if (info->compiler == NULL || strlen(info->compiler) == 0) {
        ZJE_LOG_ERROR("'info->compiler' should not be NULL or empty");
        return -1;
    }
    if (info->source_path == NULL || strlen(info->source_path) == 0) {
        ZJE_LOG_ERROR("'info->source_path' should not be NULL or empty");
        return -1;
    }
    if (info->output_path == NULL || strlen(info->output_path) == 0) {
        ZJE_LOG_ERROR("'info->output_path' should not be NULL or empty");
        return -1;
    }
    
    info->compiler_message = NULL;

    // 编译源程序
    char **args = create_compile_args_array(info);
    if (args == NULL) {
        ZJE_LOG_ERROR("fail to create compile arguments array");
        return -1;
    }

    // 建立 unix 域套接字
    int fd[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == -1) {
        ZJE_LOG_ERROR("fail to create socket pair: %s", strerror(errno));
        free_compile_args_array(args);
        return -1;
    }
    
    pid_t pid = fork();
    
    if (pid == -1) {
        ZJE_LOG_ERROR("fail to create child process for compilation: %s", strerror(errno));
        free_compile_args_array(args);
        close(fd[0]);
        close(fd[1]);
        return -1;
    }
    
    // 建立子进程编译源程序
    if (pid == 0) {
        // 打开空白文件
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
        if (dup2(fd_null, STDOUT_FILENO) == -1) {
            ZJE_LOG_ERROR("fail to duplicate the file descriptor for standard output stream: %s", strerror(errno));
            abort();
        }
        if (dup2(fd[1], STDERR_FILENO) == -1) {
            ZJE_LOG_ERROR("fail to duplicate the file descriptor for standard error output stream: %s",
                    strerror(errno));
            abort();
        }
        
        // 给子进程所有打开文件描述符添加 CLOSE-ON-EXEC 标志
        if (zje_set_all_close_on_exec() == -1) {
            ZJE_LOG_ERROR( "fail to set close-on-exec to all file descriptors of the current process");
            abort();
        }

        // 记录编译子进程信息到日志中
        ZJE_LOG_INFO("information of child process: pid: %d, ppid: %d", getpid(), getppid());
        
        // 运行编译命令
        if (execvp(args[0], args) == -1) {
            ZJE_LOG_ERROR("fail to load compiler image of compiler '%s': %s", info->compiler, strerror(errno));
            abort();
        }
        
        // 无法到达
        abort();
    }
    
    // 关闭 socketpair 的一端
    close(fd[1]);

    const size_t buffer_size = 256;
    char buffer[buffer_size];

    size_t messageSize = 1;
    char *message = (char *) calloc(messageSize, sizeof(char));

    size_t size = 0;
    pid_t wpid = 0;
    int status;
    int read_failure = 0;
    int malloc_failure = 0;

    // 循环等待子进程结束
    while ((wpid = waitpid(pid, &status, WNOHANG)) == 0) {
        if ((size = read(fd[0], buffer, buffer_size)) == -1) {
            if (read_failure == 0) {
                read_failure = 1;
                ZJE_LOG_ERROR("fail to read data from pipe: %s", strerror(errno));
            }
            continue;
        }

        if (malloc_failure == 0 && size > 0) {
            size_t newSize = messageSize + size;
            char *temp = (char *) realloc(message, newSize * sizeof(char));
            if (temp == NULL) {
                malloc_failure = 1;
                ZJE_LOG_ERROR("fail to reallocate memory: %s", strerror(errno));
                free(message);
                message = NULL;
                messageSize = 0;
                continue;
            }

            message = temp;
            messageSize = newSize;
            strncat(message, buffer, size);
            message[messageSize] = '\0';
        }
    }
    close(fd[0]);

    if (wpid == -1) {
        ZJE_LOG_ERROR("fail to wait the specific child process terminating: %s", strerror(errno));
        return -1;
    }

    if (read_failure == 1 || malloc_failure == 1) {
        return -1;
    }
    
    // 编译器异常退出
    if (!WIFEXITED(status)) {
        ZJE_LOG_WARNING("compiler exited abnormally");
        return -1;
    }
    
    // 编译器正常退出，获取其返回值及编译器信息
    info->status = WEXITSTATUS(status);
    info->compiler_message = message;

    // 释放参数数组
    free_compile_args_array(args);
    
    return 0;
}
