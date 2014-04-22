/*
 * zje_init.c
 *
 *  Created on: 2012-2-21
 *      Author: mingshun
 */
#include "zje_init.h"

#include "zje_config.h"
#include "zje_cpufreq.h"
#include "zje_execute.h"
#include "zje_net.h"
#include "zje_log.h"
#include "zje_utils.h"
#include "zje_workdir.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/termios.h>

static void init_daemon(void);
static void deal_with_args(int argc, char *argv[]);
static void operation_start(void);
static void operation_stop(void);
static void operation_status(void);
static void operation_help(void);
static void show_help(void);
static int is_running(void);

/*
 * 初始化守护进程
 */
static void init_daemon(void)
{
    // 检查进程是否具有root权限
    if (getuid() != 0) {
        fprintf(stderr, "Root permission required.\n");
        exit(1);
    }
    
    // 创建守护进程
    if (daemon(1, 0) == -1) {
        ZJE_FATAL_SYSLOG("fail to create daemon: %s", strerror(errno));
    }
    
    // 打开pid文件
    int pidfd = creat(PID_FILE, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (pidfd == -1) {
        ZJE_FATAL_SYSLOG("fail to open pid file(%s): %s", PID_FILE, strerror(errno));
    }
    
    // 锁定pid文件，实现单例运行
    struct flock lock = { .l_type = F_WRLCK,
                          .l_start = 0,
                          .l_whence = SEEK_SET,
                          .l_len = 0 };
    if (fcntl(pidfd, F_SETLK, &lock) == -1) {
        ZJE_FATAL_SYSLOG("fail to lock pid file(%s): %s", PID_FILE, strerror(errno));
    }
    
    // 清空pid文件
    if (ftruncate(pidfd, 0) == -1) {
        ZJE_FATAL_SYSLOG("fail to truncate pid file(%s) to 0: %s", PID_FILE, strerror(errno));
    }
    
    // 写入pid
    char buffer[50] = { 0 };
    if (sprintf(buffer, "%ld", (long) getpid()) < 0) {
        ZJE_FATAL_SYSLOG("fail to convert pid to string");
    }
    if (write(pidfd, buffer, strlen(buffer)) < strlen(buffer)) {
        ZJE_FATAL_SYSLOG("fail to write pid to pidfile: %s", strerror(errno));
    }
}

/*
 * 处理命令行参数
 */
static void deal_with_args(int argc, char *argv[])
{
    if (argc < 2 || argc > 2) {
        show_help();
        exit(0);
    } else {
        char *operations[] = { "start",
                               "stop",
                               "status",
                               "help" };
        void (*dealers[])() = {operation_start,
            operation_stop,
            operation_status,
            operation_help };
        int operation = -1;
        for (int i = 0; i < sizeof(operations) / sizeof(*operations); ++i) {
            if (zje_string_equality(operations[i], argv[1])) {
                operation = i;
                break;
            }
        }
        if (operation < 0 || operation >= sizeof(operations) / sizeof(*operations)) {
            fprintf(stderr, "Invalid operation.\n");
            exit(1);
        }
        dealers[operation]();
    }
}

/*
 * 处理 start 操作
 */
static void operation_start(void)
{
    // 检查进程是否具有root权限
    if (getuid() != 0) {
        fprintf(stderr, "Root permission required.\n");
        exit(1);
    }
    
    int pid = is_running();
    if (pid > 0) {
        fprintf(stderr, "Zero Judge Engine is running. PID is %d.\n", pid);
        exit(1);
    }
}

/*
 * 处理 stop 操作
 */
static void operation_stop(void)
{
    // 检查进程是否具有root权限
    if (getuid() != 0) {
        fprintf(stderr, "Root permission required.\n");
        exit(1);
    }
    
    // 获取运行状态
    int pid = is_running();
    if (pid == 0) {
        fprintf(stderr, "Zero Judge Engine is not running.\n");
        exit(1);
    }
    
    // 读取发出停止信号，等待信号
    if (setvbuf(stdout, NULL, _IONBF, 0) != 0) {
        fprintf(stderr, "Fail to make standard output stream unbuffered.\n");
        exit(1);
    }
    printf("Zero Judge Engine is running. PID is %d.\n", pid);
    if (kill(pid, SIGTERM) == -1) {
        fprintf(stderr, "Fail to terminate Zero Judge Engine. Retry later.\n");
        exit(1);
    }
    printf("Wait for Zero Judge Engine terminating...  ");
    char busy_char[] = "/-\\|";
    for (int i = 0; is_running(); ++i) {
        printf("\b%c", busy_char[i % strlen(busy_char)]);
        sleep(1);
    }
    printf("\nDone.\n");
    exit(0);
}

/*
 * 处理 status 操作
 */
static void operation_status(void)
{
    // 检查进程是否具有root权限
    if (getuid() != 0) {
        fprintf(stderr, "Root permission required.\n");
        exit(1);
    }
    
    int pid = is_running();
    if (pid > 0) {
        printf("Zero Judge Engine is running. PID is %d.\n", pid);
    } else {
        printf("Zero Judge Engine is not running.\n");
    }
    exit(0);
}

/*
 * 处理 help 操作
 */
static void operation_help(void)
{
    show_help();
    exit(0);
}

/*
 * 显示命令行帮助信息
 */
static void show_help(void)
{
    char *help_lines[] = { "Zero Judge Engine 1.0 - by mingshun (gutspot@qq.com)",
                           "Usage: zje [operation]",
                           "",
                           "Operations:",
                           "\tstart  - start judge engine immediately",
                           "\tstop   - stop judge engine after the current judge task finished",
                           "\tstatus - show status of judge engine",
                           "\thelp   - show this help message" };
    
    for (int i = 0; i < sizeof(help_lines) / sizeof(*help_lines); ++i) {
        printf("%s\n", help_lines[i]);
    }
}

/*
 * 检查是否正在运行，正在运行返回 pid，否则返回 0
 */
static int is_running(void)
{
    // 如果 pid 文件不存在，judge 不在运行
    if (access(PID_FILE, F_OK) == -1) {
        if (errno == ENOENT) {
            return 0;
        }
        ZJE_FATAL_SYSLOG("fail to access pid file(%s): %s", PID_FILE, strerror(errno));
    }
    
    // 打开 pid 文件
    int pidfd = open(PID_FILE, O_RDONLY);
    if (pidfd == -1) {
        ZJE_FATAL_SYSLOG("fail to open pid file(%s): %s", PID_FILE, strerror(errno));
    }
    
    // 获取 pid 文件的锁定状态
    struct flock lock = { .l_start = 0,
                          .l_whence = SEEK_SET,
                          .l_len = 0 };
    if (fcntl(pidfd, F_GETLK, &lock) == -1) {
        ZJE_FATAL_SYSLOG("fail to get lock status of pid file(%s): %s", PID_FILE, strerror(errno));
    }
    // pid 文件已被写锁定，judge 正在运行
    if (lock.l_type == F_WRLCK) {
        // 读取 pid 文件
        char buffer[50] = { 0 };
        int length = read(pidfd, buffer, 50);
        if (length == -1) {
            ZJE_FATAL_SYSLOG("fail to read pid file(%s): %s", PID_FILE, strerror(errno));
        }
        int pid = 0;
        if (sscanf(buffer, "%d", &pid) < 1) {
            ZJE_FATAL_SYSLOG("invalid pid file(%s): %s", PID_FILE, strerror(errno));
        }
        close(pidfd);
        return pid;
    }
    // pid 没被锁定， judge 不在运行
    close(pidfd);
    return 0;
}

/*
 * 初始化 judger
 */
void zje_init(int argc, char *argv[])
{
    // 处理命令行参数
    deal_with_args(argc, argv);
    
    // 关闭日志功能
    zje_log_off();
    
    // 初始化守护进程
    init_daemon();
    
    // 配置 zje 参数
    zje_config();
    
    // 初始化日志功能
    zje_init_log();
    
    // 打开日志功能
    zje_log_on();
    
    // 初始化网络通信模块
    if (zje_init_net() == -1) {
        ZJE_LOG_ERROR("fail to initialize network environment");
        exit(EXIT_FAILURE);
    }
    
    // 初始化 CPU 实际频率
    if (zje_init_cpufreq() == -1) {
        ZJE_LOG_ERROR( "fail to initialize current cpu frequency");
        exit(EXIT_FAILURE);
    }
    
    // 初始化工作目录
    if (zje_init_workdir() == -1) {
        ZJE_LOG_ERROR( "fail to initialize work directory");
        exit(EXIT_FAILURE);
    }

    ZJE_LOG_INFO("zje initialized");
}

