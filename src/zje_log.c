/*
 * zje_log.c
 *
 *  Created on: 2012-1-29
 *      Author: mingshun
 */

#include "zje_log.h"

#include "zje_fs.h"
#include "zje_path.h"
#include "zje_utils.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/sem.h>

// 默认日志文件大小: 10MiB
#define DEFAULT_LOG_SIZE    10 << 20

// 默认每天日志文件数目上限: 10
#define DEFAULT_DAILY_LOG_COUNT   10

// 日志文件
#define LOG_FILE    "zje.log"
#define LOG_DIR     "logs/"

// semaphore 权限
#define SEMAPHORE_MODE S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH

// 目录权限
#define DIR_MODE S_IRWXU | S_IRWXG | S_IRWXO

// 文件权限
#define FILE_MODE S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH

// 默认权限掩码
#define DEFAULT_UMASK S_IWGRP | S_IWOTH

// 临时权限掩码
#define TEMPORARY_UMASK 0

// zje 的日志格式
#define LOG_FORMAT "%s [%s] [%d] [%s:%d] [%s] %s\n"

// debug 系统日志格式
#define DEBUG_SYSLOG_FORMAT "[DEBUG] [%d] [%s:%d] [%s] %s"

// fatal 系统日志格式
#define FATAL_SYSLOG_FORMAT "[FATAL] [%d] [%s:%d] [%s] %s"

/*
 * 日志文件大小
 */
static size_t log_size = DEFAULT_LOG_SIZE;

/*
 * 每天日志文件数目上限
 */
static int daily_log_count = DEFAULT_DAILY_LOG_COUNT;

/*
 * 日志级别
 */
static int log_level = ZJE_LOG_LEVEL_WARNING;

/*
 * 日志信号量(保证同时只有一个进程读写日志文件)
 */
static int log_semaphore_id = -1;

/*
 * 1为打开日志，0为关闭日志
 */
static int do_log = 1;

static int get_log_date(char *date_str);
static int get_log_time(char *time_str);
static char *create_log_dir(void);
static int rotate_log_files(const char *log_path);
static int retrieve_log_semaphore(void);
static void release_log_semaphore(void);
static void remove_log_semaphore(void);

/*
 * 构造日期，用于日志文件夹
 */
static int get_log_date(char *date_str)
{
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    if (tm == NULL) {
        ZJE_DEBUG_SYSLOG("fail to get local time: %s", strerror(errno));
        return -1;
    }
    
    // 日期格式为"XXXX-XX-XX"
    if (strftime(date_str, 20, "%F", tm) == 0) {
        ZJE_DEBUG_SYSLOG("fail to format current date");
        return -1;
    }
    
    return 0;
}

/*
 * 构造日志时间
 */
static int get_log_time(char *time_str)
{
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    if (tm == NULL) {
        ZJE_DEBUG_SYSLOG("fail to get local time: %s", strerror(errno));
        return -1;
    }
    
    // 时间格式为"XXXX-XX-XX XX:XX:XX"
    if (strftime(time_str, 20, "%F %T", tm) == 0) {
        ZJE_DEBUG_SYSLOG("fail to format current time");
        return -1;
    }
    
    return 0;
}

/*
 * 创建日志目录，返回日志目录路径
 */
static char *create_log_dir(void)
{
    // 获取当前时间的字符串
    char date_str[20] = { 0 };
    if (get_log_date(date_str) == -1) {
        return NULL;
    }
    
    // "logs/XXXX-XX-XX/"
    char *log_dir = NULL;
    if (asprintf(&log_dir, "%s%s/", LOG_DIR, date_str) == -1) {
        ZJE_DEBUG_SYSLOG("fail to print to allocated string: %s", strerror(errno));
        return NULL;
    }
    
    // 创建 "logs/XXXX-XX-XX/"
    if (zje_create_directory(log_dir, DIR_MODE) == -1) {
        char *rp = zje_resolve_path(log_dir);
        ZJE_DEBUG_SYSLOG("fail to create log directory '%s': %s", rp, strerror(errno));
        free(rp);

        free(log_dir);
        return NULL;
    }
    
    return log_dir;
}

/*
 * 日志文件转档
 */
static int rotate_log_files(const char *log_path)
{
    int i;
    
    // 遍历后缀最大的日志文件
    for (i = 1; i < daily_log_count - 1; ++i) {
        int length = 1 + snprintf(NULL, 0, "%s.%d", log_path, i);
        char path[length];
        snprintf(path, length, "%s.%d", log_path, i);
        // 如果文件不存在，中止循环
        if (access(path, F_OK)) {
            break;
        }
    }
    
    // 如果后缀最大的日志就是第 daily_log_count 个日志，并且存在，则删除
    {
        int length = 1 + snprintf(NULL, 0, "%s.%d", log_path, i);
        char path[length];
        snprintf(path, length, "%s.%d", log_path, i);
        
        if (i == daily_log_count - 1 && access(path, F_OK) == 0) {
            if (remove(path)) {
                char *rp = zje_resolve_path(path);
                ZJE_DEBUG_SYSLOG("fail to remove log file(%s): %s", rp, strerror(errno));
                free(rp);

                return -1;
            }
        }
    }
    
    // {log_path}.{i-1} --> {log_path}.{i}
    for (; i > 1; --i) {
        // {log_path}.{i}
        int length = 1 + snprintf(NULL, 0, "%s.%d", log_path, i);
        char path[length];
        snprintf(path, length, "%s.%d", log_path, i);
        // {log_path}.{i-1}
        int length1 = 1 + snprintf(NULL, 0, "%s.%d", log_path, i - 1);
        char path1[length1];
        snprintf(path1, length1, "%s.%d", log_path, i - 1);
        
        if (rename(path1, path)) {
            char *rp1 = zje_resolve_path(path1);
            char *rp2 = zje_resolve_path(path);
            ZJE_DEBUG_SYSLOG("fail to rename log file '%s' to '%s': %s", rp1, rp2, strerror(errno));
            free(rp1);
            free(rp2);

            return -1;
        }
    }
    
    // {log_path} -- > {log_path}.1
    {
        int length = 1 + snprintf(NULL, 0, "%s.1", log_path);
        char path[length];
        snprintf(path, length, "%s.1", log_path);
        
        if (rename(log_path, path)) {
            char *rp1 = zje_resolve_path(log_path);
            char *rp2 = zje_resolve_path(path);
            ZJE_DEBUG_SYSLOG("fail to rename log file '%s' to '%s': %s", rp1, rp2, strerror(errno));
            free(rp1);
            free(rp2);

            return -1;
        }
    }
    
    return 0;
}

/*
 * 获取旗号
 */
static int retrieve_log_semaphore(void)
{
    struct sembuf buffer = { .sem_num = 0,
                             .sem_op = -1,
                             .sem_flg = 0 };
    if (semop(log_semaphore_id, &buffer, 1)) {
        ZJE_DEBUG_SYSLOG("fail to retrieve log semaphore: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * 释放旗号
 */
static void release_log_semaphore(void)
{
    struct sembuf buffer = { .sem_num = 0,
                             .sem_op = 1,
                             .sem_flg = 0 };
    if (semop(log_semaphore_id, &buffer, 1)) {
        ZJE_DEBUG_SYSLOG("fail to release log semaphore: %s", strerror(errno));
    }
}

/*
 * 删除旗号，使用atexit()注册，在zje正常退出时调用
 */
static void remove_log_semaphore(void)
{
    if (semctl(log_semaphore_id, 0, IPC_RMID)) {
        ZJE_DEBUG_SYSLOG("fail to remove log semaphore: %s", strerror(errno));
    }
}

/*
 * 初始化日志(master)
 */
void zje_init_log(void)
{
    // 修改权限掩码为文件权限
    umask(TEMPORARY_UMASK);
    
    // 创建"./logs/"
    if (zje_create_directory(LOG_DIR, DIR_MODE) == -1) {
        ZJE_FATAL_SYSLOG("fail to create directory for logging: %s", strerror(errno));
    }
    
    // 恢复权限掩码为默认权限掩码
    umask(DEFAULT_UMASK);
    
    // 获取信号量
    log_semaphore_id = semget(IPC_PRIVATE, 1, IPC_CREAT | IPC_EXCL | SEMAPHORE_MODE);
    if (log_semaphore_id == -1) {
        ZJE_FATAL_SYSLOG("fail to create semaphore for logging: %s", strerror(errno));
    }
    
    // 设置信号量的值为1，即二进制旗号
    if (semctl(log_semaphore_id, 0, SETVAL, 1) == -1) {
        ZJE_FATAL_SYSLOG("fail to set value of semaphore for logging: %s", strerror(errno));
    }
    
    // master进程退出时把信号量删除
    if (atexit(remove_log_semaphore) != 0) {
        ZJE_FATAL_SYSLOG("fail to register remove_log_semaphore() function with atexit: %s", strerror(errno));
    }
}

/*
 * 记录日志
 */
void zje_log(int level, const char *loc_file, int loc_line, const char *loc_func, const char *format, ...)
{
    // 程序关闭了日志功能，直接返回
    if (do_log == 0) {
        return;
    }
    
    // 记录的日志级别小于当前日志级别，不记录日志
    if (level < log_level) {
        return;
    }
    
    // 日志内容为空，不记录日志
    if (format == NULL) {
        return;
    }
    
    // 获取当前时间字符串
    char time_str[20] = { 0 };
    if (get_log_time(time_str) == -1) {
        return;
    }
    
    // 解析日志级别
    char *level_str = NULL;
    switch (level) {
        case ZJE_LOG_LEVEL_FATAL:
            level_str = "FATAL";
            break;
            
        case ZJE_LOG_LEVEL_ERROR:
            level_str = "ERROR";
            break;
            
        case ZJE_LOG_LEVEL_WARNING:
            level_str = "WARNING";
            break;
            
        case ZJE_LOG_LEVEL_INFO:
            level_str = "INFO";
            break;
            
        case ZJE_LOG_LEVEL_DEBUG:
            level_str = "DEBUG";
            break;
            
        case ZJE_LOG_LEVEL_TRACE:
            level_str = "TRACE";
            break;
            
        default:
            break;
    }
    if (level_str == NULL) {
        ZJE_DEBUG_SYSLOG("fail to parse log level: %d", level);
        return;
    }
    
    // 获取日志 semaphore
    if (retrieve_log_semaphore() == -1) {
        return;
    }
    
    // 修改权限掩码为文件权限
    umask(TEMPORARY_UMASK);
    
    // 生成日志格式
    int log_format_length = 1
            + snprintf(NULL, 0, LOG_FORMAT, time_str, level_str, getpid(), loc_file, loc_line, loc_func, format);
    char log_format[log_format_length];
    snprintf(log_format, log_format_length, LOG_FORMAT, time_str, level_str, getpid(), loc_file, loc_line, loc_func,
            format);
    
    va_list valist;
    // 计算日志信息长度
    va_start(valist, format);
    int message_length = 1 + vsnprintf(NULL, 0, log_format, valist);
    va_end(valist);
    // 生成日志信息格式
    char message[message_length];
    va_start(valist, format);
    vsnprintf(message, message_length, log_format, valist);
    va_end(valist);
    
    // 日志信息长度有误，返回
    if (message_length < 0) {
        ZJE_DEBUG_SYSLOG("invalid log message length: %d", message_length);
        goto finally;
    }
    // 日志信息长度大于日志文件大小，返回
    if (message_length > log_size) {
        goto finally;
    }
    
    // 日志目录
    char *log_dir = NULL;
    // 日志文件路径
    char *log_path = NULL;
    
    // 创建日志目录
    log_dir = create_log_dir();
    if (log_dir == NULL) {
        goto finally;
    }
    
    // "logs/XXXX-XX-XX/zje.log"
    log_path = NULL;
    if (asprintf(&log_path, "%s%s", log_dir, LOG_FILE) == -1) {
        ZJE_DEBUG_SYSLOG("fail to print to allocated string: %s", strerror(errno));
        goto finally1;
    }
    
    // 已存在日志文件
    if (access(log_path, F_OK) == 0) {
        // 获取日志文件大小
        struct stat sb;
        if (stat(log_path, &sb) == -1) {
            // 获取日志文件大小失败
            char *rp = zje_resolve_path(log_path);
            ZJE_DEBUG_SYSLOG("fail to retrieve file size of '%s': %s", rp, strerror(errno));
            free(rp);

            goto finally1;
        }
        // 日志文件已超过 log_size
        if (message_length + sb.st_size > log_size) {
            // 日志转档
            if (rotate_log_files(log_path)) {
                // 转档失败
                goto finally1;
            }
        }
    }
    
    // 打开日志文件
    int fd = open(log_path, O_WRONLY | O_APPEND | O_CREAT, FILE_MODE);
    // 如果日志文件不可用，直接返回。不记录日志
    if (fd == -1) {
        ZJE_DEBUG_SYSLOG("fail to open log file: %s", strerror(errno));
        goto finally1;
    }
    
    // 写入日志内容
    if (write(fd, message, strlen(message)) == -1) {
        ZJE_DEBUG_SYSLOG("fail to write log file: %s", strerror(errno));
    }
    
    // 关闭文件
    if (close(fd)) {
        ZJE_DEBUG_SYSLOG("fail to close log file: %s", strerror(errno));
    }
    
    finally1:
    // 释放内存
    free(log_path);
    free(log_dir);
    
    finally:
    // 恢复权限掩码为默认权限掩码
    umask(DEFAULT_UMASK);
    
    // 释放日志 semaphore
    release_log_semaphore();
}

/*
 * 设置日志级别
 */
int zje_set_log_level(const char *level_str)
{
    struct level {
        int level_code;
        const char *level_name;
    };
    
    struct level levels[] = { { ZJE_LOG_LEVEL_TRACE,
                                "trace" },
                              { ZJE_LOG_LEVEL_DEBUG,
                                "debug" },
                              { ZJE_LOG_LEVEL_INFO,
                                "info" },
                              { ZJE_LOG_LEVEL_WARNING,
                                "warning" },
                              { ZJE_LOG_LEVEL_ERROR,
                                "error" },
                              { ZJE_LOG_LEVEL_FATAL,
                                "fatal" },
                              { ZJE_LOG_LEVEL_OFF,
                                "off" } };
    
    for (int i = 0; i < sizeof(levels) / sizeof(*levels); ++i) {
        if (zje_string_equality(level_str, levels[i].level_name)) {
            log_level = levels[i].level_code;
            return 0;
        }
    }
    return -1;
}

/*
 * 设置日志文件大小
 */
int zje_set_log_size(const char *size_str)
{
    errno = 0;
    size_t size = zje_parse_bytes(size_str);
    if (errno != 0) {
        ZJE_DEBUG_SYSLOG("fail to parse bytes from string '%s': %s", size_str, strerror(errno));
        return -1;
    }
    if (size < 1) {
        ZJE_DEBUG_SYSLOG("invalid log size '%s'", size_str);
        return -1;
    }
    log_size = size;
    return 0;
}

/*
 * 设置每天日志文件数目上限
 */
int zje_set_daily_log_count(const char *count_str)
{
    errno = 0;
    int count = atoi(count_str);
    if (errno != 0) {
        ZJE_DEBUG_SYSLOG("fail to parse daily log count from string '%s': %s", count_str, strerror(errno));
        return -1;
    }
    if (count < 1) {
        ZJE_DEBUG_SYSLOG("invalid log size '%s'", count_str);
        return -1;
    }
    daily_log_count = count;
    return 0;
}

/*
 * 记录调试日志到 syslog 中(未完成日志功能配置时使用)
 */
void zje_syslog_debug(const char *loc_file, int loc_line, const char *loc_func, const char *format, ...)
{
    int pid = getpid();
    int length = 1 + snprintf(NULL, 0, DEBUG_SYSLOG_FORMAT, pid, loc_file, loc_line, loc_func, format);
    char log_format[length];
    snprintf(log_format, length, DEBUG_SYSLOG_FORMAT, pid, loc_file, loc_line, loc_func, format);
    log_format[length - 1] = '\0';
    
    va_list arglist;
    va_start(arglist, format);
    vsyslog(LOG_EMERG, log_format, arglist);
    va_end(arglist);
}

/*
 * 把错误信息记录到 syslog 中并退出程序(未完成日志功能配置时使用)
 */
void zje_syslog_fatal(const char *loc_file, int loc_line, const char *loc_func, const char *format, ...)
{
    int pid = getpid();
    int length = 1 + snprintf(NULL, 0, FATAL_SYSLOG_FORMAT, pid, loc_file, loc_line, loc_func, format);
    char log_format[length];
    snprintf(log_format, length, FATAL_SYSLOG_FORMAT, pid, loc_file, loc_line, loc_func, format);
    log_format[length - 1] = '\0';
    
    va_list arglist;
    va_start(arglist, format);
    vsyslog(LOG_EMERG, log_format, arglist);
    va_end(arglist);
    
    exit(EXIT_FAILURE);
}

/*
 * 打开日志功能
 */
void zje_log_on(void)
{
    do_log = 1;
}

/*
 * 关闭日志功能
 */
void zje_log_off(void)
{
    do_log = 0;
}
