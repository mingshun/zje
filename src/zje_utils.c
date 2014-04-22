/*
 * utils.c
 *
 *  Created on: 2012-1-29
 *      Author: mingshun
 */

#include "zje_utils.h"

#include "zje_log.h"
#include "zje_path.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <signal.h>

#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

static inline int charactor_to_digit(char x);

/*
 * 求最大值
 */
inline int zje_max(int a, int b)
{
    return a > b ? a : b;
}

/*
 * 求最小值
 */
inline int zje_min(int a, int b)
{
    return a < b ? a : b;
}

/*
 * 获取信号详细信息
 */
const char *zje_signal_detail(int signal)
{
    char *signal_names[] = { "SIGZERO",
                             "SIGHUP",
                             "SIGINT",
                             "SIGQUIT",
                             "SIGILL",
                             "SIGTRAP",
                             "SIGABRT",
                             "SIGBUS",
                             "SIGFPE",
                             "SIGKILL",
                             "SIGUSR1",
                             "SIGSEGV",
                             "SIGUSR2",
                             "SIGPIPE",
                             "SIGALRM",
                             "SIGTERM",
                             "SIGSTKFLT",
                             "SIGCHLD",
                             "SIGCONT",
                             "SIGSTOP",
                             "SIGTSTP",
                             "SIGTTIN",
                             "SIGTTOU",
                             "SIGURG",
                             "SIGXCPU",
                             "SIGXFSZ",
                             "SIGVTALRM",
                             "SIGPROF",
                             "SIGWINCH",
                             "SIGIO",
                             "SIGPWR",
                             "SIGSYS" };
    
    if (signal >= sizeof(signal_names) / sizeof(*signal_names) || signal < 0) {
        return "SIG_INVAL";
    }
    return signal_names[signal];
}

/*
 * 获取系统调用名称
 */
const char *zje_syscall_detail(int syscall)
{
    char *syscalls[] = { "sys_ni_syscall",             // 0
                         "sys_exit",
                         "sys_fork",
                         "sys_read",
                         "sys_write",
                         "sys_open",                   // 5
                         "sys_close",
                         "sys_waitpid",
                         "sys_creat",
                         "sys_link",
                         "sys_unlink",                 // 10
                         "sys_execve",
                         "sys_chdir",
                         "sys_time",
                         "sys_mknod",
                         "sys_chmod",                  // 15
                         "sys_lchown16",
                         "sys_ni_syscall",
                         "sys_stat",
                         "sys_lseek",
                         "sys_getpid",                 // 20
                         "sys_mount",
                         "sys_oldumount",
                         "sys_setuid16",
                         "sys_getuid16",
                         "sys_stime",                  // 25
                         "sys_ptrace",
                         "sys_alarm",
                         "sys_fstat",
                         "sys_pause",
                         "sys_utime",                  // 30
                         "sys_ni_syscall",
                         "sys_ni_syscall",
                         "sys_access",
                         "sys_nice",
                         "sys_ni_syscall",             // 35
                         "sys_sync",
                         "sys_kill",
                         "sys_rename",
                         "sys_mkdir",
                         "sys_rmdir",                  // 40
                         "sys_dup",
                         "sys_pipe",
                         "sys_times",
                         "sys_ni_syscall",
                         "sys_brk",                    // 45
                         "sys_setgid16",
                         "sys_getgid16",
                         "sys_signal",
                         "sys_geteuid16",
                         "sys_getegid16",              // 50
                         "sys_acct",
                         "sys_umount",
                         "sys_ni_syscall",
                         "sys_ioctl",
                         "sys_fcntl",                  // 55
                         "sys_ni_syscall",
                         "sys_setpgid",
                         "sys_ni_syscall",
                         "sys_olduname",
                         "sys_umask",                  // 60
                         "sys_chroot",
                         "sys_ustat",
                         "sys_dup2",
                         "sys_getppid",
                         "sys_getpgrp",                // 65
                         "sys_setsid",
                         "sys_sigaction",
                         "sys_sgetmask",
                         "sys_ssetmask",
                         "sys_setreuid16",             // 70
                         "sys_setregid16",
                         "sys_sigsuspend",
                         "sys_sigpending",
                         "sys_sethostname",
                         "sys_setrlimit",              // 75
                         "sys_old_getrlimit",
                         "sys_getrusage",
                         "sys_gettimeofday",
                         "sys_settimeofday",
                         "sys_getgroups16",            // 80
                         "sys_setgroups16",
                         "old_select",
                         "sys_symlink",
                         "sys_lstat",
                         "sys_readlink",               // 85
                         "sys_uselib",
                         "sys_swapon",
                         "sys_reboot",
                         "old_readdir",
                         "old_mmap",                   // 90
                         "sys_munmap",
                         "sys_truncate",
                         "sys_ftruncate",
                         "sys_fchmod",
                         "sys_fchown16",               // 95
                         "sys_getpriority",
                         "sys_setpriority",
                         "sys_ni_syscall",
                         "sys_statfs",
                         "sys_fstatfs",                // 100
                         "sys_ioperm",
                         "sys_socketcall",
                         "sys_syslog",
                         "sys_setitimer",
                         "sys_getitimer",              // 105
                         "sys_newstat",
                         "sys_newlstat",
                         "sys_newfstat",
                         "sys_uname",
                         "sys_iopl",                   // 110
                         "sys_vhangup",
                         "sys_ni_syscall",
                         "sys_vm86old",
                         "sys_wait4",
                         "sys_swapoff",                // 115
                         "sys_sysinfo",
                         "sys_ipc",
                         "sys_fsync",
                         "sys_sigreturn",
                         "sys_clone",                  // 120
                         "sys_setdomainname",
                         "sys_newuname",
                         "sys_modify_ldt",
                         "sys_adjtimex",
                         "sys_mprotect",               // 125
                         "sys_sigprocmask",
                         "sys_create_module",
                         "sys_init_module",
                         "sys_delete_module",
                         "sys_get_kernel_syms",        // 130
                         "sys_quotactl",
                         "sys_getpgid",
                         "sys_fchdir",
                         "sys_bdflush",
                         "sys_sysfs",                  // 135
                         "sys_personality",
                         "sys_ni_syscall",
                         "sys_setfsuid16",
                         "sys_setfsgid16",
                         "sys_llseek",                 // 140
                         "sys_getdents",
                         "sys_select",
                         "sys_flock",
                         "sys_msync",
                         "sys_readv",                  // 145
                         "sys_writev",
                         "sys_getsid",
                         "sys_fdatasync",
                         "sys_sysctl",
                         "sys_mlock",                  // 150
                         "sys_munlock",
                         "sys_mlockall",
                         "sys_munlockall",
                         "sys_sched_setparam",
                         "sys_sched_getparam",         // 155
                         "sys_sched_setscheduler",
                         "sys_sched_getscheduler",
                         "sys_sched_yield",
                         "sys_sched_get_priority_max",
                         "sys_sched_get_priority_min", // 160
                         "sys_sched_rr_get_interval",
                         "sys_nanosleep",
                         "sys_mremap",
                         "sys_setresuid16",
                         "sys_getresuid16",            // 165
                         "sys_vm86",
                         "sys_query_module",
                         "sys_poll",
                         "sys_nfsservctl",
                         "sys_setresgid16",            // 170
                         "sys_getresgid16",
                         "sys_prctl",
                         "sys_rt_sigreturn",
                         "sys_rt_sigaction",
                         "sys_rt_sigprocmask",         // 175
                         "sys_rt_sigpending",
                         "sys_rt_sigtimedwait",
                         "sys_rt_sigqueueinfo",
                         "sys_rt_sigsuspend",
                         "sys_pread",                  // 180
                         "sys_pwrite",
                         "sys_chown16",
                         "sys_getcwd",
                         "sys_capget",
                         "sys_capset",                 // 185
                         "sys_sigaltstack",
                         "sys_sendfile",
                         "sys_ni_syscall",
                         "sys_ni_syscall",
                         "sys_vfork",                  // 190
                         "sys_getrlimit",
                         "sys_mmap2",
                         "sys_truncate64",
                         "sys_ftruncate64",
                         "sys_stat64",                 // 195
                         "sys_lstat64",
                         "sys_fstat64",
                         "sys_lchown",
                         "sys_getuid",
                         "sys_getgid",                 // 200
                         "sys_geteuid",
                         "sys_getegid",
                         "sys_setreuid",
                         "sys_setregid",
                         "sys_getgroups",              // 205
                         "sys_setgroups",
                         "sys_fchown",
                         "sys_setresuid",
                         "sys_getresuid",
                         "sys_setresgid",              // 210
                         "sys_getresgid",
                         "sys_chown",
                         "sys_setuid",
                         "sys_setgid",
                         "sys_setfsuid",               // 215
                         "sys_setfsgid",
                         "sys_pivot_root",
                         "sys_mincore",
                         "sys_madvise",
                         "sys_getdents64",             // 220
                         "sys_fcntl64",
                         "sys_ni_syscall",
                         "sys_ni_syscall",
                         "sys_gettid",
                         "sys_readahead",              // 225
                         "sys_setxattr",
                         "sys_lsetxattr",
                         "sys_fsetxattr",
                         "sys_getxattr",
                         "sys_lgetxattr",              // 230
                         "sys_fgetxattr",
                         "sys_listxattr",
                         "sys_llistxattr",
                         "sys_flistxattr",
                         "sys_removexattr",            // 235
                         "sys_lremovexattr",
                         "sys_fremovexattr",
                         "sys_tkill",
                         "sys_sendfile64" };
    
    if (syscall >= sizeof(syscalls) / sizeof(*syscalls) || syscall < 0) {
        return "sys_ni_syscall";
    }
    return syscalls[syscall];
}

/*
 * 从指定的输入流中读取一行数据，行结束符为"\n"。函数会为字符串分配内存空间，调用者需要负责释放。
 *  > 如果参数 stream 为 NULL，则返回 NULL。
 *  > 如果读取过程中无法分配内存，则返回 NULL。
 */
char *zje_readline(FILE *stream)
{
    const int buf_size = 1024;
    // stream 为 NULL，返回 NULL
    if (stream == NULL) {
        ZJE_LOG_ERROR("'stream' should not be NULL");
        return NULL;
    }
    
    int length = 1;
    char *line = (char *) calloc(length, sizeof(char));
    // 分配内存空间失败，返回 NULL
    if (line == NULL) {
        ZJE_LOG_ERROR("fail to allocate memory: %s", strerror(errno));
        return NULL;
    }
    char buffer[buf_size];
    while (1) {
        // 如果已达到流结束处，则停止读取
        if (fgets(buffer, buf_size, stream) != buffer) {
            break;
        }
        length += strlen(buffer) * sizeof(char);
        char *temp = (char *) realloc(line, length);
        // 分配内存空间失败，返回 NULL
        if (temp == NULL) {
            ZJE_LOG_ERROR("fail to allocate memory: %s", strerror(errno));
            free(line);
            return NULL;
        }
        line = temp;
        
        // 判断是否已经到行结束符
        if (buffer[strlen(buffer) - 1] == '\n') {
            strncat(line, buffer, strlen(buffer) - 1);
            break;
        } else {
            strncat(line, buffer, strlen(buffer));
        }
    }
    
    return line;
}

/*
 * 从指定的路径以字符流形式读取整个文件的内容到字符缓冲区中。函数会为字符缓冲区分配内存空间，调用者需要负责释放。
 *  > 如果参数 path 为 NULL，则返回 NULL。
 *  > 如果打开文件出错，则返回 NULL。
 *  > 如果读取过程中无法分配内存，则返回 NULL。
 */
char *zje_read_file(const char *path)
{
    if (path == NULL) {
        ZJE_LOG_ERROR("'path' should not be NULL");
        return NULL;
    }
    
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to open file '%s': %s", rp, strerror(errno));
        free(rp);

        return NULL;
    }
    
    const int buffer_size = 1024;
    char buffer[buffer_size];
    int content_size = 1;
    char *content = (char *) calloc(1, sizeof(char));
    
    // 取消文件流缓冲
    if (setvbuf(fp, NULL, _IONBF, 0) != 0) {
        ZJE_LOG_ERROR("fail to set no buffer on file stream: %s", strerror(errno));
        content = NULL;
        goto FINALLY;
    }
    
    // 读取文件内容到内存缓冲区
    while (fgets(buffer, buffer_size, fp) != NULL) {
        content_size += buffer_size - 1;
        char *temp = (char *) realloc(content, content_size * sizeof(char));
        if (temp == NULL) {
            ZJE_LOG_ERROR("fail to reallocate memory: %s", strerror(errno));
            content = NULL;
            goto FINALLY;
        }
        content = temp;
        strncat(content, buffer, buffer_size - 1);
    }
    
    // 检查文件操作是否出错
    if (ferror(fp) != 0) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("error occurs when reading file '%s'", rp);
        free(rp);

        content = NULL;
        goto FINALLY;
    }
    
    FINALLY:
    // 关闭文件
    fclose(fp);
    
    return content;
}

/*
 * 寻找指定的字符在给定的字符串中第一次出现的位置。如果没找到指定的字符，返回 -1。
 */
int zje_split_sign_pos(const char *line, int character)
{
    int length = strlen(line);
    for (int i = 0; i < length; ++i) {
        if (line[i] == character) {
            return i;
        }
    }
    return -1;
}

/*
 * 将容量值解析成数值
 */
size_t zje_parse_bytes(const char *string)
{
    int len = strlen(string);
    char str[len + 1];
    snprintf(str, len + 1, "%s", string);
    
    int pos = len - 1;
    for (; pos >= 0 && isspace(str[pos]); --pos) {
        str[pos] = '\0';
    }
    if (pos < 0) {
        return 0;
    }
    
    size_t bytes = strtol(str, NULL, 10);
    if (bytes == 0) {
        return 0;
    }
    
    if (isdigit(str[pos])) {
        return bytes;
    }
    
    switch (str[pos]) {
        case 'b':
        case 'B':
            break;
            
        case 'k':
        case 'K':
            bytes <<= 10;
            break;
            
        case 'm':
        case 'M':
            bytes <<= 20;
            break;
            
        default:
            return 0;
    }
    
    return bytes;
}

/*
 * 判断两个字符串是否相等
 * > 相等返回 1
 * > 不等返回 0
 */
int zje_string_equality(const char *str1, const char *str2)
{
    if (str1 == NULL && str2 == NULL) {
        return 1;
    }

    if ((str1 == NULL && str2 != NULL) || (str1 != NULL && str2 == NULL)) {
        return 0;
    }

    int len1 = strlen(str1);
    int len2 = strlen(str2);
    if (len1 != len2) {
        return 0;
    }
    int len = len1;
    if (strncmp(str1, str2, len) != 0) {
        return 0;
    }
    return 1;
}

/*
 * 将指定的字符转换成相应的数值
 */
static inline int charactor_to_digit(char x)
{
    if ('0' <= x && x <= '9') {
        return x - '0';
    }
    return -1;
}

/*
 * 将指定的字符串转换成相应的数值
 */
int zje_parse_int(const char *s, int *value)
{
    if (s == NULL || strlen(s) == 0) {
        return -1;
    }

    int result = 0;
    int negative = 0;
    int i = 0, len = strlen(s);
    int limit = -INT_MAX;
    int min;
    int digit;

    if (len > 0) {
        char first_char = s[0];
        if (first_char < '0') {             // 可能是“+”或“-”开头
            if (first_char == '-') {
                negative = 1;
                limit = INT_MIN;
            } else if (first_char != '+') {
                return -1;
            }
            if (len == 1) {                 // 不能只有“+”或“-”
                return -1;
            }
            ++i;
        }
        min = limit / 10;
        while (i < len) {
            // 以负数累加，避免在 INT_MAX 附近出错
            digit = charactor_to_digit(s[i++]);
            if (digit < 0) {
                return -1;
            }
            if (result < min) {
                return -1;
            }
            result *= 10;
            if (result < limit + digit) {
                return -1;
            }
            result -= digit;
        }
    } else {
        return -1;
    }
    *value = negative == 1 ? result : -result;
    return 0;
}

