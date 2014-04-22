/*
 * zje_execute.c
 *
 *  Created on: 2012-1-29
 *      Author: mingshun
 */

#include "zje_execute.h"

#include "zje_cpufreq.h"
#include "zje_fs.h"
#include "zje_log.h"
#include "zje_path.h"
#include "zje_rbtree.h"
#include "zje_utils.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

/*
 * 受监视的用户ID
 */
static uid_t zje_watched_uid = -1;

/*
 * 受监视的用户组ID
 */
static gid_t zje_watched_gid = -1;

/*
 * 进程状态结构体
 */
typedef struct {
    char state; // 进程状态
    int rss; // 驻留物理地址空间大小
} zje_process_t;

static int set_watched_user_id(void);
static int set_limits(int cpu_limit, int mem_limit, int output_limit);
static int get_process_status(pid_t pid, zje_process_t *status);
static int is_restricted_function(int syscall);
static int wait_for_child_init(const pid_t pid);
static int trace_child_process(const pid_t pid, zje_execute_t *info);

/*
 * 设置用户ID和组ID
 */
static int set_watched_user_id(void)
{
    ZJE_LOG_INFO("tries to set watched user to child process, uid: %d, gid: %d", zje_watched_uid, zje_watched_gid);
    
    if (setgid(zje_watched_gid) == -1) {
        ZJE_LOG_ERROR("fail to set group id to %d: %s", zje_watched_gid, strerror(errno));
        return -1;
    }
    if (setuid(zje_watched_uid) == -1) {
        ZJE_LOG_ERROR("fail to set user id to %d: %s", zje_watched_uid, strerror(errno));
        return -1;
    }
    
    // 不能在设置完受监视用户后记录日志，否则会使进程死锁
    
    return 0;
}

/*
 * 设置资源限制：时间(s)、内存(MiB)、文件长度(MiB)
 */
static int set_limits(int cpu_limit, int mem_limit, int output_limit)
{
    struct rlimit rlimit;
    
    // 限制内存使用量
    rlimit.rlim_cur = mem_limit * 1024 * 1024;
    rlimit.rlim_max = mem_limit * 1024 * 1024;
    if (setrlimit(RLIMIT_AS, &rlimit) == -1) {
        ZJE_LOG_ERROR("fail to set memory limit: %s", strerror(errno));
        return -1;
    }
    
    // 限制输出文件长度
    rlimit.rlim_cur = output_limit * 1024 * 1024;
    rlimit.rlim_max = output_limit * 1024 * 1024;
    if (setrlimit(RLIMIT_FSIZE, &rlimit) == -1) {
        ZJE_LOG_ERROR("fail to set output limit: %s", strerror(errno));
        return -1;
    }
    
    // 限制子进程数目
    rlimit.rlim_cur = 1;
    rlimit.rlim_max = 1;
    if (setrlimit(RLIMIT_NPROC, &rlimit) == -1) {
        ZJE_LOG_ERROR("fail to set process limit: %s", strerror(errno));
        return -1;
    }
    
    // 限制生成core文件
    rlimit.rlim_cur = 0;
    rlimit.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &rlimit) == -1) {
        ZJE_LOG_ERROR("fail to set core dump limit: %s", strerror(errno));
        return -1;
    }
    
    // 转换理论时间为实际时间
    // 实际CPU限制时间＝理论CPU限制时间*(基准CPU频率/实际CPU频率)
    double cpufreq = zje_get_cpufreq();
    if (cpufreq < 0) {
        ZJE_LOG_ERROR("fail to get current cpu frequency");
        return -1;
    }
    double cur_time_limit = cpu_limit * (BASE_MHZ / cpufreq);
    
    // 分解实际CPU限制时间为秒和微秒
    double time_sec;
    double time_usec = modf(cur_time_limit, &time_sec) * 1e6;
    
    // 设置用户空间代码执行定时器用于限制子进程CPU时间
    struct itimerval timerval = { .it_value.tv_sec = (long) time_sec,
                                  .it_value.tv_usec = (long) time_usec,
                                  .it_interval.tv_sec = 0,
                                  .it_interval.tv_usec = 0 };
    if (setitimer(ITIMER_PROF, &timerval, NULL) == -1) {
        ZJE_LOG_ERROR("fail to set cpu timer for user process: %s", strerror(errno));
        return -1;
    }
    
    return 0;
}

/*
 * 获取进程状态
 */
static int get_process_status(pid_t pid, zje_process_t *status)
{
    if (status == NULL) {
        ZJE_LOG_ERROR("'status' should not be NULL");
        return -1;
    }
    
    char buffer[2048];
    
    sprintf(buffer, "/proc/%d/stat", pid);
    if (access(buffer, F_OK | R_OK) == -1) {
        ZJE_LOG_DEBUG("the specific process status file(%s) does not exist or be ready for read: %s",
                buffer, strerror(errno));
        return -1;
    }
    
    int proc_stat_file = open(buffer, O_RDONLY);
    if (proc_stat_file == -1) {
        ZJE_LOG_INFO("fail to open the process status file(%s): %s", buffer, strerror(errno));
        return -1;
    }
    int size = read(proc_stat_file, buffer, sizeof(buffer) - 1);
    if (size == -1) {
        ZJE_LOG_INFO("fail to read the process status: %s", strerror(errno));
        close(proc_stat_file);
        return -1;
    }
    close(proc_stat_file);
    buffer[size] = '\0';
    
    int offset = 0;
    char *token = buffer;
    do {
        switch (offset++) {
            case 0: // pid
            case 1: // comm
                break;
            case 2: //state
                if (sscanf(token, "%c", &status->state) != 1) {
                    ZJE_LOG_INFO("fail to retrieve process state: %s", strerror(errno));
                    return -1;
                }
                break;
            case 3: // ppid
            case 4: // pgrp
            case 5: // session
            case 6: // tty_nr
            case 7: // tty_pgrp
            case 8: // flags
            case 9: // min_flt
            case 10: // cmin_flt
            case 11: // maj_flt
            case 12: // cmaj_flt
            case 13: // utime
            case 14: // stime
            case 15: // cutime
            case 16: // cstime
            case 17: // priority
            case 18: // nice
            case 19: // 0
            case 20: // it_real_value
            case 21: // start_time
            case 22: // vsize
                break;
            case 23: // rss
                if (sscanf(token, "%d", &status->rss) != 1) {
                    ZJE_LOG_INFO("fail to retrieve resident set size of process: %s", strerror(errno));
                    return -1;
                }
                break;
            case 24: // rlim_rss
            case 25: // start_code
            case 26: // end_code
            case 27: // start_stack
            case 28: // esp
            case 29: // eip
            case 30: // pending_signal
            case 31: // blocked_signal
            case 32: // sigign
            case 33: // sigcatch
            case 34: // wchan
            case 35: // nswap
            case 36: // cnswap
            case 37: // exit_signal
            case 38: // processor
            default:
                break;
        }
    } while (strsep(&token, " ") != NULL);
    
    return 0;
}

/*
 * 判断指定的系统调用是否被限制
 */
static int is_restricted_function(int syscall)
{
    
    int restricted_functions[] = {
                                   // 进程控制
                                   __NR_fork,
                                   __NR_clone,
                                   __NR_execve,
                                   __NR_setpgid,
                                   __NR_setpriority,
                                   __NR_modify_ldt,
                                   __NR_nanosleep,
                                   __NR_nice,
                                   __NR_pause,
                                   __NR_personality,
                                   __NR_prctl,
                                   __NR_ptrace,
                                   __NR_sched_get_priority_max,
                                   __NR_sched_get_priority_min,
                                   __NR_sched_getparam,
                                   __NR_sched_getscheduler,
                                   __NR_sched_rr_get_interval,
                                   __NR_sched_setparam,
                                   __NR_sched_setscheduler,
                                   __NR_sched_yield,
                                   __NR_vfork,
                                   __NR_waitpid,
                                   __NR_wait4,
                                   __NR_capset,
                                   __NR_setsid,
                                   // 文件系统控制
                                   __NR_fcntl,
                                   __NR_creat,
                                   __NR_readv,
                                   __NR_writev,
                                   __NR_lseek,
                                   __NR_dup,
                                   __NR_dup2,
                                   __NR_flock,
                                   __NR_poll,
                                   __NR_truncate,
                                   __NR_ftruncate,
                                   __NR_umask,
                                   __NR_fsync,
                                   __NR_chdir,
                                   __NR_fchdir,
                                   __NR_chmod,
                                   __NR_fchmod,
                                   __NR_chown,
                                   __NR_fchown,
                                   __NR_lchown,
                                   __NR_chroot,
                                   __NR_stat,
                                   __NR_lstat,
                                   __NR_fstat,
                                   __NR_statfs,
                                   __NR_fstatfs,
                                   __NR_readdir,
                                   __NR_getdents,
                                   __NR_mkdir,
                                   __NR_mknod,
                                   __NR_rmdir,
                                   __NR_rename,
                                   __NR_link,
                                   __NR_symlink,
                                   __NR_unlink,
                                   __NR_readlink,
                                   __NR_mount,
                                   __NR_umount,
                                   __NR_ustat,
                                   __NR_utime,
                                   __NR_utimes,
                                   __NR_quotactl,
                                   // 系统控制
                                   __NR_ioctl,
                                   __NR__sysctl,
                                   __NR_acct,
                                   __NR_getrlimit,
                                   __NR_setrlimit,
                                   __NR_getrusage,
                                   __NR_uselib,
                                   __NR_ioperm,
                                   __NR_iopl,
                                   __NR_reboot,
                                   __NR_swapon,
                                   __NR_swapoff,
                                   __NR_bdflush,
                                   __NR_sysfs,
                                   __NR_sysinfo,
                                   __NR_adjtimex,
                                   __NR_alarm,
                                   __NR_getitimer,
                                   __NR_setitimer,
                                   __NR_settimeofday,
                                   __NR_stime,
                                   __NR_time,
                                   __NR_times,
                                   __NR_vhangup,
                                   __NR_nfsservctl,
                                   __NR_vm86,
                                   __NR_create_module,
                                   __NR_delete_module,
                                   __NR_init_module,
                                   __NR_query_module,
                                   __NR_get_kernel_syms,
                                   // 网络控制
                                   __NR_setdomainname,
                                   __NR_sethostname,
                                   // socket控制
                                   __NR_socketcall,
                                   __NR_select,
                                   __NR_sendfile,
                                   // 用户管理
                                   __NR_setuid,
                                   __NR_setgid,
                                   __NR_setregid,
                                   __NR_setreuid,
                                   __NR_setresgid,
                                   __NR_setresuid,
                                   __NR_setfsgid,
                                   __NR_setfsuid,
                                   __NR_setgroups,
                                   // 进程间通信
                                   __NR_ipc,
                                   __NR_sigaction,
                                   __NR_sigprocmask,
                                   __NR_sigpending,
                                   __NR_sigsuspend,
                                   __NR_signal,
                                   __NR_kill,
                                   __NR_ssetmask,
                                   __NR_pipe,
                                   __NR_rt_sigreturn,
                                   __NR_rt_sigaction,
                                   __NR_rt_sigprocmask,
                                   __NR_rt_sigpending,
                                   __NR_rt_sigtimedwait,
                                   __NR_rt_sigqueueinfo,
                                   __NR_rt_sigsuspend };
    for (int i = 0; i < sizeof(restricted_functions) / sizeof(*restricted_functions); ++i) {
        if (syscall == restricted_functions[i]) {
            ZJE_LOG_INFO("restricted function(%s)", zje_syscall_detail(restricted_functions[i]));
            return syscall;
        }
    }
    
    return 0;
}

/*
 * 等待子进程初始化完成，即sys_execve系统调用之后
 */
static int wait_for_child_init(const pid_t pid)
{
    int failure = 0; // 错误标志
    
    while (1) {
        int status;
        
        waitpid(pid, &status, 0);
        
        // 子进程正常退出
        if (WIFEXITED(status)) {
            ZJE_LOG_ERROR("child process initialization has exited with %d", WEXITSTATUS(status));
            failure = 1;
            break;
        }
        
        // 子进程异常退出(由信号引起的)
        if (WIFSIGNALED(status)) {
            ZJE_LOG_ERROR("child process initialization has terminated by %s", zje_signal_detail(status));
            failure = 1;
            break;
        }
        
        // 如果子进程停止(由信号引起的)
        if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP) {
            ZJE_LOG_ERROR("child process initialization has stopped by %s", zje_signal_detail(WSTOPSIG(status)));
            ptrace(PTRACE_KILL, pid, NULL, NULL);
            continue;
        }
        
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            // 如果无法获取，子进程可能已被杀死或者是父进程没有root权限
            ZJE_LOG_INFO("fail to retrieve registers: %s", strerror(errno));
            continue;
        }
        
        // 出现sys_execve系统调用
        if (regs.orig_eax == __NR_execve) {
            ZJE_LOG_INFO("child process has reached sys_execve");
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            break;
        }
        
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    }
    
    if (failure == 1) {
        return -1;
    }
    return 0;
}

/*
 * 跟踪子进程
 */
static int trace_child_process(const pid_t pid, zje_execute_t *info)
{
    if (pid <= 1) {
        ZJE_LOG_ERROR("'pid' should be greater than 1");
        return -1;
    }
    if (info == NULL) {
        ZJE_LOG_ERROR("'info' should not be NULL");
        return -1;
    }
    // 初始化子进程运行消耗的时间和内存
    info->time_used = 0;
    info->memory_used = 0;
    
    {
        char *rp = zje_resolve_path(info->executable_path);
        ZJE_LOG_INFO("start tracing child process(pid: %d, image-path: %s)", pid, rp);
        free(rp);
    }
    
    if (wait_for_child_init(pid) == -1) {
        ZJE_LOG_ERROR("child process failed to initialize");
        return -1;
    }
    
    // 通过ptrace跟踪子进程的系统调用
    int status;
    struct rusage usage;
    zje_process_t proc_stat = { .state = ' ',
                                .rss = -1 };
    struct user_regs_struct regs;
    int insyscall = 0;
    int syscall = -1;
    int restricted = 0; // 是否是受限的系统调用
    int sys_brk_requested = 0; // 申请分配的空间大小
    while (1) {
        
        // 子进程处于睡眠，立即唤醒
        if (get_process_status(pid, &proc_stat) != -1) {
            if (proc_stat.state == 'S') {
                kill(pid, SIGALRM);
            }
        }
        
        // 非阻塞等待子进程进入或退出系统调用
        if (wait4(pid, &status, WNOHANG, &usage) == 0) {
            continue;
        }
        
        // 收集子进程的内存使用状况
        if (get_process_status(pid, &proc_stat) != -1) {
            int memory_used = proc_stat.rss * getpagesize() / 1024;
            ZJE_LOG_TRACE("proc_stat - state: %c, mem: %d", proc_stat.state, memory_used);
            info->memory_used = zje_max(info->memory_used, memory_used);
        }
        
        // 子进程正常退出
        if (WIFEXITED(status)) {
            info->status = ZJE_EXECUTE_NORMAL;
            info->comment = WEXITSTATUS(status);
            break;
        }
        // 子进程异常退出(由信号引起的)
        if (WIFSIGNALED(status)) {
            // 归类为运行时错误
            if (WTERMSIG(status) != SIGKILL) {
                info->status = ZJE_EXECUTE_RTE;
                info->comment = WTERMSIG(status);
            }
            break;
        }
        
        // 如果子进程停止信号是由SIGXCPU、SIGXFSZ、SIGSEGV引起的，则直接中断子进程
        if (WIFSTOPPED(status)) {
            int signal = WSTOPSIG(status);
            if (signal != SIGTRAP) {
                if (signal == SIGPROF) {
                    // 超出时间限制
                    info->status = ZJE_EXECUTE_TLE;
                    info->comment = -1;
                    ZJE_LOG_INFO("TLE");
                } else if (signal == SIGXFSZ) {
                    // 超出输出限制
                    info->status = ZJE_EXECUTE_OLE;
                    info->comment = -1;
                    ZJE_LOG_INFO("OLE");
                } else {
                    // 其他运行时出错误
                    info->status = ZJE_EXECUTE_RTE;
                    info->comment = signal;
                    ZJE_LOG_INFO("stopped by %s", zje_signal_detail(WSTOPSIG(status)));
                }
                ptrace(PTRACE_KILL, pid, NULL, NULL);
                continue;
            }
        }
        
        // 获取系统调用的寄存器信息
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            // 如果无法获取，子进程可能已被杀死或者是父进程没有root权限
            ZJE_LOG_INFO("fail to retrieve registers: %s", strerror(errno));
            continue;
        }
        
        if (insyscall == 0) {
            insyscall = 1;
            
            // 进入系统调用
            syscall = regs.orig_eax;
            ZJE_LOG_TRACE("entering %s", zje_syscall_detail(syscall));
            
            if (syscall == -1) {
                // 无法获取eax的内容，可能是没有root权限
                
                ZJE_LOG_ERROR("fail to retrieve eax");
                ptrace(PTRACE_KILL, pid, NULL, NULL);
                continue;
                
            } else if (syscall == __NR_brk) {
                // 记录申请分配空间的大小
                sys_brk_requested = regs.ebx;
                
            } else {
                if (is_restricted_function(syscall) != 0) {
                    info->status = ZJE_EXECUTE_RF;
                    info->comment = syscall;
                    restricted = 1;
                }
            }
            
        } else {
            insyscall = 0;
            
            // 退出系统调用
            ZJE_LOG_TRACE("exiting %s", zje_syscall_detail(syscall));
            
            // 对比返回申请分配空间的大小(检查是否超出内存限制)
            if (syscall == __NR_brk) {
                int sys_brk_returned = regs.eax;
                if (sys_brk_requested == 0) {
                    if (sys_brk_returned == 0) {
                        info->status = ZJE_EXECUTE_MLE;
                        info->comment = -1;
                        restricted = 1;
                        ZJE_LOG_INFO("MLE");
                    }
                } else {
                    if (sys_brk_requested != sys_brk_returned) {
                        info->status = ZJE_EXECUTE_MLE;
                        info->comment = -1;
                        restricted = 1;
                        ZJE_LOG_INFO("MLE");
                    }
                }
            }
        }
        
        // 使用了系统调用，停止跟踪子进程，并终止子进程
        if (restricted == 1) {
            ptrace(PTRACE_KILL, pid, NULL, NULL);
            continue;
        }
        
        // 跟踪下一个系统调用
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    }
    
    // 获取程序消耗的CPU时间
    int actual_time_used = usage.ru_utime.tv_sec * 1e6 + usage.ru_utime.tv_usec + usage.ru_stime.tv_sec * 1e6
            + usage.ru_stime.tv_usec;
    
    // 将实际消耗的CPU换算成理论时间
    double cpufreq = zje_get_cpufreq();
    if (cpufreq < 0) {
        ZJE_LOG_ERROR("fail to get current cpu frequency");
        return -1;
    }
    info->time_used = (int) (actual_time_used * (cpufreq / BASE_MHZ) / 1e3);
    
    ZJE_LOG_INFO("actual_time_used: %d, theory_time_used: %dms", actual_time_used, info->time_used);
    
    return 0;
}

/*
 * 跟踪运行单个测试用例
 */
int zje_execute(zje_execute_t *info)
{
    if (info == NULL) {
        ZJE_LOG_ERROR("'info' should not be NULL");
        return -1;
    }
    if (info->id < 0) {
        ZJE_LOG_ERROR("'info->id' should not be less than 0");
        return -1;
    }
    if (info->input_path == NULL || strlen(info->input_path) == 0) {
        ZJE_LOG_ERROR("'info->input_path' should not be NULL or empty");
        return -1;
    }
    if (info->output_path == NULL || strlen(info->output_path) == 0) {
        ZJE_LOG_ERROR("'info->output_path' should not be NULL or empty");
        return -1;
    }
    if (info->executable_path == NULL || strlen(info->executable_path) == 0) {
        ZJE_LOG_ERROR("'info->executable_path' should not be NULL or empty");
        return -1;
    }
    if (info->time_limit < 0) {
        ZJE_LOG_ERROR("'info->time_limit' should not be less than 0");
        return -1;
    }
    if (info->memory_limit < 0) {
        ZJE_LOG_ERROR("'info->memory_limit' should not be less than 0");
        return -1;
    }
    if (info->output_limit < 0) {
        ZJE_LOG_ERROR("'info->output_limit' should not be less than 0");
        return -1;
    }
    
    // 创建子进程
    pid_t pid = fork();
    
    if (pid < 0) {
        ZJE_LOG_ERROR("fail to create child process: %s", strerror(errno));
        return -1;
    }
    
    if (pid == 0) {
        // 启用子进程跟踪
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            ZJE_LOG_ERROR("child process failed to get traced: %s", strerror(errno));
            abort();
        }
        
        // 打开用于重定向标准 I/O 的文件
        int fd_in, fd_out, fd_err;
        if ((fd_in = open(info->input_path, O_RDONLY)) == -1) {
            char *rp = zje_resolve_path(info->input_path);
            ZJE_LOG_ERROR("fail to open file '%s': %s", rp, strerror(errno));
            free(rp);

            abort();
        }
        if ((fd_out = open(info->output_path, O_WRONLY)) == -1) {
            char *rp = zje_resolve_path(info->output_path);
            ZJE_LOG_ERROR("fail to open file '%s': %s", rp, strerror(errno));
            free(rp);

            abort();
        }
        if ((fd_err = open(ZJE_NULL_FILE, O_WRONLY)) == -1) {
            ZJE_LOG_ERROR("fail to open file '%s': %s", ZJE_NULL_FILE, strerror(errno));
            abort();
        }

        // 重定向标准 I/O
        if (dup2(fd_in, STDIN_FILENO) == -1) {
            ZJE_LOG_ERROR("fail to duplicate the file descriptor for standard input stream: %s", strerror(errno));
            abort();
        }
        if (dup2(fd_out, STDOUT_FILENO) == -1) {
            ZJE_LOG_ERROR("fail to duplicate the file descriptor for standard output stream: %s", strerror(errno));
            abort();
        }
        if (dup2(fd_err, STDERR_FILENO) == -1) {
            ZJE_LOG_ERROR("fail to duplicate the file descriptor for standard error output stream: %s",
                    strerror(errno));
            abort();
        }
        
        // 给子进程所有打开文件描述符添加 CLOSE-ON-EXEC 标志
        if (zje_set_all_close_on_exec() == -1) {
            ZJE_LOG_ERROR("fail to set close-on-exec to all file descriptors of the current process");
            abort();
        }

        // 设置子进程的用户 ID 和组 ID 为受监视的用户，以限制不安全操作
        if (set_watched_user_id() == -1) {
            ZJE_LOG_ERROR("fail to set watched user id(%d, %d) in child process", zje_watched_uid, zje_watched_gid);
            abort();
        }
        
        // 设置子进程资源限制
        if (set_limits(info->time_limit, info->memory_limit, info->output_limit) == -1) {
            ZJE_LOG_ERROR("fail to set resource limits in child process");
            abort();
        }
        
        // 载入子进程映像文件
        if (execl(info->executable_path, info->executable_path, NULL) == -1) {
            char *rp = zje_resolve_path(info->executable_path);
            ZJE_LOG_ERROR("fail to execute (image-path: %s): %s", rp, strerror(errno));
            free(rp);

            abort();
        }
        
        // 不可能到达
        exit(0);
    }
    
    // 跟踪子进程
    if (trace_child_process(pid, info) == -1) {
        return -1;
    }
    
    return 0;
}

/*
 * 设置受监视用户的uid和gid
 */
int zje_set_watched_user(const char *user)
{
    errno = 0;
    struct passwd *userinfo = getpwnam(user);
    if (userinfo == NULL) {
        if (errno == 0 || errno == ENOENT || errno == ESRCH || errno == EBADF || errno == EPERM) {
            ZJE_FATAL_SYSLOG("user information of '%s' can not be found", user);
        } else {
            ZJE_FATAL_SYSLOG("error occurs while retrieving user information: %s", strerror(errno));
        }
        return -1;
    }
    
    zje_watched_uid = userinfo->pw_uid;
    zje_watched_gid = userinfo->pw_gid;
    
    return 0;
}
