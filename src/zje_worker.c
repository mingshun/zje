/*
 * zje_worker.c
 *
 *  Created on: 2012-12-17
 *      Author: mingshun
 */

#include "zje_worker.h"

#include "zje_compile.h"
#include "zje_digest.h"
#include "zje_execute.h"
#include "zje_fs.h"
#include "zje_log.h"
#include "zje_net.h"
#include "zje_path.h"
#include "zje_review.h"
#include "zje_sj.h"
#include "zje_stack.h"
#include "zje_utils.h"
#include "zje_workdir.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include "jansson.h"

// 目录权限
#define DIR_MODE S_IRWXU | S_IRWXG | S_IRWXO

// 文件权限
#define FILE_MODE S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH

// 默认权限掩码
#define DEFAULT_UMASK S_IWGRP | S_IWOTH

// 临时权限掩码
#define TEMPORARY_UMASK 0

/*
 * 中止标志
 */
static int terminated = 0;

/*
 * 重试时间间隔
 */
static int retry_interval = 3;

/*
 * 重试次数
 */
static int max_retry_times = 5;

/*
 * worker 目录
 */
static char *worker_dir = NULL;

/*
 * 正在处理任务的 json 对象
 */
static json_t *current_task = NULL;

/*
 * 任务处理结果的 json 对象
 */
static json_t *process_result = NULL;

/*
 * worker 出错信息
 */
static char *worker_error_message = NULL;

/*
 * worker 连续运行失败次数
 */
static int worker_failure_times = 0;

/*
 * special judge 程序路径
 */
static char *special_judge_path = NULL;

/*
 * 临时路径栈
 */
static zje_stack_t temporary_path_stack = NULL;

/*
 * 网络连接对象
 */
static zje_net_connection *connection = NULL;

static void sigterm_handler(int signo);
static int register_sigterm_handler(void);
static void temporary_path_destructor(void *data);
static void worker_destroy(void);
static char *generate_unique_path(const char *suffix);
static const char *code_file_suffix(const char *language);
static int send_json(json_t *json);
static int recv_json(json_t **json);
static int send_command(const char *command, json_t *options, json_t **data);
static int do_handshake(void);
static int take_task(void);
static int finish_task(void);
static int finish_task_with_error(void);
static void clear_temporary_data(void);
static int prepare_file(const char *path, json_t *task, const char *file_content_key, const char *file_size_key,
        const char *file_md5_key, const char *file_sha1_key);
static zje_compile_t *prepare_special_judge_compile_info(void);
static int do_special_judge_compile(zje_compile_t *info);
static zje_compile_t *prepare_compile_info(void);
static int do_compile(zje_compile_t *info);
static zje_execute_t *prepare_execute_info(json_t *node);
static int do_execute(zje_execute_t *info);
static zje_review_t *prepare_review_info(json_t *node);
static int do_review(zje_review_t *info);
static zje_special_judge_t *prepare_special_judge_info(json_t *node);
static int do_special_judge(zje_special_judge_t *info);
static int do_judge();
static int worker_run(void);

/*
 * 中止信号处理函数
 */
static void sigterm_handler(int signo)
{
    if (signo == SIGTERM) {
        terminated = 1;
    }
}

/*
 * 注册中止信号处理函数
 */
static int register_sigterm_handler(void)
{
    // 由 signal 函数的行为在不同版本的 UNIX，甚至不同版本的 Linux 中可能不一致
    // 所以避免使用 signal，用 sigaction 代替，它是符合 POSIX 标准的函数
    struct sigaction act = { .sa_handler = sigterm_handler,
                             .sa_flags = SA_RESTART | SA_NODEFER };
    sigaddset(&act.sa_mask, SIGTERM);
    if (sigaction(SIGTERM, &act, NULL) == -1) {
        ZJE_LOG_ERROR( "fail to register handler for SIGTERM: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * 释放临时路径栈数据内存，用于 zje_stack_pop
 */
static void temporary_path_destructor(void *data)
{
    ZJE_LOG_INFO("free path string: %s", (const char*) data);
    free(data);
}

/*
 * worker 退出前的清理工作，使用atexit()注册，在 worker 进程正常退出时调用
 */
static void worker_destroy(void)
{
    {
        char *rp = zje_resolve_path(worker_dir);
        ZJE_LOG_INFO("destroying worker directory '%s'", rp);
        free(rp);
    }

    if (zje_remove_directory(worker_dir) == -1) {
        char *rp = zje_resolve_path(worker_dir);
        ZJE_LOG_ERROR("fail to remove directory '%s'", rp);
        free(rp);
    }
    free(worker_dir);
}

/*
 * 产生一个在 worker 目录中独一无二的文件名，返回与 worker 目录组成的路径
 * 函数会自行分配内存空间给路径字符串，调用者需要自行 free 掉内存
 */
static char *generate_unique_path(const char *suffix)
{
    const char *format = "%s/%ld.%s";
    if (suffix == NULL || strlen(suffix) == 0) {
        format = "%s/%ld";
    }

    while (1) {
        // 用随机数产生路径
        long r = random();
        char *path = NULL;
        if (asprintf(&path, format, worker_dir, r, suffix) == -1) {
            ZJE_LOG_ERROR("fail to print to allocated string: %s", strerror(errno));
            return NULL;
        }

        // 检查路径是不是存在
        int ret = access(path, F_OK);
        if (ret == -1) {
            if (errno == ENOENT) {
                // 添加到临时路径栈中便于 worker 退出时释放
                if (zje_stack_push(&temporary_path_stack, path) == -1) {
                    char *rp = zje_resolve_path(path);
                    ZJE_LOG_ERROR("fail to add path '%s' to temporary path stack", rp);
                    free(rp);

                    free(path);
                    return NULL;
                }
                // 返回新路径
                return path;

            } else {
                // 其他错误
                char *rp = zje_resolve_path(path);
                ZJE_LOG_ERROR("fail to access '%s': %s", rp, strerror(errno));
                free(rp);

                free(path);
                return NULL;
            }
        }

        // 释放内存
        free(path);
    }

    // 不可能到达
    return NULL;
}

/*
 * 返回编程语言对应的文件后缀名
 */
static const char *code_file_suffix(const char *language)
{
    if (zje_string_equality("c", language)) {
        return "c";
    } else if (zje_string_equality("c++", language)) {
        return "cc";
    } else if (zje_string_equality("pascal", language)) {
        return "pas";
    }

    ZJE_LOG_WARNING("no code file suffix for language: %s", language);
    return NULL;
}

/*
 * 向服务器发送 json 对象
 */
static int send_json(json_t *json)
{
    char *str = json_dumps(json, JSON_COMPACT);

    if (zje_net_send(connection, str) == -1) {
        ZJE_LOG_ERROR("error occurs while sending to server");
        free(str);
        return -1;
    }

    free(str);
    return 0;
}

/*
 * 从服务器接收 json 对象
 */
static int recv_json(json_t **json)
{
    if (json != NULL) {
        *json = NULL;
    }

    char *str = NULL;
    if (zje_net_recv(connection, &str) == -1) {
        ZJE_LOG_ERROR("error occurs while receiving from server");
        return -1;
    }

    json_error_t json_error;
    json_t *obj = json_loads(str, 0, &json_error);
    if (obj == NULL) {
        ZJE_LOG_ERROR("error occurs while parsing data from server: %s at line %d column $d",
                json_error.text, json_error.line, json_error.column);
        free(str);
        return -1;
    }

    free(str);
    if (json != NULL) {
        *json = obj;
    }
    return 0;
}

/*
 * 向服务器发送指令(json 对象)，并接收服务器返回的数据，并解析成 json 对象存放在 data 中
 */
static int send_command(const char *command, json_t *options, json_t **data)
{
    if (data != NULL) {
        *data = NULL;
    }

    json_t *root = json_object();

    json_t *cmd = json_string(command);
    json_object_set(root, "cmd", cmd);

    if (options != NULL) {
        json_object_set(root, "options", json_deep_copy(options));
    }

    if (send_json(root) == -1) {
        ZJE_LOG_ERROR("internal error occurs while sending json object");
        json_decref(root);
        return -1;
    }

    json_decref(root);
    root = NULL;
    if (recv_json(&root) == -1) {
        ZJE_LOG_ERROR("internal error occurs while receiving json object");
        return -1;
    }

    json_t *result = json_object_get(root, "result");
    json_t *reason = json_object_get(root, "reason");
    if (!zje_string_equality("success", json_string_value(result))) {
        if (reason == NULL || json_string_value(reason) == NULL) {
            ZJE_LOG_ERROR("server error message: unknown reason");
        } else {
            ZJE_LOG_ERROR("server error message: %s", json_string_value(reason));
        }
        json_decref(root);
        return 1;
    }

    if (data != NULL && json_object_get(root, "data") != NULL) {
        *data = json_deep_copy(json_object_get(root, "data"));
    }

    json_decref(root);
    return 0;
}

/*
 * 与服务器握手
 */
static int do_handshake(void)
{
    json_t *options = json_object();

    json_t *role = json_string("consumer");
    json_object_set(options, "role", role);

    int ret = send_command("connect", options, NULL);
    json_decref(options);

    return ret;
}

/*
 * 接收任务
 */
static int take_task(void)
{
    json_t *data = NULL;
    int ret = send_command("take task", NULL, &data);
    if (ret != 0) {
        return ret;
    }

    current_task = data;

    process_result = json_object();

    // 如果 submission_id 存在于 current_task 则复制到 process_result
    if (json_object_get(current_task, "submission_id") != NULL) {
        json_object_set(process_result, "submission_id",
                json_deep_copy(json_object_get(current_task, "submission_id")));
    }

    return 0;
}

/*
 * 完成任务
 */
static int finish_task(void)
{
    json_t *result = json_object();
    json_object_set(result, "result", json_deep_copy(process_result));

    int ret = send_command("finish task", result, NULL);
    json_decref(result);
    return ret;
}

static int finish_task_with_error(void)
{
    json_t *error = json_string(worker_error_message);

    int ret = send_command("finish task", error, NULL);
    json_decref(error);
    return ret;
}

/*
 * 清理临时数据
 */
static void clear_temporary_data(void)
{
    // 清理当前任务的 json 对象
    ZJE_LOG_DEBUG("clean current task object");
    json_decref(current_task);
    current_task = NULL;

    // 清理处理结果的 json 对象
    ZJE_LOG_DEBUG("clean process result object");
    json_decref(process_result);
    process_result = NULL;

    // 重置错误信息
    ZJE_LOG_DEBUG("reset worker error message");
    worker_error_message = NULL;

    // 重置 special judge 程序路径为空
    ZJE_LOG_DEBUG("reset special judge path");
    special_judge_path = NULL;

    // 释放临时路径栈中路径占用的内存空间
    ZJE_LOG_DEBUG("clear temporary path stack");
    zje_stack_clear(&temporary_path_stack, temporary_path_destructor);

    // 清理临时文件
    ZJE_LOG_DEBUG("clear worker directory");
    if (zje_clear_directory(worker_dir) == -1) {
        char *rp = zje_resolve_path(worker_dir);
        ZJE_LOG_ERROR("fail to clear directory '%s'", rp);
        free(rp);
    }
}

/*
 * 从 json 对象获取相应的文件信息，并准备好文件保存至指定的路径中，并校验文件摘要信息是否正确
 */
static int prepare_file(const char *path, json_t *task, const char *file_content_key, const char *file_size_key,
        const char *file_md5_key, const char *file_sha1_key)
{
    // 检查参数有效性
    if (path == NULL || strlen(path) == 0) {
        ZJE_LOG_ERROR("'path' should not be NULL or empty");
        return -1;
    }
    if (file_content_key == NULL || strlen(file_content_key) == 0) {
        ZJE_LOG_ERROR("'file_content_key' should not be NULL or empty");
        return -1;
    }
    if (file_size_key == NULL || strlen(file_size_key) == 0) {
        ZJE_LOG_ERROR("'file_size_key' should not be NULL or empty");
        return -1;
    }
    if (file_md5_key == NULL || strlen(file_md5_key) == 0) {
        ZJE_LOG_ERROR("'file_md5_key' should not be NULL or empty");
        return -1;
    }
    if (file_sha1_key == NULL || strlen(file_sha1_key) == 0) {
        ZJE_LOG_ERROR("'file_sha1_key' should not be NULL or empty");
        return -1;
    }

    // 从 json 对象中获取相应的数据

    json_t *file_content_node = json_object_get(task, file_content_key);
    if (!json_is_string(file_content_node)) {
        ZJE_LOG_ERROR("'%s' not found in the task", file_content_key);
        return -1;
    }
    const char *content = json_string_value(file_content_node);
    ZJE_LOG_DEBUG("file content: %s", content);

    json_t *file_size_node = json_object_get(task, file_size_key);
    if (!json_is_integer(file_size_node)) {
        ZJE_LOG_ERROR("'%s' not found in the task", file_size_key);
        return -1;
    }
    int size = json_integer_value(file_size_node);
    ZJE_LOG_DEBUG("file size: %d", size);

    json_t *file_md5_node = json_object_get(task, file_md5_key);
    if (!json_is_string(file_md5_node)) {
        ZJE_LOG_ERROR("'%s' not found in the task", file_md5_key);
        return -1;
    }
    const char *md5 = json_string_value(file_md5_node);
    ZJE_LOG_DEBUG("file md5: %s", md5);

    json_t *file_sha1_node = json_object_get(task, file_sha1_key);
    if (!json_is_string(file_sha1_node)) {
        ZJE_LOG_ERROR("'%s' not found in the task", file_sha1_key);
        return -1;
    }
    const char *sha1 = json_string_value(file_sha1_node);
    ZJE_LOG_DEBUG("file sha1: %s", sha1);

    // 创建文件并写入内容

    int fd = creat(path, FILE_MODE);
    if (fd == -1) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to open file '%s': %s", rp, strerror(errno));
        free(rp);

        return -1;
    }

    if (write(fd, content, strlen(content)) == -1) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to write to file '%s': %s", rp, strerror(errno));
        free(rp);

        return -1;
    }

    if (close(fd) == -1) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to close file '%s': %s", rp, strerror(errno));
        free(rp);

        return -1;
    }
    {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_DEBUG("finish writing file: %s", rp);
        free(rp);
    }

    // 校验文件尺寸
    int _size = zje_file_size(path);
    if (size != _size) {
        ZJE_LOG_ERROR("file size not match, expect %d, actual %d", size, _size);
        return -1;
    }

    // 校验文件 md5 摘要
    char *_md5 = zje_file_md5(path);
    if (!zje_string_equality(md5, _md5)) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("md5 of file '%s' not match, expect %s, actual %s", rp, md5, _md5);
        free(rp);

        free(_md5);
        return -1;
    }
    free(_md5);

    // 校验文件 sha1 摘要
    char *_sha1 = zje_file_sha1(path);
    if (!zje_string_equality(sha1, _sha1)) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("sha1 of file '%s' not match, expect %s, actual %s", rp, sha1, _sha1);
        free(rp);

        free(_sha1);
        return -1;
    }
    free(_sha1);

    return 0;
}

/*
 * 准备 special judge 编译
 */
static zje_compile_t *prepare_special_judge_compile_info(void)
{
    int failure = 0;

    zje_compile_t *info = (zje_compile_t *) malloc(sizeof(zje_compile_t));
    if (info == NULL) {
        ZJE_LOG_ERROR("fail to allocate memory: %s", strerror(errno));
        failure = 1;
        goto FINALLY;
    }

    // 检查有否提供 special judge 代码
    json_t *sj = json_object_get(current_task, "special_judge");
    // 没提供 special judge 代码就返回 compiler 为 NULL 的 info 指针
    if (json_is_null(sj)) {
        info->compiler = NULL;
        info->source_path = NULL;
        info->output_path = NULL;
        info->status = 0;
        info->compiler_message = NULL;
        goto FINALLY;
    }

    json_t *code_language = json_object_get(sj, "code_language");
    char *code_language_value = (char *) json_string_value(code_language);
    if (code_language_value == NULL) {
        ZJE_LOG_ERROR("'code_language' of special judge is not a json string");
        failure = 1;
        goto FINALLY;
    }

    info->compiler = code_language_value;
    info->source_path = generate_unique_path(code_file_suffix(code_language_value));
    info->output_path = generate_unique_path(NULL);
    info->status = 0;
    info->compiler_message = NULL;

    if (prepare_file(info->source_path, sj, "code_file", "code_file_size", "code_file_md5", "code_file_sha1") == -1) {
        ZJE_LOG_ERROR("fail to prepare special judge code file");
        failure = 1;
        goto FINALLY;
    }

    FINALLY:
    // 释放内存空间
    if (failure) {
        free(info);
        return NULL;
    }

    return info;
}

/*
 * 编译 special judge 程序
 */
static int do_special_judge_compile(zje_compile_t *info)
{
    if (info->compiler == NULL) {
        // 没有 special judge 程序，不需要编译
        return 0;
    }

    if (zje_compile(info) == -1) {
        ZJE_LOG_ERROR("fail to compile special judge code");
        return -1;
    }

    // 将编译器输出信息写入日志并清除
    ZJE_LOG_INFO("compiler message while compiling special judge code: %s", info->compiler_message);
    free(info->compiler_message);

    // 编译失败
    if (info->status != 0) {
        special_judge_path = NULL;
        return -1;
    }

    // 编译成功，设置 special judge 程序路径到全局变量
    special_judge_path = info->output_path;

    return 0;
}

/*
 * 准备编译
 */
static zje_compile_t *prepare_compile_info(void)
{
    int failure = 0;

    zje_compile_t *info = (zje_compile_t *) malloc(sizeof(zje_compile_t));
    if (info == NULL) {
        ZJE_LOG_ERROR("fail to allocate memory: %s", strerror(errno));
        failure = 1;
        goto FINALLY;
    }

    json_t *code_language = json_object_get(current_task, "code_language");
    char *code_language_value = (char *) json_string_value(code_language);
    if (code_language == NULL) {
        ZJE_LOG_ERROR("'code_language' of task is not a json string");
        failure = 1;
        goto FINALLY;
    }

    info->compiler = code_language_value;
    info->source_path = generate_unique_path(code_file_suffix(code_language_value));
    info->output_path = generate_unique_path(NULL);
    info->status = 0;
    info->compiler_message = NULL;

    if (prepare_file(info->source_path, current_task, "code_file", "code_file_size", "code_file_md5", "code_file_sha1")
            == -1) {
        ZJE_LOG_ERROR("fail to prepare code file");
        failure = 1;
        goto FINALLY;
    }

    FINALLY:
    // 释放内存空间
    if (failure) {
        free(info);
        return NULL;
    }

    return info;
}

static int do_compile(zje_compile_t *info)
{
    if (zje_compile(info) == -1) {
        ZJE_LOG_ERROR("fail to compile");
        return -1;
    }

    if (info->status == 0) {
        json_t *compile_passed = json_boolean(1);
        json_object_set(process_result, "compile_passed", compile_passed);
    } else {
        json_t *compile_passed = json_boolean(0);
        json_object_set(process_result, "compile_passed", compile_passed);
    }

    char *message = info->compiler_message;
    if (message != NULL && strlen(message) > 0) {
        json_t *compiler_message = json_string(message);
        json_object_set(process_result, "compiler_message", compiler_message);
    } else {
        json_t *compiler_message = json_null();
        json_object_set(process_result, "compiler_message", compiler_message);
    }
    free(message);
    message = NULL;

    return 0;
}

static zje_execute_t *prepare_execute_info(json_t *node)
{
    return NULL;
}

static int do_execute(zje_execute_t *info)
{
    return 0;
}

static zje_review_t *prepare_review_info(json_t *node)
{
    return NULL;
}

static int do_review(zje_review_t *info)
{
    return 0;
}

static zje_special_judge_t *prepare_special_judge_info(json_t *node)
{
    return NULL;
}

static int do_special_judge(zje_special_judge_t *info)
{
    return 0;
}

static int do_judge()
{
    return 0;
}

static int process_task(void)
{
    // 重置错误标志及错误信息
    int failure = 0;

    // 编译 special judge 程序
    zje_compile_t *sj_compile_info = prepare_special_judge_compile_info();
    if (sj_compile_info == NULL) {
        worker_error_message = "error occurs while preparing special judge compile info";
        ZJE_LOG_ERROR("fail to prepare special judge compile info");
        failure = 1;
        goto FINALLY;
    }
    if (do_special_judge_compile(sj_compile_info) == -1) {
        worker_error_message = "error occurs while compiling special judge code";
        ZJE_LOG_ERROR("fail to do compile special judge code");
        free(sj_compile_info);
        failure = 1;
        goto FINALLY;
    }
    free(sj_compile_info);

    // 编译
    zje_compile_t *compile_info = prepare_compile_info();
    if (compile_info == NULL) {
        worker_error_message = "error occurs while preparing compile info";
        ZJE_LOG_ERROR("fail to prepare compile info");
        failure = 1;
        goto FINALLY;
    }
    if (do_compile(compile_info) == -1) {
        worker_error_message = "error occurs while compiling";
        ZJE_LOG_ERROR("fail to do compile");
        free(compile_info);
        failure = 1;
        goto FINALLY;
    }
    free(compile_info);

    // 测试
    if (do_judge() == -1) {
        ZJE_LOG_ERROR("fail to do judge");
        failure = 1;
        goto FINALLY;
    }

    FINALLY:
    // 出错
    if (failure == 1) {
        return -1;
    }
    return 0;
}

static int worker_run(void)
{
    connection = zje_net_connect();
    if (connection == NULL) {
        ZJE_LOG_ERROR("fail to connect to server");
        return -1;
    }

    if (do_handshake() == -1) {
        ZJE_LOG_ERROR("fail to do handshake");
        return -1;
    }

    // 失败标志，如果此标志不为 0，返回错误信息到服务器并清理任务数据
    int failure = 0;

    //while (!terminated) {
    for (int i = 0; i < 3; ++i) {
        // 获取任务
        int take_task_failure = 0;
        int ret = take_task();
        for (int i = 0; i < max_retry_times && ret == 1; ++i, take_task_failure = 1) {
            take_task_failure = 0;
            ZJE_LOG_ERROR("fail to take task, retry in %d seconds", retry_interval);
            sleep(retry_interval);
            ret = take_task();
        }
        if (ret == -1) {
            ZJE_LOG_ERROR("internal network error");
            failure = 1;
            break;
        }
        if (take_task_failure == 1) {
            ZJE_LOG_ERROR("fail to take task in %d consecutive times.", max_retry_times);
            failure = 1;
            break;
        }

        // 处理任务
        int finish_task_failure = 0;
        if (process_task() == -1) {
            int ret = finish_task_with_error();
            for (int i = 0; i < max_retry_times && ret == 1; ++i, finish_task_failure = 1) {
                finish_task_failure = 0;
                ZJE_LOG_ERROR("fail to finish task, retry in %d seconds", retry_interval);
                sleep(retry_interval);
                ret = finish_task_with_error();
            }
            if (ret == -1) {
                ZJE_LOG_ERROR("internal network error");
                failure = 1;
                break;
            }
            if (finish_task_failure == 1) {
                ZJE_LOG_ERROR("fail to finish task with error in %d consecutive times.", max_retry_times);
                failure = 1;
                break;
            }

        } else {
            int ret = finish_task();
            for (int i = 0; i < max_retry_times && ret == 1; ++i, finish_task_failure = 1) {
                finish_task_failure = 0;
                ZJE_LOG_ERROR("fail to finish task, retry in %d seconds", retry_interval);
                sleep(retry_interval);
                ret = finish_task_with_error();
            }
            if (ret == -1) {
                ZJE_LOG_ERROR("internal network error");
                failure = 1;
                break;
            }
            if (finish_task_failure == 1) {
                ZJE_LOG_ERROR("fail to finish task in %d consecutive times.", max_retry_times);
                failure = 1;
                break;
            }
        }

        // 清理全局任务信息
        clear_temporary_data();
    }
    //}

    // 清理全局任务信息
    clear_temporary_data();
    zje_net_disconnect(connection);
    connection = NULL;

    if (failure == 1) {
        return -1;
    }

    return 0;
}

/*
 * 工作进程初始化
 */
int zje_worker_init(void)
{
    // 设置随机数种子
    srandom(time(NULL) + getpid());

    // 创建 worker 的工作目录
    if (asprintf(&worker_dir, "%s/%d", zje_get_workdir(), getpid()) == -1) {
        ZJE_LOG_ERROR("fail to print to allocated string: %s", strerror(errno));
        return -1;
    }

    if (atexit(worker_destroy) != 0) {
        ZJE_LOG_ERROR("fail to register worker_destroy() function with atexit: %s", strerror(errno));
        free(worker_dir);
        return -1;
    }

    // 注册中止信号处理函数
    if (register_sigterm_handler() == -1) {
        return -1;;
    }

    // 修改权限掩码为文件权限
    umask(TEMPORARY_UMASK);
    // 创建"./logs/"
    if (zje_create_directory(worker_dir, DIR_MODE) == -1) {
        char *rp = zje_resolve_path(worker_dir);
        ZJE_LOG_ERROR("fail to create directory '%s' for worker: %s", rp, strerror(errno));
        free(rp);

        return -1;
    }
    // 恢复权限掩码为默认权限掩码
    umask(DEFAULT_UMASK);
    {
        char *rp = zje_resolve_path(worker_dir);
        ZJE_LOG_INFO("worker directory '%s' created", rp);
        free(rp);
    }

    temporary_path_stack = zje_stack_new();
    if (temporary_path_stack == NULL) {
        ZJE_LOG_ERROR("fail to create temporary path stack");
        return -1;
    }

    ZJE_LOG_INFO("worker initialized", getpid());

    return 0;
}

/*
 * 启动工作进程
 */
int zje_worker_start(void)
{
    int worker_failure = 0;
    for (; worker_failure_times < max_retry_times && worker_run() == -1; ++worker_failure_times, worker_failure = 1) {
        ZJE_LOG_ERROR("worker failed, restart in %d seconds", retry_interval);
        sleep(retry_interval);
        worker_failure = 0;
    }

    if (worker_failure == 1) {
        ZJE_LOG_ERROR("worker failed in %d consecutive times", max_retry_times);
        return -1;
    }

    return 0;
}

/*
 * 获取 worker 的工作目录
 */
char *zje_get_worker_dir(void)
{
    return worker_dir;
}
