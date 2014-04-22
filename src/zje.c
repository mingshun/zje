/*
 ============================================================================
 Name        : zje.c
 Author      : mingshun
 Version     : 1.0
 Copyright   : Copyright (C) 2011,2012,2013 mingshun.
 Description : Zero Judge Engine
 ============================================================================
 */

/*
 * 适用架构: Linux Kernel 2.6+ x86 32bits
 */


#include "zje_compile.h"
#include "zje_cpufreq.h"
#include "zje_digest.h"
#include "zje_execute.h"
#include "zje_init.h"
#include "zje_log.h"
#include "zje_net.h"
#include "zje_review.h"
#include "zje_sj.h"
#include "zje_utils.h"
#include "zje_worker.h"

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include <sys/wait.h>

#include "jansson.h"


// 测试正常通过
static void test_c1()
{
    zje_compile_t info = { .compiler = "c",
                           .source_path = "c.c",
                           .output_path = "c" };
    
    int ret = zje_compile(&info);
    json_t *root = json_object();
    if (ret != -1) {
        json_int_t value1 = info.status;
        json_t *obj1 = json_integer(value1);
        json_object_set_new(root, "compilation status", obj1);
        if (info.status != 0) {
            char *message = info.compiler_message;
            json_t *obj2 = json_string(message);
            json_object_set_new(root, "error message", obj2);
            free(message);
        }
    }
    char *json = json_dumps(root, JSON_PRESERVE_ORDER);
    ZJE_LOG_INFO(json);
    free(json);
    json_decref(root);

    //free(info.compiler_message);
}

// 测试编译文件不存在的情况
static void test_c2()
{
    zje_compile_t info = { .compiler = "c",
                           .source_path = "c1.c",
                           .output_path = "c1" };
    
    int ret = zje_compile(&info);
    json_t *root = json_object();
    if (ret != -1) {
        json_int_t value1 = info.status;
        json_t *obj1 = json_integer(value1);
        json_object_set_new(root, "compilation status", obj1);
        if (info.status != 0) {
            char *message = info.compiler_message;
            json_t *obj2 = json_string(message);
            json_object_set_new(root, "error message", obj2);
            free(message);
        }
    }
    char *json = json_dumps(root, JSON_PRESERVE_ORDER);
    ZJE_LOG_INFO(json);
    free(json);
    json_decref(root);

    //free(info.compiler_message);
}

// 运行测试
static void test_compile()
{
    ZJE_LOG_INFO( "===========test_c1============");
    test_c1();
    ZJE_LOG_INFO( "===========test_c2============");
    test_c2();
}

// 正确性测试
static void test_e1(int i)
{
    char executable_path[1024] = { 0 };
    sprintf(executable_path, "a-%d", i);
    
    zje_execute_t info = { .id = 1,
                           .input_path = "in1.txt",
                           .output_path = "out1.txt",
                           .executable_path = executable_path,
                           .time_limit = 1,
                           .memory_limit = 10,
                           .output_limit = 10 };
    
    int ret = zje_execute(&info);
    json_t *root = json_object();
    if (ret != -1) {
        json_int_t value1 = info.status;
        json_t *obj1 = json_integer(value1);
        json_object_set_new(root, "execution status", obj1);
        
        json_int_t value2 = info.comment;
        json_t *obj2 = json_integer(value2);
        json_object_set_new(root, "comment", obj2);
        
        int len3 = 1 + snprintf(NULL, 0, "%dms", info.time_used);
        char value3[len3];
        snprintf(value3, len3, "%dms", info.time_used);
        json_t *obj3 = json_string(value3);
        json_object_set_new(root, "time used", obj3);
        
        int len4 = 1 + snprintf(NULL, 0, "%dKiB", info.memory_used);
        char value4[len4];
        snprintf(value4, len4, "%dKiB", info.memory_used);
        json_t *obj4 = json_string(value4);
        json_object_set_new(root, "memory used", obj4);
        
        if (info.status == ZJE_EXECUTE_RTE) {
            json_t *obj5 = json_string(zje_signal_detail(info.comment));
            json_object_set_new(root, "reason", obj5);
        } else if (info.status == ZJE_EXECUTE_RF) {
            json_t *obj5 = json_string(zje_syscall_detail(info.comment));
            json_object_set_new(root, "restricted function", obj5);
        }
    } else {
        json_t *obj = json_string("error");
        json_object_set_new(root, "execute testcase", obj);
    }
    char *json = json_dumps(root, JSON_PRESERVE_ORDER);
    ZJE_LOG_INFO(json);
    free(json);
    json_decref(root);
}

// 测量值测试
static void test_e2()
{
    zje_execute_t info = { .id = 1,
                           .input_path = "in2.txt",
                           .output_path = "out2.txt",
                           .executable_path = "b",
                           .time_limit = 1,
                           .memory_limit = 64,
                           .output_limit = 128 };
    
    int ret = zje_execute(&info);
    json_t *root = json_object();
    if (ret != -1) {
        json_int_t value1 = info.status;
        json_t *obj1 = json_integer(value1);
        json_object_set_new(root, "execution status", obj1);
        
        json_int_t value2 = info.comment;
        json_t *obj2 = json_integer(value2);
        json_object_set_new(root, "comment", obj2);
        
        int len3 = 1 + snprintf(NULL, 0, "%dms", info.time_used);
        char value3[len3];
        snprintf(value3, len3, "%dms", info.time_used);
        json_t *obj3 = json_string(value3);
        json_object_set_new(root, "time used", obj3);
        
        int len4 = 1 + snprintf(NULL, 0, "%dKiB", info.memory_used);
        char value4[len4];
        snprintf(value4, len4, "%dKiB", info.memory_used);
        json_t *obj4 = json_string(value4);
        json_object_set_new(root, "memory used", obj4);
        
        if (info.status == ZJE_EXECUTE_RTE) {
            json_t *obj5 = json_string(zje_signal_detail(info.comment));
            json_object_set_new(root, "reason", obj5);
        } else if (info.status == ZJE_EXECUTE_RF) {
            json_t *obj5 = json_string(zje_syscall_detail(info.comment));
            json_object_set_new(root, "restricted function", obj5);
        }
    } else {
        json_t *obj = json_string("error");
        json_object_set_new(root, "execute testcase", obj);
    }
    char *json = json_dumps(root, JSON_PRESERVE_ORDER);
    ZJE_LOG_INFO(json);
    free(json);
    json_decref(root);
}

// 打开文件测试
static void test_e3()
{
    zje_execute_t info = { .id = 1,
                           .input_path = "d.in",
                           .output_path = "d.out",
                           .executable_path = "d",
                           .time_limit = 1,
                           .memory_limit = 10,
                           .output_limit = 10 };
    
    int ret = zje_execute(&info);
    
    json_t *root = json_object();
    if (ret != -1) {
        json_int_t value1 = info.status;
        json_t *obj1 = json_integer(value1);
        json_object_set_new(root, "execution status", obj1);
        
        json_int_t value2 = info.comment;
        json_t *obj2 = json_integer(value2);
        json_object_set_new(root, "comment", obj2);
        
        int len3 = 1 + snprintf(NULL, 0, "%dms", info.time_used);
        char value3[len3];
        snprintf(value3, len3, "%dms", info.time_used);
        json_t *obj3 = json_string(value3);
        json_object_set_new(root, "time used", obj3);
        
        int len4 = 1 + snprintf(NULL, 0, "%dKiB", info.memory_used);
        char value4[len4];
        snprintf(value4, len4, "%dKiB", info.memory_used);
        json_t *obj4 = json_string(value4);
        json_object_set_new(root, "memory used", obj4);
        
        if (info.status == ZJE_EXECUTE_RTE) {
            json_t *obj5 = json_string(zje_signal_detail(info.comment));
            json_object_set_new(root, "reason", obj5);
        } else if (info.status == ZJE_EXECUTE_RF) {
            json_t *obj5 = json_string(zje_syscall_detail(info.comment));
            json_object_set_new(root, "restricted function", obj5);
        }
    } else {
        json_t *obj = json_string("error");
        json_object_set_new(root, "execute testcase", obj);
    }
    char *json = json_dumps(root, JSON_PRESERVE_ORDER);
    ZJE_LOG_INFO(json);
    free(json);
    json_decref(root);
}

// 运行不存在的文件
static void test_e4()
{
    zje_execute_t info = { .id = 1,
                           .input_path = "dfsdfasdf.in",
                           .output_path = "dfsdfasdf.out",
                           .executable_path = "dfsdfasdf",
                           .time_limit = 1,
                           .memory_limit = 10,
                           .output_limit = 10 };
    
    int ret = zje_execute(&info);
    
    json_t *root = json_object();
    if (ret != -1) {
        json_int_t value1 = info.status;
        json_t *obj1 = json_integer(value1);
        json_object_set_new(root, "execution status", obj1);
        
        json_int_t value2 = info.comment;
        json_t *obj2 = json_integer(value2);
        json_object_set_new(root, "comment", obj2);
        
        int len3 = 1 + snprintf(NULL, 0, "%dms", info.time_used);
        char value3[len3];
        snprintf(value3, len3, "%dms", info.time_used);
        json_t *obj3 = json_string(value3);
        json_object_set_new(root, "time used", obj3);
        
        int len4 = 1 + snprintf(NULL, 0, "%dKiB", info.memory_used);
        char value4[len4];
        snprintf(value4, len4, "%dKiB", info.memory_used);
        json_t *obj4 = json_string(value4);
        json_object_set_new(root, "memory used", obj4);
        
        if (info.status == ZJE_EXECUTE_RTE) {
            json_t *obj5 = json_string(zje_signal_detail(info.comment));
            json_object_set_new(root, "reason", obj5);
        } else if (info.status == ZJE_EXECUTE_RF) {
            json_t *obj5 = json_string(zje_syscall_detail(info.comment));
            json_object_set_new(root, "restricted function", obj5);
        }
    } else {
        json_t *obj = json_string("error");
        json_object_set_new(root, "execute testcase", obj);
    }
    char *json = json_dumps(root, JSON_PRESERVE_ORDER);
    ZJE_LOG_INFO(json);
    free(json);
    json_decref(root);
}

static void test_execute()
{
    ZJE_LOG_INFO( "===========test_e1============");
    for (int i = 1; i <= 15; ++i) {
        ZJE_LOG_INFO( "%d:", i);
        test_e1(i);
    }
    ZJE_LOG_INFO( "===========test_e2============");
    test_e2();
    ZJE_LOG_INFO( "===========test_e3============");
    test_e3();
    ZJE_LOG_INFO( "===========test_e4============");
    test_e4();
}

void check_answer(int answer)
{
    switch (answer) {
        case ZJE_REVIEW_CORRECT:
            ZJE_LOG_INFO( "Correct!");
            break;
            
        case ZJE_REVIEW_WFORMAT:
            ZJE_LOG_INFO( "Format errors!");
            break;
            
        case ZJE_REVIEW_WRONG:
            ZJE_LOG_INFO( "Wrong!");
            break;
            
        default:
            break;
    }
}

void test_review()
{
    ZJE_LOG_INFO( "===========test_r1============");
    zje_review_t info1 = { .output_path = "s1.txt",
                           .answer_path = "s2.txt" };
    if (zje_review(&info1) == -1) {
        ZJE_LOG_INFO("Error occurs when comparing '%s' and '%s'.", info1.output_path, info1.answer_path);
    } else {
        ZJE_LOG_INFO("Review result of '%s' and '%s' is ", info1.output_path, info1.answer_path);
        check_answer(info1.result);
    }
    
    ZJE_LOG_INFO( "===========test_r2============");
    zje_review_t info2 = { .output_path = "f1.txt",
                           .answer_path = "f2.txt" };
    if (zje_review(&info2) == -1) {
        ZJE_LOG_INFO("Error occurs when comparing '%s' and '%s'.", info2.output_path, info2.answer_path);
    } else {
        ZJE_LOG_INFO("Review result of '%s' and '%s' is ", info2.output_path, info2.answer_path);
        check_answer(info2.result);
    }
    
    ZJE_LOG_INFO( "===========test_r3============");
    zje_review_t info3 = { .output_path = "w1.txt",
                           .answer_path = "w2.txt" };
    if (zje_review(&info3) == -1) {
        ZJE_LOG_INFO("Error occurs when comparing '%s' and '%s'.", info3.output_path, info3.answer_path);
    } else {
        ZJE_LOG_INFO("Review result of '%s' and '%s' is ", info3.output_path, info3.answer_path);
        check_answer(info3.result);
    }
}

// 启动评测机
static void test_judge(void)
{
    test_compile();
    test_execute();
    test_review();
}

static void test_jansson()
{
    json_t *root = json_object();
    
    json_t *compile_result = json_string("success");
    json_object_set_new(root, "compile result", compile_result);
    
    json_t *compile_error = json_null();
    json_object_set_new(root, "compile error", compile_error);
    
    json_t *executable_size = json_integer(235);
    json_object_set_new(root, "executable size", executable_size);
    
    json_t *judge_results = json_array();
    
    json_t *judge_result = json_object();
    
    json_t *id = json_integer(1);
    json_object_set_new(judge_result, "id", id);
    
    json_t *result = json_string("AC");
    json_object_set_new(judge_result, "result", result);
    
    json_t *score = json_integer(10);
    json_object_set_new(judge_result, "score", score);
    
    json_t *weight = json_integer(10);
    json_object_set_new(judge_result, "weight", weight);
    
    json_t *time_used = json_integer(235);
    json_object_set_new(judge_result, "time used", time_used);
    
    json_t *memory_used = json_integer(235);
    json_object_set_new(judge_result, "memory used", memory_used);
    
    json_array_append_new(judge_results, judge_result);
    
    judge_result = json_object();
    
    id = json_integer(2);
    json_object_set_new(judge_result, "id", id);
    
    result = json_string("RTE");
    json_object_set_new(judge_result, "result", result);
    
    score = json_integer(0);
    json_object_set_new(judge_result, "score", score);
    
    weight = json_integer(10);
    json_object_set_new(judge_result, "weight", weight);
    
    time_used = json_integer(-1);
    json_object_set_new(judge_result, "time used", time_used);
    
    memory_used = json_integer(-1);
    json_object_set_new(judge_result, "memory used", memory_used);
    
    json_array_append_new(judge_results, judge_result);
    
    json_object_set_new(root, "judge results", judge_results);
    
    char *json = json_dumps(root, JSON_PRESERVE_ORDER);
    ZJE_LOG_INFO("============test jansson============");
    ZJE_LOG_INFO("%s", json);
    free(json);
    
    json_decref(root);
}

static void test_net(void)
{
    zje_net_connection *conn = zje_net_connect();
    char send[2048] = "{\"cmd\":\"connect\",\"options\":{\"role\":\"consumer\"}}\r\n";
    if (zje_net_send(conn, send) < 0) {
        ZJE_LOG_ERROR("error occurs while sending data");
        goto FINALLY;
    }
    send[strlen(send) - 2] = '\0';
    ZJE_LOG_INFO("sent data '%s' successfully", send);
    
    char* recv = NULL;
    if (zje_net_recv(conn, &recv) < 0) {
        ZJE_LOG_ERROR("error occurs while receiving data");
        goto FINALLY;
    }
    json_error_t jerror;
    json_t* json = json_loads(recv, 0, &jerror);
    if (json == NULL) {
        ZJE_LOG_INFO("%s", jerror.text);
    } else {
        char *str = json_dumps(json, JSON_COMPACT);
        ZJE_LOG_INFO("received data: %s", str);
        free(str);
    }
    free(recv);

    strcpy(send, "{\"cmd\":\"take task\"}\r\n");
    if (zje_net_send(conn, send) < 0) {
        ZJE_LOG_ERROR("error occurs while sending data");
        goto FINALLY;
    }
    send[strlen(send) - 2] = '\0';
    ZJE_LOG_INFO("sent data '%s' successfully", send);

    recv = NULL;
    if (zje_net_recv(conn, &recv) < 0) {
        ZJE_LOG_ERROR("error occurs while receiving data");
        goto FINALLY;
    }
    json = json_loads(recv, 0, &jerror);
    if (json == NULL) {
        ZJE_LOG_INFO("%s", jerror.text);
    } else {
        char *str = json_dumps(json, JSON_COMPACT);
        ZJE_LOG_INFO("received data: %s", str);
        free(str);
    }
    free(recv);

    strcpy(send, "{\"cmd\":\"finish task\",\"options\":{\"result\":{\"submission_id\":2999,\"compile_passed\":true,\"compiler_message\":\"COMPILER MESSAGE\",\"test_results\":[{\"testcase_id\":44442,\"status\":\"tle\",\"details\":null,\"score\":0,\"time_used\":1007,\"memory_used\":280},{\"testcase_id\":44443,\"status\":\"mle\",\"details\":null,\"score\":0,\"time_used\":0,\"memory_used\":284},{\"testcase_id\":44444,\"status\":\"ole\",\"details\":null,\"score\":0,\"time_used\":59,\"memory_used\":280},{\"testcase_id\":44445,\"status\":\"re\",\"details\":\"SIGSEGV\",\"score\":0,\"time_used\":0,\"memory_used\":284},{\"testcase_id\":44446,\"status\":\"rf\",\"details\":\"sys_clone\",\"score\":0,\"time_used\":1007,\"memory_used\":280},{\"testcase_id\":44447,\"status\":\"ac\",\"details\":null,\"score\":6,\"time_used\":275,\"memory_used\":284},{\"testcase_id\":44448,\"status\":\"pe\",\"details\":null,\"score\":0,\"time_used\":275,\"memory_used\":284},{\"testcase_id\":44449,\"status\":\"wa\",\"details\":null,\"score\":0,\"time_used\":275,\"memory_used\":284},{\"testcase_id\":44450,\"status\":\"sj\",\"details\":\"special judge comment\",\"score\":9,\"time_used\":275,\"memory_used\":280},{\"testcase_id\":44451,\"status\":\"sj\",\"details\":\"special judge comment 2\",\"score\":8,\"time_used\":275,\"memory_used\":284}]}}}\r\n");
    if (zje_net_send(conn, send) < 0) {
        ZJE_LOG_ERROR("error occurs while sending data");
        goto FINALLY;
    }
    send[strlen(send) - 2] = '\0';
    ZJE_LOG_INFO("sent data '%s' successfully", send);

    recv = NULL;
    if (zje_net_recv(conn, &recv) < 0) {
        ZJE_LOG_ERROR("error occurs while receiving data");
        goto FINALLY;
    }
    json = json_loads(recv, 0, &jerror);
    if (json == NULL) {
        ZJE_LOG_INFO("%s", jerror.text);
    } else {
        char *str = json_dumps(json, JSON_COMPACT);
        ZJE_LOG_INFO("received data: %s", str);
        free(str);
    }
    free(recv);
    
    FINALLY:

    zje_net_disconnect(conn);
}

static void test_digest()
{
    char *path = "md_test";
    char *md5 = zje_file_md5(path);
    ZJE_LOG_INFO("md5 of '%s': %s", path, md5);
    free(md5);
    char *sha1 = zje_file_sha1(path);
    ZJE_LOG_INFO("sha1 of '%s': %s", path, sha1);
    free(sha1);
}

static void test_sj(void)
{
    zje_special_judge_t sj = { .judger_path = "sj",
                               .input_path = "input",
                               .answer_path = "answer",
                               .output_path = "output",
                               .weight = 12 };

    int ret = zje_special_judge(&sj);
    if (ret != -1) {
        ZJE_LOG_INFO("sj: %d, %s", sj.score, sj.comment);
        free(sj.comment);
    }
    
    sj.input_path = "1";
    ret = zje_special_judge(&sj);
    if (ret != -1) {
        ZJE_LOG_INFO("sj: %d, %s", sj.score, sj.comment);
        free(sj.comment);
    }
    
    sj.input_path = "input";
    sj.answer_path = "1";
    ret = zje_special_judge(&sj);
    if (ret != -1) {
        ZJE_LOG_INFO("sj: %d, %s", sj.score, sj.comment);
        free(sj.comment);
    }
    
    sj.answer_path = "answer";
    sj.output_path = "2";
    ret = zje_special_judge(&sj);
    if (ret != -1) {
        ZJE_LOG_INFO("sj: %d, %s", sj.score, sj.comment);
        free(sj.comment);
    }
    
    sj.output_path = "output";
    sj.weight = 11;
    ret = zje_special_judge(&sj);
    if (ret != -1) {
        ZJE_LOG_INFO("sj: %d, %s", sj.score, sj.comment);
        free(sj.comment);
    }
    
    sj.input_path = "-1";
    ret = zje_special_judge(&sj);
    if (ret != -1) {
        ZJE_LOG_INFO("sj: %d, %s", sj.score, sj.comment);
        free(sj.comment);
    }
    
    sj.input_path = "input";
    sj.weight = 12;
    ret = zje_special_judge(&sj);
    if (ret != -1) {
        ZJE_LOG_INFO("sj: %d, %s", sj.score, sj.comment);
        free(sj.comment);
    }
}


int main(int argc, char *argv[])
{
    zje_init(argc, argv);

    if (zje_worker_init() == -1) {
        ZJE_LOG_ERROR("worker fails to initialize");
        return EXIT_FAILURE;
    }

    if (zje_worker_start() == -1) {
        ZJE_LOG_ERROR("error occurs while worker running");
        return EXIT_FAILURE;
    }

/*
    int n = 2;
    pid_t workers[n];
    for (int i = 0; i < n; ++i) {
        pid_t pid = fork();
        if (pid == 0) {
            if (zje_worker_init() == -1) {
                ZJE_LOG_ERROR("worker fails to initialize");
                return EXIT_FAILURE;
            }

            if (zje_worker_run() == -1) {
                ZJE_LOG_ERROR("error occurs while worker running");
                return EXIT_FAILURE;
            }

            return EXIT_SUCCESS;
        }
        workers[i] = pid;
    }

    for (int i = 0; i < n; ++ i) {
        waitpid(workers[i], NULL, 0);
    }


    test_sj();

    test_net();
    test_digest();
    
    test_judge();
    test_jansson();
*/
    return EXIT_SUCCESS;
}
