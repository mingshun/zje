/*
 * zje_config.c
 *
 *  Created on: 2012-3-21
 *      Author: mingshun
 */
#include "zje_config.h"

#include "zje_compile.h"
#include "zje_execute.h"
#include "zje_log.h"
#include "zje_net.h"
#include "zje_path.h"
#include "zje_rbtree.h"
#include "zje_utils.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 配置文件路径
#define ZJE_CONFIG_FILE_PATH "./conf/zje.conf"

// 配置键值分隔符
#define ZJE_CONFIG_SPLITER '='

// 编译命令行参数结束标志，用于从配置参数映射表中搜索编译命令行
#define ZJE_COMPILE_COMMAND_CONFIG_TERMINATE_MARK "-compile-command"

/*
 * 配置参数映射表
 */
static zje_rb_tree_t config_map = NULL;

static void parse_key_value(const char *line, int pos);
static void parse_config_from_file(void);
static void pick_compile_commands(zje_rb_node_t node);

/*
 * 解析配置信息
 */
static void parse_key_value(const char *line, int pos)
{
    // 检查传入的参数
    if (line == NULL) {
        ZJE_FATAL_SYSLOG("parse_config: line should not be NULL");
    }
    if (pos < 1) {
        ZJE_FATAL_SYSLOG("parse_config: pos < 1");
    }
    
    int length = strlen(line);
    
    // 去掉键值对首尾的空白字符
    int key_pos1 = 0;
    while (key_pos1 < pos && isspace(line[key_pos1])) {
        ++key_pos1;
    }
    int key_pos2 = pos;
    while (key_pos1 < key_pos2 && isspace(line[key_pos2 - 1])) {
        --key_pos2;
    }
    int value_pos1 = pos + 1;
    while (value_pos1 < length && isspace(line[value_pos1])) {
        ++value_pos1;
    }
    int value_pos2 = length;
    while (value_pos1 < value_pos2 && isspace(line[value_pos2 - 1])) {
        --value_pos2;
    }
    
    // 计算键值字符串长度
    int key_length = key_pos2 - key_pos1;
    int value_length = value_pos2 - value_pos1;
    
    // 键不能是空字符串
    if (key_length == 0) {
        ZJE_FATAL_SYSLOG("parse_config: key must not be empty string");
    }
    
    // 解析
    char *key = calloc(key_length + 1, sizeof(char));
    if (key == NULL) {
        ZJE_FATAL_SYSLOG("fail to allocate memory for config key: %s", strerror(errno));
    }
    char *value = calloc(value_length + 1, sizeof(char));
    if (value == NULL) {
        ZJE_FATAL_SYSLOG("fail to allocate memory for config value: %s", strerror(errno));
    }
    
    strncpy(key, line + key_pos1, key_length);
    strncpy(value, line + value_pos1, value_length);
    
    if (zje_rb_put(config_map, key, value) == -1) {
        ZJE_FATAL_SYSLOG("fail to put key-value to configure map");
    }
    
    free(key);
    free(value);
}

/*
 * 解析配置文件
 */
static void parse_config_from_file(void)
{
    // 打开配置文件
    FILE *config_file = fopen(ZJE_CONFIG_FILE_PATH, "r");
    if (config_file == NULL) {
        ZJE_FATAL_SYSLOG("fail to open configure file(%s)", zje_resolve_path(ZJE_CONFIG_FILE_PATH));
    }
    
    for (int i = 1; !feof(config_file); ++i) {
        char *line = zje_readline(config_file);
        if (line == NULL) {
            ZJE_FATAL_SYSLOG("fail to allocate memory for config line: %s", strerror(errno));
        }
        
        if (strlen(line) <= 1) {
            continue;
        } else if (line[0] == '#') {
            continue;
        } else if (line[0] == '\n') {
            continue;
        } else {
            int pos = zje_split_sign_pos(line, ZJE_CONFIG_SPLITER);
            if (pos >= 0) {
                parse_key_value(line, pos);
            } else {
                ZJE_FATAL_SYSLOG("invalid line in config file(%s) line %d: %s", zje_resolve_path(ZJE_CONFIG_FILE_PATH), i, line);
            }
        }
        
        free(line);
    }
    
    fclose(config_file);
}

/*
 * 从配置参数映射表中找编译命令行，并添加到编译命令行映射表中
 */
static void pick_compile_commands(zje_rb_node_t node)
{
    // 假设匹配
    int match = 1;
    
    char *key = node->key;
    char *mark = ZJE_COMPILE_COMMAND_CONFIG_TERMINATE_MARK;
    int key_size = strlen(key);
    int mark_size = strlen(mark);
    int size_differ = key_size - mark_size;
    
    // 逐个字符匹配
    for (int i = 0; i < mark_size; ++i) {
        if (mark[i] != key[size_differ + i]) {
            match = 0;
            break;
        }
    }
    
    // 如果不匹配，返回
    if (match == 0) {
        return;
    }
    
    // 解析出编译命令行的key
    char *command_key = (char*) calloc((size_differ + 1), sizeof(char));
    if (command_key == NULL) {
        ZJE_FATAL_SYSLOG("fail to create key for command line of %s: %s", key, strerror(errno));
        return;
    }
    strncpy(command_key, key, size_differ);
    
    // 添加编译命令行
    if (zje_add_compile_command(command_key, node->value) == -1) {
        ZJE_FATAL_SYSLOG("fail to add compile command line");
        return;
    }
    
    // 释放编译命令行key所占用的内存
    free(command_key);
}

/*
 * 配置zje
 */
void zje_config(void)
{
    // 建立配置参数映射表
    config_map = zje_rb_create();
    if (config_map == NULL) {
        ZJE_FATAL_SYSLOG("fail to create configure map");
    }
    
    // 解析配置参数
    parse_config_from_file();
    
    // 设置日志级别
    {
        zje_rb_node_t log_level_node = zje_rb_get(config_map, "log-level");
        if (log_level_node != NULL) {
            const char *log_level = log_level_node->value;
            if (zje_set_log_level(log_level) == -1) {
                ZJE_FATAL_SYSLOG("invalid configure value of parameter 'log-level': %s", log_level);
            }
        }
    }
    // 设置日志文件大小
    {
        zje_rb_node_t log_size_node = zje_rb_get(config_map, "log-size");
        if (log_size_node != NULL) {
            const char *log_size = log_size_node->value;
            if (zje_set_log_size(log_size) == -1) {
                ZJE_FATAL_SYSLOG("invalid configure value of parameter 'log-size': %s", log_size);
            }
        }
    }
    // 设置每天日志文件数目上限
    {
        zje_rb_node_t daily_log_count_node = zje_rb_get(config_map, "daily-log-count");
        if (daily_log_count_node != NULL) {
            const char *daily_log_count = daily_log_count_node->value;
            if (zje_set_daily_log_count(daily_log_count) == -1) {
                ZJE_FATAL_SYSLOG("invalid configure value of parameter 'daily-log-count': %s", daily_log_count);
            }
        }
    }
    
    // 设置受监视用户
    {
        zje_rb_node_t watched_user_node = zje_rb_get(config_map, "watched-user");
        if (watched_user_node != NULL) {
            const char *watched_user = watched_user_node->value;
            if (zje_set_watched_user(watched_user) == -1) {
                ZJE_FATAL_SYSLOG("invalid configure value for configure parameter 'watched-user': %s", watched_user);
            }
        }
    }
    
    // 设置套接字类型
    {
        zje_rb_node_t socket_type_node = zje_rb_get(config_map, "socket-type");
        if (socket_type_node != NULL) {
            const char *socket_type = socket_type_node->value;
            if (zje_set_socket_type(socket_type) == -1) {
                ZJE_FATAL_SYSLOG("invalid configure value for configure parameter 'socket-type': %s", socket_type);
            }
        }
    }
    // 设置 unix 域套接路径
    {
        zje_rb_node_t socket_path_node = zje_rb_get(config_map, "socket-path");
        if (socket_path_node != NULL) {
            const char *socket_path = socket_path_node->value;
            if (zje_set_socket_path(socket_path) == -1) {
                ZJE_FATAL_SYSLOG("invalid configure value for configure parameter 'socket-type': %s", socket_path);
            }
        }
    }
    // 设置 tcp 套接字主机
    {
        zje_rb_node_t socket_host_node = zje_rb_get(config_map, "socket-host");
        if (socket_host_node != NULL) {
            const char *socket_host = socket_host_node->value;
            if (zje_set_socket_host(socket_host) == -1) {
                ZJE_FATAL_SYSLOG("invalid configure value for configure parameter 'socket-host': %s", socket_host);
            }
        }
    }
    // 设置 tcp 套接字端口
    {
        zje_rb_node_t socket_port_node = zje_rb_get(config_map, "socket-port");
        if (socket_port_node != NULL) {
            const char *socket_port = socket_port_node->value;
            if (zje_set_socket_port(socket_port) == -1) {
                ZJE_FATAL_SYSLOG("invalid configure value for configure parameter 'socket-port': %s", socket_port);
            }
        }
    }
    // 设置 PKCS#12 证书文件路径，用于 TLS/SSL TCP套接字
    {
        zje_rb_node_t pkcs12_certificate_path_node = zje_rb_get(config_map, "pkcs12-certificate-path");
        if (pkcs12_certificate_path_node != NULL) {
            const char *pkcs12_certificate_path = pkcs12_certificate_path_node->value;
            if (zje_set_pkcs12_certificate_path(pkcs12_certificate_path) == -1) {
                ZJE_FATAL_SYSLOG("invalid configure value for configure parameter 'pkcs12-certificate-path': %s",
                        pkcs12_certificate_path);
            }
        }
    }
    // 设置 PKCS#12 证书密码
    {
        zje_rb_node_t pkcs12_certificate_password_node = zje_rb_get(config_map, "pkcs12-certificate-password");
        if (pkcs12_certificate_password_node != NULL) {
            const char *pkcs12_certificate_password = pkcs12_certificate_password_node->value;
            if (zje_set_pkcs12_certificate_password(pkcs12_certificate_password) == -1) {
                ZJE_FATAL_SYSLOG( "invalid configure value for configure parameter 'pkcs12-certificate-password': %s",
                        pkcs12_certificate_password);
            }
        }
    }
    
    // 配置编译命令行
    zje_rb_pre_order_traverse(config_map, pick_compile_commands);
    
    // 释放配置参数表
    zje_rb_delete(config_map);
}
