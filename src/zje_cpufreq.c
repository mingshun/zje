/*
 * zje_cpufreq.c
 *
 *  Created on: 2012-1-29
 *      Author: mingshun
 */

#include "zje_cpufreq.h"

#include "zje_log.h"
#include "zje_utils.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

// CPU信息文件路径
#define CPUINFO_PATH "/proc/cpuinfo"

// CPU信息文件中键值的分隔符
#define CPUINFO_SPLITER ':'

// CPU频率在 /proc/cpuinfo 的键名及其长度
#define CPUMHZ_MARK "cpu MHz"
#define CPUMHZ_MARK_LENGTH strlen(CPUMHZ_MARK)

/*
 * 用于记录实际CPU频率值
 */
static double cur_cpufreq = -1;

static double get_cpufreq_from_cpufreq(void);
static double get_cpufreq_from_cpuinfo(void);

/*
 * 从cpufreq文件中获取CPU最高工作频率(MHz)，返回1为内核没有启用cpufreq功能
 */
static double get_cpufreq_from_cpufreq(void)
{
    const char *MAX_CPUFREQ_INFO = "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq";
    
    double cpufreq = -1;
    
    if (access(MAX_CPUFREQ_INFO, F_OK | R_OK) == -1) {
        return -1;
    }
    
    FILE *file = fopen(MAX_CPUFREQ_INFO, "r");
    if (file == NULL) {
        ZJE_LOG_ERROR( "fail to open cpufreq file(%s): %s", MAX_CPUFREQ_INFO, strerror(errno));
        return -1;
    }
    
    if (fscanf(file, "%lf", &cpufreq) != 1) {
        ZJE_LOG_ERROR( "fail to read cpu frequency from %s", MAX_CPUFREQ_INFO);
        fclose(file);
        
        return -1;
    }
    
    fclose(file);
    
    // 将KHz换算成MHz
    return cpufreq / 1000;
}

/*
 * 从cpuinfo文件中获取CPU工作频率(MHz)
 */
static double get_cpufreq_from_cpuinfo(void)
{
    
    // 打开CPU信息文件
    FILE *file = fopen(CPUINFO_PATH, "r");
    if (file == NULL) {
        ZJE_LOG_ERROR( "fail to open cpuinfo(/proc/cpuinfo): %s", strerror(errno));
        return -1;
    }
    
    double cpufreq = -1;
    while (!feof(file)) {
        char *line = zje_readline(file);
        if (line == NULL) {
            ZJE_LOG_ERROR( "fail to allocate memory: %s.", strerror(errno));
            return -1;
        }
        
        int pos = zje_split_sign_pos(line, CPUINFO_SPLITER);
        if (pos == -1) {
            continue;
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
        while (line[value_pos1] < length && isspace(line[value_pos1])) {
            ++value_pos1;
        }
        int value_pos2 = length;
        while (value_pos1 < value_pos2 && isspace(line[value_pos2 - 1])) {
            --value_pos2;
        }
        
        // 计算键值字符串长度
        int key_length = key_pos2 - key_pos1;
        int value_length = value_pos2 - value_pos1;
        
        // 解析
        char *key = calloc(key_length + 1, sizeof(char));
        if (key == NULL) {
            ZJE_LOG_ERROR( "fail to allocate memory : %s.", strerror(errno));
            return -1;
        }
        char *value = calloc(value_length + 1, sizeof(char));
        if (value == NULL) {
            ZJE_LOG_ERROR( "fail to allocate memory : %s.", strerror(errno));
            return -1;
        }
        
        strncpy(key, line + key_pos1, key_length);
        strncpy(value, line + value_pos1, value_length);
        
        if (zje_string_equality(CPUMHZ_MARK, key)) {
            // 读取CPU频率值。如果有多个值，则取其中的最小值
            double tmpfreq = -1;
            sscanf(value, "%lf", &tmpfreq);
            cpufreq = cpufreq < 0 ? tmpfreq : cpufreq < tmpfreq ? cpufreq : tmpfreq;
        }
        
        free(key);
        free(value);
        
    }
    
    fclose(file);
    
    return cpufreq;
}

/*
 * 初始化实际CPU频率值
 */
int zje_init_cpufreq(void)
{
    // 如果内核启用cpufreq
    cur_cpufreq = get_cpufreq_from_cpufreq();
    if (cur_cpufreq > 0) {
        ZJE_LOG_WARNING( "cpufreq service is active on this machine, this may affect the result of judgement");
        ZJE_LOG_INFO( "maximum cpu frequency is %lf", cur_cpufreq);
        return 0;
    }
    
    // 如果内核没有启用cpufreq
    cur_cpufreq = get_cpufreq_from_cpuinfo();
    if (cur_cpufreq > 0) {
        ZJE_LOG_INFO( "cpu frequency is %lf", cur_cpufreq);
        return 0;
    }
    
    // 无法获取正确的CPU频率
    return -1;
}

/*
 * 获取实际CPU频率值
 */
double zje_get_cpufreq(void)
{
    // 如果已更新CPU频率，则直接返回
    if (cur_cpufreq < 0) {
        ZJE_LOG_ERROR( "fail to get current cpu frequency");
        return -1;
    }
    
    return cur_cpufreq;
}

