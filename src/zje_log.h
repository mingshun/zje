/*
 * zje_log.h
 *
 *  Created on: 2012-1-29
 *      Author: mingshun
 */

#ifndef ZJE_LOG_H_
#define ZJE_LOG_H_

// 日志级别
#define ZJE_LOG_LEVEL_TRACE       0
#define ZJE_LOG_LEVEL_DEBUG       1
#define ZJE_LOG_LEVEL_INFO        2
#define ZJE_LOG_LEVEL_WARNING     3
#define ZJE_LOG_LEVEL_ERROR       4
#define ZJE_LOG_LEVEL_FATAL       5
#define ZJE_LOG_LEVEL_OFF         6

// zje 日志宏
#define ZJE_LOG(level, format, ...) \
		zje_log(level, __FILE__, __LINE__, __func__, format, ## __VA_ARGS__)
#define ZJE_LOG_TRACE(format, ...) \
		ZJE_LOG(ZJE_LOG_LEVEL_TRACE, format, ## __VA_ARGS__)
#define ZJE_LOG_DEBUG(format, ...) \
		ZJE_LOG(ZJE_LOG_LEVEL_DEBUG, format, ## __VA_ARGS__)
#define ZJE_LOG_INFO(format, ...) \
        ZJE_LOG(ZJE_LOG_LEVEL_INFO, format, ## __VA_ARGS__)
#define ZJE_LOG_WARNING(format, ...) \
        ZJE_LOG(ZJE_LOG_LEVEL_WARNING, format, ## __VA_ARGS__)
#define ZJE_LOG_ERROR(format, ...) \
        ZJE_LOG(ZJE_LOG_LEVEL_ERROR, format, ## __VA_ARGS__)
#define ZJE_LOG_FATAL(format, ...) \
        ZJE_LOG(ZJE_LOG_LEVEL_FATAL, format, ## __VA_ARGS__)

// 系统日志宏
#define ZJE_DEBUG_SYSLOG(format, ...) \
		zje_syslog_debug(__FILE__, __LINE__, __func__, format, ## __VA_ARGS__)
#define ZJE_FATAL_SYSLOG(format, ...) \
		zje_syslog_fatal(__FILE__, __LINE__, __func__, format, ## __VA_ARGS__)

/*
 * 初始化日志(master)
 */
void zje_init_log(void);

/*
 * 记录日志
 */
void zje_log(int level, const char *loc_file, int loc_line, const char *loc_func, const char *format, ...);

/*
 * 设置日志级别
 */
int zje_set_log_level(const char *level_str);

/*
 * 设置日志文件大小
 */
int zje_set_log_size(const char *size_str);

/*
 * 设置每天日志文件数目上限
 */
int zje_set_daily_log_count(const char *count_str);

/*
 * 记录调试日志到syslog中(未完成日志功能配置时使用)
 */
void zje_syslog_debug(const char *loc_file, int loc_line, const char *loc_func, const char *format, ...);

/*
 * 把错误信息记录到syslog中并退出程序(未完成日志功能配置时使用)
 */
void zje_syslog_fatal(const char *loc_file, int loc_line, const char *loc_func, const char *format, ...);

/*
 * 打开日志功能
 */
void zje_log_on(void);

/*
 * 关闭日志功能
 */
void zje_log_off(void);

#endif /* ZJE_LOG_H_ */
