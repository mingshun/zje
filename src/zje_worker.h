/*
 * zje_worker.h
 *
 *  Created on: 2012-12-17
 *      Author: mingshun
 */

#ifndef ZJE_WORKER_H_
#define ZJE_WORKER_H_

/*
 * 检查中止信号
 */
int zje_is_terminated(void);

/*
 * 初始化工作进程
 */
int zje_worker_init(void);

/*
 * 启动工作进程
 */
int zje_worker_start(void);

/*
 * 获取 worker 的工作目录
 */
char *zje_get_worker_dir(void);

#endif /* ZJE_WORKER_H_ */
