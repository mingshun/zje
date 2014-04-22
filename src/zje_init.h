/*
 * zje_init.h
 *
 *  Created on: 2012-2-21
 *      Author: mingshun
 */

#ifndef ZJE_INIT_H_
#define ZJE_INIT_H_

// 守护进程文件路径
#define PID_FILE "/var/run/zje.pid"

/*
 * 初始化judger
 */
void zje_init(int argc, char *argv[]);

#endif /* ZJE_INIT_H_ */
