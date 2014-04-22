/*
 * zje_cpufreq.h
 *
 *  Created on: 2012-1-29
 *      Author: mingshun
 */

#ifndef ZJE_CPUFREQ_H_
#define ZJE_CPUFREQ_H_

// 默认基准CPU频率(2GHz)
#define BASE_MHZ        2000.0

/*
 * 初始化实际CPU频率值
 */
int zje_init_cpufreq(void);

/*
 * 获取实际CPU频率值
 */
double zje_get_cpufreq(void);

#endif /* ZJE_CPUFREQ_H_ */
