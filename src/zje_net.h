/*
 * zje_net.h
 *
 *  Created on: 2012-9-2
 *      Author: mingshun
 */

#ifndef ZJE_NET_H_
#define ZJE_NET_H_

#include <openssl/ssl.h>

/*
 * 网络连接结构体
 */
typedef struct {
    BIO *bio;
} zje_net_connection;

/*
 * 设置是否启用 TLS/SSL ，on 为 1，off 为 0
 * > 启用 TLS/SSL 返回 1
 * > 禁用 TLS/SLL 返回 0
 * > 函数出错返回 -1
 */
int zje_set_ssl_enable(const char *ssl);

/*
 * 设置套接字类型
 */
int zje_set_socket_type(const char *type);

/*
 * 设置套接字路径
 */
int zje_set_socket_path(const char *path);

/*
 * 设置套接字主机
 */
int zje_set_socket_host(const char *host);

/*
 * 设置套接字端口
 */
int zje_set_socket_port(const char *port);

/*
 * 设置 PKCS#12 证书文件路径
 */
int zje_set_pkcs12_certificate_path(const char *path);

/*
 * 设置 PKCS#12 证书密码
 */
int zje_set_pkcs12_certificate_password(const char *password);

/*
 * 初始化网络通信模块
 */
int zje_init_net();

/*
 * 建立连接网络
 */
zje_net_connection *zje_net_connect();

/*
 * 从网络连接中接收数据，直到 CRLF 停止
 * - 接收到的数据中的 CRLF 将被去掉。
 * - 函数会自行分配足够的内存空间给接收到的数据，调用者须自行释放这些空间。
 * > 如果成功，返回 0
 * > 如果失败，返回 -1
 */
int zje_net_recv(zje_net_connection *connection, char **data_ptr);

/*
 * 向网络连接发送数据，并在数据末尾加上 CRLF
 * > 如果成功，返回 0
 * > 如果失败，返回 -1
 */
int zje_net_send(zje_net_connection *connection, const char *buffer);

/*
 * 断开网络连接
 */
void zje_net_disconnect(zje_net_connection *connection);

#endif /* ZJE_NET_H_ */
