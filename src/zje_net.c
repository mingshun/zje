/*
 * zje_net.c
 *
 *  Created on: 2012-9-2
 *      Author: mingshun
 */

#include "zje_net.h"

#include "zje_log.h"
#include "zje_path.h"
#include "zje_utils.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>

#define CR '\r'
#define LF '\n'
#define CRLF "\r\n"

// Unix 域套接字
#define SOCKET_LOCAL    0
// TCP 套接字
#define SOCKET_TCP      1
// 带 TLS/SSL 的 TCP 套接字
#define SOCKET_SSL      2

/*
 * 套接字类型
 */
static int socket_type = SOCKET_LOCAL;

/*
 * 套接字路径，只用于 SOCKET_UNIX
 */
static char *socket_path = NULL;

/*
 * 套接字主机，用于 SOCKET_TCP 和 SOCKET_TCPSSL
 */
static char *socket_host = NULL;

/*
 * 套接字端口，用于 SOCKET_TCP 和 SOCKET_TCPSSL
 */
static unsigned socket_port = 0;

/*
 * PKCS#12 证书文件路径
 */
static char *pkcs12_certificate_path = NULL;

/*
 * PKCS#12 证书密码
 */
static char *pkcs12_certificate_password = NULL;

/*
 * TLS/SSL 上下文对象
 */
static SSL_CTX *ssl_context = NULL;

static const char *openssl_error_string(void);
static int load_pkcs12_certificate(SSL_CTX *ctx, const char *path);
static int init_ssl_context(void);
static void free_ssl_context(void);
static const char *ssl_verificateion_description(int verification_code);
static BIO *connect_local(void);
static BIO *connect_tcp(void);
static BIO *connect_ssl(void);

/*
 * 获取 TLS/SSL 错误信息
 */
static const char *openssl_error_string(void)
{
    unsigned long error_code = ERR_get_error();
    return ERR_reason_error_string(error_code);
}

/*
 * 加载 PKCS#12 文件中的证书到 SSL_CTX 对象
 * > 加载成功，返回 0
 * > 加载失败，返回 -1
 */
static int load_pkcs12_certificate(SSL_CTX *ctx, const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to open PKCS#12 file '%s': %s", rp, strerror(errno));
        free(rp);

        return -1;
    }
    
    // 读取 PKCS#12 文件
    PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
    if (p12 == NULL) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to read PKCS#12 file '%s': %s", rp, openssl_error_string());
        free(rp);

        fclose(fp);
        return -1;
    }
    fclose(fp);
    
    // 加载 PKCS#12 加密算法
    PKCS12_PBE_add();
    
    int failure = 0;
    
    // 解析 PKCS#12 文件
    X509 *certificate = NULL;
    EVP_PKEY *private_key = NULL;
    STACK_OF(X509) *ca_certificates = NULL;
    if (PKCS12_parse(p12, pkcs12_certificate_password, &private_key, &certificate, &ca_certificates) != 1) {
        char *rp = zje_resolve_path(path);
        ZJE_LOG_ERROR("fail to parse PKCS#12 file '%s': %s", rp, openssl_error_string());
        free(rp);

        PKCS12_free(p12);
        failure = 1;
        goto FINALLY;
    }
    PKCS12_free(p12);
    
    // 设置客户端证书
    if (SSL_CTX_use_certificate(ctx, certificate) != 1) {
        ZJE_LOG_ERROR("fail to set the parsed certificate to TLS/SSL context: %s", openssl_error_string());
        failure = 1;
        goto FINALLY;
    }
    // 设置客户端私钥
    if (SSL_CTX_use_PrivateKey(ctx, private_key) != 1) {
        ZJE_LOG_ERROR("fail to set the parsed private key to TLS/SSL context: %s", openssl_error_string());
        failure = 1;
        goto FINALLY;
    }
    
    // 检查私钥和公钥是否匹配
    if (SSL_CTX_check_private_key(ctx) != 1) {
        ZJE_LOG_ERROR("the parsed private key is not matched the parsed certificate: %s", openssl_error_string());
        failure = 1;
        goto FINALLY;
    }
    
    // 添加 CA 证书到 TLS/SSL 上下文证书信任列表中
    int ca_certificate_count = sk_X509_num(ca_certificates);
    if (ca_certificate_count <= 0) {
        ZJE_LOG_ERROR("CA certificate not found in PKCS#12 file");
        failure = 1;
        goto FINALLY;
    } else {
        ZJE_LOG_INFO("%d CA certificates found", sk_X509_num(ca_certificates));
    }
    for (int i = 0; i < ca_certificate_count; ++i) {
        if (X509_STORE_add_cert(ctx->cert_store, sk_X509_value(ca_certificates, i)) != 1) {
            ZJE_LOG_ERROR("fail to add the parsed CA certificate to trusted list of certificate store: %s",
                    openssl_error_string());
            failure = 1;
            goto FINALLY;
        }
    }
    
    FINALLY:
    // 检查是否出错
    if (failure == 1) {
        if (certificate != NULL) {
            X509_free(certificate);
        }
        if (private_key != NULL) {
            EVP_PKEY_free(private_key);
        }
        if (ca_certificates != NULL) {
            sk_X509_pop_free(ca_certificates, X509_free);
        }
        return -1;
    }
    
    return 0;
}

/*
 * 初始化 TLS/SSL 上下文
 */
static int init_ssl_context(void)
{
    // 加载 TLS/SSL 库错误描述字符串
    SSL_load_error_strings();
    // 初始化 TLS/SSL 库
    SSL_library_init();
    // 使用 TLSv1.0
    SSL_METHOD *method = (SSL_METHOD*) TLSv1_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ZJE_LOG_ERROR("fail to create SSL context object: %s", openssl_error_string());
        return -1;
    }
    // 设置 TLS/SSL 库选项，可以绕过已知的 bugs
    SSL_CTX_set_options(ctx, SSL_OP_ALL);
    
    // 加载 PKCS#12 证书
    if (load_pkcs12_certificate(ctx, pkcs12_certificate_path) != 0) {
        char *rp = zje_resolve_path(pkcs12_certificate_path);
        ZJE_LOG_ERROR("fail to load PKCS#12 certificate from path '%s'", rp);
        free(rp);

        SSL_CTX_free(ctx);
        return -1;
    } else {
        char *rp = zje_resolve_path(pkcs12_certificate_path);
        ZJE_LOG_INFO("PKCS#12 certificate path '%s' has been loaded", rp);
        free(rp);
    }
    
    // 设置客户端验证方式：服务器必须提供证书
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    // 设置自动重试模式
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    
    // 设置 TLS/SSL 上下文对象
    ssl_context = ctx;
    
    return 0;
}

/*
 * 释放 TLS/SSL 上下文
 */
static void free_ssl_context(void)
{
    if (ssl_context != NULL) {
        SSL_CTX_free(ssl_context);
    }
    EVP_cleanup();
    ERR_free_strings();
}

/*
 * 获取 TLS/SSL 验证代码的描述信息
 */
static const char *ssl_verificateion_description(int code)
{
    switch (code) {
        case X509_V_OK:
            return "ok";
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            return "unable to get issuer certificate";
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            return "unable to get certificate CRL";
        case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
            return "unable to decrypt certificate's signature";
        case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
            return "unable to decrypt CRL's signature";
        case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
            return "unable to decode issuer public key";
        case X509_V_ERR_CERT_SIGNATURE_FAILURE:
            return "certificate signature failure";
        case X509_V_ERR_CRL_SIGNATURE_FAILURE:
            return "CRL signature failure";
        case X509_V_ERR_CERT_NOT_YET_VALID:
            return "certificate is not yet valid";
        case X509_V_ERR_CERT_HAS_EXPIRED:
            return "certificate has expired";
        case X509_V_ERR_CRL_NOT_YET_VALID:
            return "CRL is not yet valid";
        case X509_V_ERR_CRL_HAS_EXPIRED:
            return "CRL has expired";
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            return "format error in certificate's notBefore field";
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            return "format error in certificate's notAfter field";
        case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
            return "format error in CRL's lastUpdate field";
        case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
            return "format error in CRL's nextUpdate field";
        case X509_V_ERR_OUT_OF_MEM:
            return "out of memory";
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            return "self signed certificate";
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            return "self signed certificate in certificate chain";
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            return "unable to get local issuer certificate";
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
            return "unable to verify the first certificate";
        case X509_V_ERR_CERT_CHAIN_TOO_LONG:
            return "certificate chain too long";
        case X509_V_ERR_CERT_REVOKED:
            return "certificate revoked";
        case X509_V_ERR_INVALID_CA:
            return "invalid CA certificate";
        case X509_V_ERR_PATH_LENGTH_EXCEEDED:
            return "path length constraint exceeded";
        case X509_V_ERR_INVALID_PURPOSE:
            return "unsupported certificate purpose";
        case X509_V_ERR_CERT_UNTRUSTED:
            return "certificate not trusted";
        case X509_V_ERR_CERT_REJECTED:
            return "certificate rejected";
        case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
            return "subject issuer mismatch";
        case X509_V_ERR_AKID_SKID_MISMATCH:
            return "authority and subject key identifier mismatch";
        case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
            return "authority and issuer serial number mismatch";
        case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
            return "key usage does not include certificate signing";
        case X509_V_ERR_APPLICATION_VERIFICATION:
            return "application verification failure";
        default:
            break;
    }
    return "(undefined TLS/SSL verification code)";
}

/*
 * 建立 unix 域 socket 连接
 */
static BIO *connect_local(void)
{
    int sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (sockfd == -1) {
        ZJE_LOG_ERROR("fail to create a file descriptor for unix domain socket: ", strerror(errno));
        return NULL;
    }

    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_LOCAL;
    strncpy(un.sun_path, socket_path, strlen(socket_path));
    if (connect(sockfd, &un, sizeof(un)) == -1) {
        ZJE_LOG_ERROR("fail to initiate unix socket connection: %s", strerror(errno));
        close(sockfd);
        return NULL;
    }
    
    BIO *ubio = BIO_new_socket(sockfd, BIO_CLOSE);
    if (ubio == NULL) {
        ZJE_LOG_ERROR("fail to create local connect: ", openssl_error_string());
        return NULL;
    }
    return ubio;
}

/*
 * 建立 tcp 连接
 */
static BIO *connect_tcp(void)
{
    BIO *cbio = BIO_new_connect(socket_host);
    if (cbio == NULL) {
        ZJE_LOG_ERROR("fail to create BIO_s_connect");
        return NULL;
    }
    BIO_set_close(cbio, BIO_CLOSE);
    BIO_set_conn_int_port(cbio, &socket_port);
    if (BIO_do_connect(cbio) <= 0) {
        ZJE_LOG_ERROR("fail to do TCP/IP connect: %s", openssl_error_string());
        BIO_free_all(cbio);
        return NULL;
    }
    
    int sockfd = -1;
    if (BIO_get_fd(cbio, &sockfd) == -1) {
        ZJE_LOG_ERROR("fail to retrieve file descriptor of TCP connection: %s", openssl_error_string());
        BIO_free_all(cbio);
        return NULL;
    }
    return cbio;
}

/*
 * 建立 TLS/SSL 连接
 */
static BIO *connect_ssl(void)
{
    // 创建 TLS/SSL 连接的 BIO
    BIO *sbio = BIO_new_ssl_connect(ssl_context);
    if (sbio == NULL) {
        ZJE_LOG_ERROR("fail to create BIO_f_ssl chain");
        return NULL;
    }
    // 设置在关闭 BIO 时关闭内部的 SSL 结构并释放 SSL 结构体占用的内存空间
    BIO_set_close(sbio, BIO_CLOSE);
    // 设置 TLS/SSL 连接主机名或 IP
    BIO_set_conn_hostname(sbio, socket_host);
    // 设置 TLS/SSL 连接的端口号
    BIO_set_conn_int_port(sbio, &socket_port);
    // 发起 TLS/SSL 连接
    if (BIO_do_connect(sbio) <= 0) {
        ZJE_LOG_ERROR("fail to do TLS/SSL connect: %s", openssl_error_string());
        BIO_free_all(sbio);
        return NULL;
    }
    // 进行 TLS/SSL 握手
    if (BIO_do_handshake(sbio) <= 0) {
        ZJE_LOG_ERROR("fail to do TLS/SSL handshake: %s", openssl_error_string());
        BIO_free_all(sbio);
        return NULL;
    }
    
    // 获取证书验证结果
    SSL *ssl;
    BIO_get_ssl(sbio, &ssl);
    int verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        ZJE_LOG_ERROR("fail to verify the certificate presented by the peer: %s",
                ssl_verificateion_description(verify_result));
        BIO_free_all(sbio);
        return NULL;
    }
    
    // 给 TLS/SSL 连接的文件描述符设置 CLOSE_ON_EXEC 标志，以便在调用 execve 时自动关闭文件描述符
    int sockrfd = SSL_get_rfd(ssl);
    if (sockrfd == -1) {
        ZJE_LOG_ERROR("fail to retrieve file descriptor for the read channel of TLS/SSL connection: %s",
                openssl_error_string());
        BIO_free_all(sbio);
        return NULL;
    }

    int sockwfd = SSL_get_wfd(ssl);
    if (sockwfd == -1) {
        ZJE_LOG_ERROR("fail to retrieve file descriptor for the write channel of TLS/SSL connection: %s",
                openssl_error_string());
        BIO_free_all(sbio);
        return NULL;
    }
    return sbio;
}

/*
 * 设置套接字类型
 */
int zje_set_socket_type(const char *type_str)
{
    struct type {
        int code;
        const char *name;
    };
    
    struct type types[] = { { SOCKET_LOCAL,
                              "local" },
                            { SOCKET_TCP,
                              "tcp" },
                            { SOCKET_SSL,
                              "ssl" } };
    
    for (int i = 0; i < sizeof(types) / sizeof(*types); ++i) {
        if (zje_string_equality(type_str, types[i].name)) {
            socket_type = types[i].code;
            return 0;
        }
    }
    
    return -1;
}

/*
 * 设置套接字路径
 */
int zje_set_socket_path(const char *path)
{
    if (socket_type != SOCKET_LOCAL) {
        return 0;
    }
    
    if (path == NULL || strlen(path) == 0) {
        ZJE_DEBUG_SYSLOG("'socket-path' should be provided while using unix socket");
        return -1;
    }
    
    size_t length = strlen(path);
    char *dump = (char *) calloc(length + 1, sizeof(char));
    if (dump == NULL) {
        ZJE_DEBUG_SYSLOG("fail to allocate memory for socket path: %s", strerror(errno));
        return -1;
    }
    strncpy(dump, path, length);
    socket_path = dump;
    return 0;
}

/*
 * 设置套接字主机
 */
int zje_set_socket_host(const char *host)
{
    if (socket_type != SOCKET_TCP && socket_type != SOCKET_SSL) {
        return 0;
    }
    
    if (host == NULL || strlen(host) == 0) {
        ZJE_DEBUG_SYSLOG("'socket-host' should be provided while using tcp socket");
        return -1;
    }
    
    size_t length = strlen(host);
    char *dump = (char *) calloc(length + 1, sizeof(char));
    if (dump == NULL) {
        ZJE_DEBUG_SYSLOG("fail to allocate memory for socket host: %s", strerror(errno));
        return -1;
    }
    strncpy(dump, host, length);
    socket_host = dump;
    return 0;
}

/*
 * 设置套接字端口
 */
int zje_set_socket_port(const char *port)
{
    if (socket_type != SOCKET_TCP && socket_type != SOCKET_SSL) {
        return 0;
    }
    
    if (port == NULL || strlen(port) == 0) {
        ZJE_DEBUG_SYSLOG("'socket-port' should be provided while using tcp socket");
        return -1;
    }
    
    errno = 0;
    unsigned long val = strtoul(port, NULL, 10);
    if ((errno == ERANGE && val == ULONG_MAX) || (errno != 0 && val == 0)) {
        ZJE_DEBUG_SYSLOG("fail to convert a string of 'socket_port' to an integer: %s", strerror(errno));
        return -1;
    }
    if (val > 65535) {
        ZJE_DEBUG_SYSLOG("'socket_port' is out of range: %ld", val);
        return -1;
    }
    
    socket_port = (unsigned) val;
    return 0;
}

/*
 * 设置 PKCS#12 证书文件路径
 */
int zje_set_pkcs12_certificate_path(const char *path)
{
    if (socket_type != SOCKET_SSL) {
        return 0;
    }
    
    size_t length = strlen(path);
    char *dump = (char *) calloc(length + 1, sizeof(char));
    if (dump == NULL) {
        ZJE_DEBUG_SYSLOG("fail to allocate memory for PKCS#12 certificate path: %s", strerror(errno));
        return -1;
    }
    strncpy(dump, path, length);
    pkcs12_certificate_path = dump;
    return 0;
}

/*
 * 设置 PKCS#12 证书密码
 */
int zje_set_pkcs12_certificate_password(const char *password)
{
    if (socket_type != SOCKET_SSL) {
        return 0;
    }
    
    size_t length = strlen(password);
    char *dump = (char *) calloc(length + 1, sizeof(char));
    if (dump == NULL) {
        ZJE_DEBUG_SYSLOG("fail to allocate memory for PKCS#12 certificate password: %s", strerror(errno));
        return -1;
    }
    strncpy(dump, password, length);
    pkcs12_certificate_password = dump;
    return 0;
}

/*
 * 初始化网络通信模块
 */
int zje_init_net(void)
{
    if (socket_type == SOCKET_SSL) {
        ZJE_LOG_INFO("TLS/SSL enabled");
        
        // 初始化 TLS/SSL 上下文
        if (init_ssl_context() != 0) {
            ZJE_LOG_ERROR("fail to initialize TLS/SSL context");
            return -1;
        }
        
        // judge 退出时释放 TLS/SSL 上下文对象
        if (atexit(free_ssl_context) != 0) {
            ZJE_LOG_ERROR("fail to register free_ssl_context() function with atexit: %s", strerror(errno));
            free_ssl_context();
            return -1;
        }
    }
    
    return 0;
}

/*
 * 建立连接网络
 */
zje_net_connection *zje_net_connect()
{
    BIO *bio = NULL;
    
    if (socket_type == SOCKET_SSL) {
        bio = connect_ssl();
        if (bio == NULL) {
            ZJE_LOG_ERROR("fail to connect ssl");
            return NULL;
        }
    } else if (socket_type == SOCKET_TCP) {
        bio = connect_tcp();
        if (bio == NULL) {
            ZJE_LOG_ERROR("fail to connect tcp");
            return NULL;
        }
    } else if (socket_type == SOCKET_LOCAL) {
        bio = connect_local();
        if (bio == NULL) {
            ZJE_LOG_ERROR("fail to connect local");
            return NULL;
        }
    } else {
        ZJE_LOG_ERROR("invalid socket type");
        return NULL;
    }
    
    zje_net_connection *connection = (zje_net_connection*) malloc(sizeof(zje_net_connection));
    if (connection == NULL) {
        ZJE_LOG_ERROR("fail to allocate memory for zje_net_connection: %s", strerror(errno));
        return NULL;
    }
    
    BIO *bbio = BIO_new(BIO_f_buffer());
    if (bbio == NULL) {
        ZJE_LOG_ERROR("fail to create BIO_f_buffer");
        BIO_free_all(bio);
        return NULL;
    }
    BIO_push(bbio, bio);
    
    connection->bio = bbio;
    return connection;
}

/*
 * 从网络连接中接收数据，直到 CRLF 停止
 * - 接收到的数据中的 CRLF 将被去掉。
 * - 函数会自行分配足够的内存空间给接收到的数据，调用者须自行释放这些空间。
 * > 如果成功，返回 0
 * > 如果失败，返回 -1
 */
int zje_net_recv(zje_net_connection *connection, char **data_ptr)
{
    BIO *bio = connection->bio;
    
    size_t buffer_size = 1024;
    char buffer[buffer_size];
    
    size_t data_size = 1024;
    char *data = (char *) malloc(data_size * sizeof(char));
    if (data == NULL) {
        ZJE_LOG_ERROR("fail to allocate memory while receiving data: %s", strerror(errno));
        return -1;
    }
    data[0] = '\0';
    char *cnt_ptr = data;
    
    while (1) {
        int size = BIO_gets(bio, buffer, buffer_size);
        if (size == -1) {
            ZJE_LOG_ERROR("fail to receive data: %s", openssl_error_string());
            free(data);
            return -1;
        }
        if (size == -2) {
            ZJE_LOG_ERROR("BIO_gets is not implemented");
            free(data);
            return -1;
        }
        
        size_t new_size = ((strlen(data) + size + 1) / 1024 + 1) * 1024;
        if (new_size > data_size) {
            char *temp = (char *) realloc(data, new_size * sizeof(char));
            if (temp == NULL) {
                ZJE_LOG_ERROR("fail to reallocate memory for expansion while receiving data", strerror(errno));
                free(data);
                return -1;
            }
            
            data = temp;
            data_size = new_size;
        }
        
        strncat(data, buffer, size);
        int data_len = strlen(data);
        if (data[data_len - 2] == CR && data[data_len - 1] == LF) {
            data[data_len - 2] = '\0';
            break;
        }
        
    }
    
    *data_ptr = data;
    return 0;
}

/*
 * 向网络连接发送数据，并在数据末尾加上 CRLF
 * > 如果成功，返回 0
 * > 如果失败，返回 -1
 */
int zje_net_send(zje_net_connection *connection, const char *buffer)
{
    BIO *bio = connection->bio;
    
    char *data = (char *) malloc((strlen(buffer) + strlen(CRLF) + 1) * sizeof(char));
    if (data == NULL) {
        ZJE_LOG_ERROR("fail to allocate memory for data to be sent: %s", strerror(errno));
        return -1;
    }
    
    int buffer_size = strlen(buffer);
    strncpy(data, buffer, buffer_size);
    data[buffer_size] = '\0';
    strncat(data, CRLF, strlen(CRLF));
    
    int size = BIO_puts(bio, data);
    free(data);
    if (size == -1) {
        ZJE_LOG_ERROR("fail to send data: ", openssl_error_string());
        return -1;
    }
    if (size == -2) {
        ZJE_LOG_ERROR("BIO_puts is not implemented");
        return -1;
    }
    BIO_flush(bio);
    return 0;
}

/*
 * 断开网络连接
 */
void zje_net_disconnect(zje_net_connection *connection)
{
    if (connection != NULL) {
        BIO_free_all(connection->bio);
        free(connection);
        connection = NULL;
    }
}
