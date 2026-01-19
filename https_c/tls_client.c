#include "tls_client.h"
#include <stdio.h>
#include <string.h>

int tls_client_init(tls_client_t *client) {
    memset(client, 0, sizeof(*client));

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif

    client->ctx = SSL_CTX_new(TLS_client_method());
    if (!client->ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Set minimum TLS version to 1.2
    SSL_CTX_set_min_proto_version(client->ctx, TLS1_2_VERSION);

    // Load default trusted CA certificates
    if (!SSL_CTX_set_default_verify_paths(client->ctx)) {
        fprintf(stderr, "Failed to load default CA certificates\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(client->ctx);
        return -1;
    }

    return 0;
}

int tls_client_connect(tls_client_t *client, int sock, const char *hostname) {
    client->sock = sock;
    client->ssl = SSL_new(client->ctx);
    if (!client->ssl) {
        fprintf(stderr, "Failed to create SSL structure\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

/*
✦ client->ssl 的类型是 SSL*，在 OpenSSL 库中，SSL 是一个 不透明结构体（Opaque Structure）。

  这意味着：

   1. 你无法直接查看或访问其内部成员： OpenSSL 库的头文件（如 ssl.h）通常不会暴露 SSL 结构体的具体定义（例如，你不会看到 struct ssl_st { ... } 这样的完整定义）。你不能像 client->ssl->some_field 这样直接访问它的内部字段。
   2. 通过 API 函数进行交互： 所有对 SSL 对象的创建、配置、操作和查询都必须通过 OpenSSL 提供的专门的 API 函数来完成（例如 SSL_new()、SSL_set_fd()、SSL_read()、SSL_get_version() 等）。

  SSL 结构体在概念上代表什么？

  尽管是内部结构，但从功能上讲，一个 SSL 对象（SSL* 指向的实例）代表着一个 独立的、正在进行中的 TLS/SSL 会话。它封装了所有与这个特定会话相关的状态和信息，包括：

   1. 会话状态机： 记录了当前 TLS 握手的各个阶段（例如，等待 ClientHello、发送 ServerHello、验证证书、密钥交换等）。
   2. 协商好的协议参数：
       * TLS/SSL 版本： 当前会话使用的 TLS 协议版本（如 TLSv1.2, TLSv1.3）。SSL_get_version() 可以获取。
       * 密码套件（Cipher Suite）： 双方协商并选定的加密算法、哈希算法和密钥交换算法组合。SSL_get_cipher() 可以获取。
       * 压缩方法： 如果启用了压缩，会记录使用的压缩算法（现在 TLS1.3 已移除）。
   3. 连接引用：
       * 上下文引用： 它会持有创建它的 SSL_CTX 对象的引用，从而继承上下文中的配置（如证书、私钥、CA 信任链、回调函数等）。
       * 底层 I/O 引用： 它与底层的网络连接（例如通过 SSL_set_fd() 设置的文件描述符或通过 BIO 设置的 I/O 抽象层）关联，负责通过该通道发送和接收加密数据。
   4. 会话密钥： 存储着为当前会话协商和生成的对称加密密钥、HMAC 密钥等，用于后续应用数据的加密和认证。
   5. 证书信息： 存储了远程端（服务器或客户端）发送的证书链信息，以及本地证书信息。
   6. 会话 ID / 会话票据（Session ID / Session Ticket）： 用于会话复用的信息，可以在后续连接中加快握手速度。
   7. 各种标志和选项： 记录了针对这个特定会话启用的各种功能和行为选项。

  所以，当你看到 client->ssl 时，你应该理解它是一个指向 OpenSSL 内部数据结构的指针，这个数据结构承载了一个 TLS 客户端会话的所有动态信息和状态。你通过调用 SSL_... 系列函数来操作和查询这个会话。
*/

    // Set SNI (Server Name Indication)
    SSL_set_tlsext_host_name(client->ssl, hostname);

    // Set hostname for certificate verification
    SSL_set1_host(client->ssl, hostname);

    // Associate socket with SSL
    SSL_set_fd(client->ssl, sock);

    // Perform TLS handshake
    int ret = SSL_connect(client->ssl);
    if (ret != 1) {
        fprintf(stderr, "TLS handshake failed: ");
        int err = SSL_get_error(client->ssl, ret);
        switch (err) {
            case SSL_ERROR_ZERO_RETURN:
                fprintf(stderr, "Connection closed\n");
                break;
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                fprintf(stderr, "Non-blocking I/O\n");
                break;
            case SSL_ERROR_SYSCALL:
                fprintf(stderr, "I/O error\n");
                break;
            case SSL_ERROR_SSL:
                fprintf(stderr, "SSL protocol error\n");
                ERR_print_errors_fp(stderr);
                break;
            default:
                fprintf(stderr, "Unknown error %d\n", err);
                break;
        }
        SSL_free(client->ssl);
        client->ssl = NULL;
        return -1;
    }

    printf("TLS handshake successful\n");
    printf("Protocol: %s\n", SSL_get_version(client->ssl));
    printf("Cipher: %s\n", SSL_get_cipher(client->ssl));

    return 0;
}

int tls_client_write(tls_client_t *client, const void *buf, int len) {
    if (!client->ssl) return -1;

    int total_sent = 0;
    while (total_sent < len) {
        int sent = SSL_write(client->ssl, (char*)buf + total_sent, len - total_sent);
        if (sent <= 0) {
            int err = SSL_get_error(client->ssl, sent);
            fprintf(stderr, "SSL_write error: %d\n", err);
            return -1;
        }
        total_sent += sent;
    }
    return total_sent;
}

int tls_client_read(tls_client_t *client, void *buf, int len) {
    if (!client->ssl) return -1;

    int received = SSL_read(client->ssl, buf, len);
    if (received < 0) {
        int err = SSL_get_error(client->ssl, received);
        fprintf(stderr, "SSL_read error: %d\n", err);
        return -1;
    }
    return received;
}

void tls_client_close(tls_client_t *client) {
    if (client->ssl) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
    if (client->ctx) {
        SSL_CTX_free(client->ctx);
        client->ctx = NULL;
    }
}
