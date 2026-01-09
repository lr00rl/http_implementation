// server.c - HTTPS 服务器（使用自定义 TLS 实现）
//
// 这个服务器演示了如何实现 TLS/SSL 协议的服务器端
// 包括握手协议、密钥派生、加密通信等
//
// 作者注：这是一个教学性质的实现，展示 TLS 服务器的工作原理
// 生产环境请使用经过严格审计的 OpenSSL 或其他成熟的 TLS 库

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

#include "tls_types.h"
#include "tls_crypto.h"
#include "tls_server_handshake.h"
#include "tls_record.h"

#define PORT 4433  // HTTPS 常用测试端口
#define BUFFER_SIZE 16384

// ============================================================================
// HTTPS 服务器主函数
// ============================================================================

int main(int argc, char *argv[]) {
    int port = PORT;

    // 如果提供了命令行参数，使用自定义端口
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    printf("============================================================\n");
    printf("  HTTPS Server with Custom TLS Implementation\n");
    printf("  教学用 TLS 实现 - 展示服务器端加密细节\n");
    printf("============================================================\n\n");
    printf("Server port: %d\n\n", port);

    // ========================================================================
    // 1. 创建监听套接字
    // ========================================================================
    printf("[TCP] Creating server socket...\n");
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    // 设置 SO_REUSEADDR 选项
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_fd);
        return 1;
    }

    // 绑定地址
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    // 开始监听
    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("[TCP] Server listening on port %d\n\n", port);

    // ========================================================================
    // 2. 主循环：接受客户端连接
    // ========================================================================
    while (1) {
        printf("============================================================\n");
        printf("  Waiting for client connection...\n");
        printf("============================================================\n\n");

        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("[TCP] Client connected from %s:%d\n\n", client_ip, ntohs(client_addr.sin_port));

        // ====================================================================
        // 3. 初始化 TLS 会话
        // ====================================================================
        tls_session_t session;
        tls_session_init(&session, client_fd);

        // ====================================================================
        // 4. 执行 TLS 握手
        // ====================================================================
        // TLS 服务器握手过程包括：
        // - 接收 ClientHello
        // - 发送 ServerHello（选择加密套件）
        // - 发送 Certificate（服务器证书）
        // - 发送 ServerKeyExchange（ECDHE 公钥）
        // - 发送 ServerHelloDone
        // - 接收 ClientKeyExchange（客户端 ECDHE 公钥）
        // - 接收 ChangeCipherSpec
        // - 接收 Finished（已加密）
        // - 发送 ChangeCipherSpec
        // - 发送 Finished（已加密）

        if (tls_server_handshake(&session, NULL) < 0) {
            fprintf(stderr, "\n[ERROR] TLS handshake failed!\n");
            tls_session_cleanup(&session);
            close(client_fd);
            continue;
        }

        // ====================================================================
        // 5. 接收 HTTP 请求（已加密）
        // ====================================================================
        printf("[HTTP] Waiting for encrypted HTTP request...\n");

        uint8_t request[BUFFER_SIZE];
        int received = tls_receive_application_data(&session, request, sizeof(request) - 1);

        if (received < 0) {
            fprintf(stderr, "[ERROR] Failed to receive HTTP request\n");
            tls_session_cleanup(&session);
            close(client_fd);
            continue;
        }

        request[received] = '\0';
        printf("\n============================================================\n");
        printf("Decrypted HTTP Request (%d bytes):\n", received);
        printf("============================================================\n");
        printf("%s\n", request);
        printf("============================================================\n\n");

        // ====================================================================
        // 6. 发送 HTTP 响应（已加密）
        // ====================================================================
        printf("[HTTP] Sending encrypted HTTP response...\n");

        const char *response_body =
            "<!DOCTYPE html>\n"
            "<html>\n"
            "<head>\n"
            "    <title>Custom TLS Server</title>\n"
            "</head>\n"
            "<body>\n"
            "    <h1>Hello from Custom TLS Server!</h1>\n"
            "    <p>This response was encrypted using a custom TLS 1.2 implementation.</p>\n"
            "    <h2>TLS Details:</h2>\n"
            "    <ul>\n"
            "        <li>Protocol: TLS 1.2</li>\n"
            "        <li>Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256</li>\n"
            "        <li>Key Exchange: ECDHE (Elliptic Curve Diffie-Hellman)</li>\n"
            "        <li>Encryption: AES-128-GCM</li>\n"
            "        <li>Hash: SHA-256</li>\n"
            "    </ul>\n"
            "    <p><em>Note: This is an educational implementation. "
            "Production systems should use OpenSSL or similar libraries.</em></p>\n"
            "</body>\n"
            "</html>\n";

        char response[BUFFER_SIZE];
        int response_len = snprintf(response, sizeof(response),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            strlen(response_body), response_body);

        // 使用 TLS 发送应用数据
        if (tls_send_application_data(&session, (uint8_t*)response, response_len) < 0) {
            fprintf(stderr, "[ERROR] Failed to send HTTP response\n");
            tls_session_cleanup(&session);
            close(client_fd);
            continue;
        }

        printf("[HTTP] Response sent successfully (%d bytes)\n\n", response_len);

        // ====================================================================
        // 7. 清理
        // ====================================================================
        printf("[TLS] Closing connection...\n");
        tls_session_cleanup(&session);
        close(client_fd);

        printf("\n[Server] Client session completed\n\n");
    }

    // ========================================================================
    // 8. 关闭服务器（实际上不会到达这里）
    // ========================================================================
    close(server_fd);

    return 0;
}
