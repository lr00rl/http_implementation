// test_client.c - 测试客户端（连接到本地 HTTPS 服务器）
//
// 这个客户端用于测试自定义 TLS 服务器
// 它连接到 localhost 而不是远程服务器

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

#include "tls_types.h"
#include "tls_crypto.h"
#include "tls_handshake.h"
#include "tls_record.h"

int main(int argc, char *argv[]) {
    const char *hostname = "localhost";
    const char *ip_address = "127.0.0.1";
    int port = 4433;  // 默认测试端口

    // 如果提供了命令行参数，使用自定义端口
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    printf("============================================================\n");
    printf("  TLS Test Client - Connecting to Local Server\n");
    printf("============================================================\n\n");
    printf("Target: %s:%d\n", hostname, port);
    printf("IP: %s\n\n", ip_address);

    // ========================================================================
    // 1. 建立 TCP 连接
    // ========================================================================
    printf("[TCP] Creating socket...\n");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip_address, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address: %s\n", ip_address);
        close(sock);
        return 1;
    }

    printf("[TCP] Connecting to %s:%d...\n", ip_address, port);
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }
    printf("[TCP] Connected successfully!\n\n");

    // ========================================================================
    // 2. 初始化 TLS 会话
    // ========================================================================
    tls_session_t session;
    tls_session_init(&session, sock);

    // ========================================================================
    // 3. 执行 TLS 握手
    // ========================================================================
    if (tls_handshake(&session, hostname) < 0) {
        fprintf(stderr, "\n[ERROR] TLS handshake failed!\n");
        tls_session_cleanup(&session);
        close(sock);
        return 1;
    }

    // ========================================================================
    // 4. 发送 HTTP 请求（已加密）
    // ========================================================================
    printf("[HTTP] Sending encrypted HTTP request...\n");

    char request[512];
    snprintf(request, sizeof(request),
        "GET / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: CustomTLS-TestClient/1.0\r\n"
        "Connection: close\r\n"
        "\r\n",
        hostname);

    printf("Request:\n%s\n", request);

    if (tls_send_application_data(&session, (uint8_t*)request, strlen(request)) < 0) {
        fprintf(stderr, "[ERROR] Failed to send HTTP request\n");
        tls_session_cleanup(&session);
        close(sock);
        return 1;
    }

    printf("[HTTP] Request sent successfully\n\n");

    // ========================================================================
    // 5. 接收 HTTP 响应（已加密）
    // ========================================================================
    printf("[HTTP] Receiving encrypted HTTP response...\n");

    uint8_t response[16384];
    int total_received = 0;

    while (1) {
        int received = tls_receive_application_data(&session,
                                                     response + total_received,
                                                     sizeof(response) - total_received);
        if (received < 0) {
            break;  // 连接关闭或错误
        }

        total_received += received;

        // 检查是否接收完整
        if ((size_t)total_received >= sizeof(response) - 1) {
            break;
        }
    }

    if (total_received > 0) {
        response[total_received] = '\0';
        printf("\n============================================================\n");
        printf("Decrypted HTTP Response (%d bytes):\n", total_received);
        printf("============================================================\n");
        printf("%s\n", response);
        printf("============================================================\n\n");
    } else {
        printf("[WARNING] No response received or connection closed\n\n");
    }

    // ========================================================================
    // 6. 清理
    // ========================================================================
    printf("[TLS] Closing connection...\n");
    tls_session_cleanup(&session);
    close(sock);

    printf("\n============================================================\n");
    printf("  Test Complete!\n");
    printf("============================================================\n\n");

    return 0;
}

