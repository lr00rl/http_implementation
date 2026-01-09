// client.c - HTTPS 客户端（使用自定义 TLS 实现）
//
// 这个客户端演示了如何手动实现 TLS/SSL 协议的核心功能
// 包括加密算法、握手协议、密钥派生等
//
// 作者注：这是一个教学性质的实现，展示 TLS 的工作原理
// 生产环境请使用经过严格审计的 OpenSSL 或其他成熟的 TLS 库

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

// ============================================================================
// HTTPS 客户端主函数
// ============================================================================

int main(int argc, char *argv[]) {
    const char *hostname = "example.com";  // 目标主机名
    const char *ip_address = "93.184.216.34";  // example.com 的 IP
    int port = 443;  // HTTPS 默认端口

    // 如果提供了命令行参数，使用自定义主机
    if (argc > 1) {
        hostname = argv[1];
        ip_address = argv[1];  // 简化实现，假设提供的是 IP
    }
    if (argc > 2) {
        port = atoi(argv[2]);
    }

    printf("============================================================\n");
    printf("  HTTPS Client with Custom TLS Implementation\n");
    printf("  教学用 TLS 实现 - 展示加密细节\n");
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
    // TLS 握手过程包括：
    // - ClientHello: 客户端发送支持的加密套件和随机数
    // - ServerHello: 服务器选择加密套件并发送随机数
    // - Certificate: 服务器发送证书
    // - ServerKeyExchange: 服务器发送 ECDHE 公钥
    // - ServerHelloDone: 服务器握手消息结束
    // - ClientKeyExchange: 客户端发送 ECDHE 公钥
    // - ChangeCipherSpec: 切换到加密模式
    // - Finished: 发送握手完成消息（已加密）
    //
    // 在这个过程中：
    // 1. 使用 ECDHE 进行密钥交换（生成共享密钥）
    // 2. 使用 PRF (伪随机函数) 从共享密钥派生主密钥
    // 3. 从主密钥派生会话密钥（加密密钥和 IV）
    // 4. 使用 AES-128-GCM 进行后续通信加密

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
        "User-Agent: CustomTLS/1.0\r\n"
        "Connection: close\r\n"
        "\r\n",
        hostname);

    printf("Request:\n%s\n", request);

    // 使用 TLS 发送应用数据
    // 数据将通过以下步骤加密：
    // 1. 构造 GCM nonce (IV + 序列号)
    // 2. 使用 AES-128-GCM 加密数据
    // 3. 生成认证标签 (GMAC)
    // 4. 发送加密数据和标签
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

    // 接收响应数据
    // 数据将通过以下步骤解密：
    // 1. 接收 TLS 记录（包含加密数据和认证标签）
    // 2. 提取 GCM nonce
    // 3. 使用 AES-128-GCM 解密数据
    // 4. 验证认证标签（防止篡改）
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
    printf("  TLS 加密通信演示完成\n");
    printf("============================================================\n\n");

    printf("TLS 关键技术总结：\n");
    printf("1. 对称加密: AES-128-GCM (加密应用数据)\n");
    printf("   - AES: 高级加密标准，使用 128-bit 密钥\n");
    printf("   - GCM: Galois/Counter Mode，提供加密和认证\n");
    printf("   - 每个记录使用唯一的 nonce (IV + 序列号)\n\n");

    printf("2. 哈希函数: SHA-256 (消息摘要和 HMAC)\n");
    printf("   - 用于生成消息摘要\n");
    printf("   - 用于 HMAC (消息认证码)\n");
    printf("   - 用于 PRF (伪随机函数) 派生密钥\n\n");

    printf("3. 密钥派生: TLS PRF (伪随机函数)\n");
    printf("   - 从预主密钥派生主密钥\n");
    printf("   - 从主密钥派生会话密钥\n");
    printf("   - 基于 HMAC-SHA256 的 P_hash 函数\n\n");

    printf("4. 密钥交换: ECDHE (椭圆曲线 Diffie-Hellman)\n");
    printf("   - 提供前向保密性\n");
    printf("   - 使用椭圆曲线 P-256 (secp256r1)\n");
    printf("   - 注：本实现为简化版本\n\n");

    printf("5. 记录层协议:\n");
    printf("   - 分段：将数据分成记录\n");
    printf("   - 加密：使用会话密钥加密\n");
    printf("   - 认证：使用 GMAC 防止篡改\n\n");

    printf("注意：这是教学实现，生产环境请使用 OpenSSL！\n\n");

    return 0;
}
