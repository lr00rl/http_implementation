// tls_server_handshake.c - TLS 服务器端握手协议实现
//
// 这个模块实现了 TLS 1.2 服务器端的握手流程
// 包括接收客户端消息、发送服务器消息、密钥交换等
//
// 注意：这是教学实现，展示 TLS 服务器的工作原理

#include "tls_server_handshake.h"
#include "tls_handshake.h"
#include "tls_record.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

// ============================================================================
// 内置自签名证书（DER 格式，用于教学演示）
// ============================================================================

// 这是一个简化的自签名证书，仅用于教学目的
// 实际应用中应使用真实的 CA 签名证书
static const uint8_t BUILTIN_CERTIFICATE[] = {
    // 这里是一个最小化的 X.509 证书结构
    // 为了简化，我们使用一个占位符证书
    0x30, 0x82, 0x02, 0x00,  // SEQUENCE (证书)
    0x30, 0x82, 0x01, 0x69,  // SEQUENCE (TBSCertificate)
    // ... 证书内容（简化版本）
    // 注：实际实现中应该包含完整的证书
};

// ============================================================================
// ECDHE 密钥交换（简化实现）
// ============================================================================

// 简化的 ECDHE 密钥生成
// 注：实际应使用完整的椭圆曲线实现
static void generate_ecdhe_keypair(uint8_t private_key[32], uint8_t public_key[65]) {
    // 生成私钥（随机 32 字节）
    tls_random_bytes(private_key, 32);

    // 生成公钥（简化实现：未压缩格式）
    // 格式：0x04 || X (32 bytes) || Y (32 bytes)
    public_key[0] = 0x04;  // 未压缩点
    tls_random_bytes(public_key + 1, 64);  // X 和 Y 坐标

    // 注：这是占位符实现，真实的 ECDHE 需要椭圆曲线点乘运算
}

// 简化的 ECDHE 共享密钥计算
static void compute_ecdhe_shared_secret(const uint8_t private_key[32],
                                       const uint8_t peer_public_key[65],
                                       uint8_t shared_secret[32]) {
    // 简化实现：使用 HMAC 模拟 ECDH 计算
    // 真实实现需要椭圆曲线点乘运算
    hmac_sha256(private_key, 32, peer_public_key, 65, shared_secret);
}

// ============================================================================
// 接收 ClientHello
// ============================================================================

int tls_receive_client_hello(tls_session_t *session) {
    printf("[Server] Waiting for ClientHello...\n");

    uint8_t buffer[4096];
    int received = recv(session->socket_fd, buffer, sizeof(buffer), 0);

    if (received < 0) {
        perror("recv");
        return -1;
    }

    printf("[Server] Received %d bytes\n", received);

    // 解析 TLS 记录头
    if (received < 5) {
        fprintf(stderr, "[Server] Invalid TLS record (too short)\n");
        return -1;
    }

    tls_record_header_t *rec_hdr = (tls_record_header_t *)buffer;

    if (rec_hdr->content_type != TLS_CONTENT_HANDSHAKE) {
        fprintf(stderr, "[Server] Expected Handshake, got %d\n", rec_hdr->content_type);
        return -1;
    }

    uint16_t version = ntohs(rec_hdr->version);
    uint16_t length = ntohs(rec_hdr->length);

    printf("[Server] TLS Record: type=%d, version=0x%04x, length=%d\n",
           rec_hdr->content_type, version, length);

    // 解析握手消息头
    uint8_t *handshake_data = buffer + 5;
    tls_handshake_header_t *hs_hdr = (tls_handshake_header_t *)handshake_data;

    if (hs_hdr->msg_type != TLS_HANDSHAKE_CLIENT_HELLO) {
        fprintf(stderr, "[Server] Expected ClientHello, got %d\n", hs_hdr->msg_type);
        return -1;
    }

    uint32_t hs_length = (hs_hdr->length[0] << 16) |
                         (hs_hdr->length[1] << 8) |
                         hs_hdr->length[2];

    printf("[Server] Handshake: type=ClientHello, length=%u\n", hs_length);

    // 保存握手消息（用于计算 Finished）
    if (session->handshake_messages_len + 4 + hs_length <= sizeof(session->handshake_messages)) {
        memcpy(session->handshake_messages + session->handshake_messages_len,
               handshake_data, 4 + hs_length);
        session->handshake_messages_len += 4 + hs_length;
    }

    // 解析 ClientHello 内容
    uint8_t *hello_data = handshake_data + 4;

    // 客户端版本
    uint16_t client_version = (hello_data[0] << 8) | hello_data[1];
    printf("[Server] Client version: 0x%04x\n", client_version);

    // 客户端随机数
    memcpy(session->client_random, hello_data + 2, 32);
    printf("[Server] Client random: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", session->client_random[i]);
    }
    printf("\n");

    printf("[Server] ClientHello received successfully\n\n");
    return 0;
}

// ============================================================================
// 发送 ServerHello
// ============================================================================

int tls_send_server_hello(tls_session_t *session) {
    printf("[Server] Sending ServerHello...\n");

    uint8_t buffer[512];
    size_t offset = 0;

    // TLS 记录头（稍后填充长度）
    buffer[offset++] = TLS_CONTENT_HANDSHAKE;
    buffer[offset++] = (TLS_VERSION_1_2 >> 8) & 0xFF;
    buffer[offset++] = TLS_VERSION_1_2 & 0xFF;
    size_t record_length_pos = offset;
    offset += 2;  // 预留长度字段

    // 握手消息头
    size_t handshake_start = offset;
    buffer[offset++] = TLS_HANDSHAKE_SERVER_HELLO;
    size_t handshake_length_pos = offset;
    offset += 3;  // 预留长度字段

    // ServerHello 内容
    size_t server_hello_start = offset;

    // 服务器版本
    buffer[offset++] = (TLS_VERSION_1_2 >> 8) & 0xFF;
    buffer[offset++] = TLS_VERSION_1_2 & 0xFF;

    // 服务器随机数
    tls_random_bytes(session->server_random, 32);
    memcpy(buffer + offset, session->server_random, 32);
    offset += 32;

    printf("[Server] Server random: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", session->server_random[i]);
    }
    printf("\n");

    // 会话 ID（空）
    buffer[offset++] = 0;

    // 选择的加密套件
    buffer[offset++] = (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 >> 8) & 0xFF;
    buffer[offset++] = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 & 0xFF;

    // 压缩方法（无压缩）
    buffer[offset++] = 0;

    // 扩展（空）
    // 注：可以添加扩展支持

    // 填充长度字段
    size_t server_hello_length = offset - server_hello_start;
    buffer[handshake_length_pos] = (server_hello_length >> 16) & 0xFF;
    buffer[handshake_length_pos + 1] = (server_hello_length >> 8) & 0xFF;
    buffer[handshake_length_pos + 2] = server_hello_length & 0xFF;

    size_t record_length = offset - record_length_pos - 2;
    buffer[record_length_pos] = (record_length >> 8) & 0xFF;
    buffer[record_length_pos + 1] = record_length & 0xFF;

    // 保存握手消息
    size_t handshake_msg_len = offset - handshake_start;
    if (session->handshake_messages_len + handshake_msg_len <= sizeof(session->handshake_messages)) {
        memcpy(session->handshake_messages + session->handshake_messages_len,
               buffer + handshake_start, handshake_msg_len);
        session->handshake_messages_len += handshake_msg_len;
    }

    // 发送
    if (send(session->socket_fd, buffer, offset, 0) < 0) {
        perror("send");
        return -1;
    }

    printf("[Server] ServerHello sent (%zu bytes)\n\n", offset);
    return 0;
}

// ============================================================================
// 发送 Certificate
// ============================================================================

int tls_send_certificate(tls_session_t *session, tls_server_certificate_t *cert) {
    printf("[Server] Sending Certificate...\n");

    uint8_t buffer[4096];
    size_t offset = 0;

    // TLS 记录头
    buffer[offset++] = TLS_CONTENT_HANDSHAKE;
    buffer[offset++] = (TLS_VERSION_1_2 >> 8) & 0xFF;
    buffer[offset++] = TLS_VERSION_1_2 & 0xFF;
    size_t record_length_pos = offset;
    offset += 2;

    // 握手消息头
    size_t handshake_start = offset;
    buffer[offset++] = TLS_HANDSHAKE_CERTIFICATE;
    size_t handshake_length_pos = offset;
    offset += 3;

    // Certificate 内容
    // 证书链长度（3 字节）
    size_t cert_chain_length_pos = offset;
    offset += 3;

    // 单个证书
    const uint8_t *cert_data;
    size_t cert_len;

    if (cert && cert->cert_data) {
        cert_data = cert->cert_data;
        cert_len = cert->cert_len;
    } else {
        // 使用内置证书
        cert_data = BUILTIN_CERTIFICATE;
        cert_len = sizeof(BUILTIN_CERTIFICATE);
    }

    // 证书长度（3 字节）
    buffer[offset++] = (cert_len >> 16) & 0xFF;
    buffer[offset++] = (cert_len >> 8) & 0xFF;
    buffer[offset++] = cert_len & 0xFF;

    // 证书数据
    memcpy(buffer + offset, cert_data, cert_len);
    offset += cert_len;

    // 填充证书链长度
    size_t cert_chain_length = offset - cert_chain_length_pos - 3;
    buffer[cert_chain_length_pos] = (cert_chain_length >> 16) & 0xFF;
    buffer[cert_chain_length_pos + 1] = (cert_chain_length >> 8) & 0xFF;
    buffer[cert_chain_length_pos + 2] = cert_chain_length & 0xFF;

    // 填充握手长度
    size_t handshake_length = offset - handshake_start - 4;
    buffer[handshake_length_pos] = (handshake_length >> 16) & 0xFF;
    buffer[handshake_length_pos + 1] = (handshake_length >> 8) & 0xFF;
    buffer[handshake_length_pos + 2] = handshake_length & 0xFF;

    // 填充记录长度
    size_t record_length = offset - record_length_pos - 2;
    buffer[record_length_pos] = (record_length >> 8) & 0xFF;
    buffer[record_length_pos + 1] = record_length & 0xFF;

    // 保存握手消息
    size_t handshake_msg_len = offset - handshake_start;
    if (session->handshake_messages_len + handshake_msg_len <= sizeof(session->handshake_messages)) {
        memcpy(session->handshake_messages + session->handshake_messages_len,
               buffer + handshake_start, handshake_msg_len);
        session->handshake_messages_len += handshake_msg_len;
    }

    // 发送
    if (send(session->socket_fd, buffer, offset, 0) < 0) {
        perror("send");
        return -1;
    }

    printf("[Server] Certificate sent (%zu bytes, cert size: %zu)\n\n", offset, cert_len);
    return 0;
}

// ============================================================================
// 发送 ServerKeyExchange
// ============================================================================

int tls_send_server_key_exchange(tls_session_t *session, const uint8_t *server_public_key) {
    printf("[Server] Sending ServerKeyExchange...\n");

    uint8_t buffer[1024];
    size_t offset = 0;

    // TLS 记录头
    buffer[offset++] = TLS_CONTENT_HANDSHAKE;
    buffer[offset++] = (TLS_VERSION_1_2 >> 8) & 0xFF;
    buffer[offset++] = TLS_VERSION_1_2 & 0xFF;
    size_t record_length_pos = offset;
    offset += 2;

    // 握手消息头
    size_t handshake_start = offset;
    buffer[offset++] = TLS_HANDSHAKE_SERVER_KEY_EXCHANGE;
    size_t handshake_length_pos = offset;
    offset += 3;

    // ServerKeyExchange 内容（ECDHE）

    // 曲线类型（named_curve = 3）
    buffer[offset++] = 3;

    // 曲线 ID（secp256r1 = 23）
    buffer[offset++] = 0x00;
    buffer[offset++] = TLS_EC_CURVE_SECP256R1;

    // 公钥长度
    buffer[offset++] = 65;  // 未压缩格式：1 + 32 + 32

    // 公钥数据
    memcpy(buffer + offset, server_public_key, 65);
    offset += 65;

    // 签名（简化实现：使用占位符）
    // 实际应使用服务器私钥对参数进行签名

    // 签名算法（rsa_pkcs1_sha256 = 0x0401）
    buffer[offset++] = 0x04;
    buffer[offset++] = 0x01;

    // 签名长度（占位符）
    uint16_t signature_len = 256;  // 典型的 RSA-2048 签名长度
    buffer[offset++] = (signature_len >> 8) & 0xFF;
    buffer[offset++] = signature_len & 0xFF;

    // 签名数据（占位符：全零）
    memset(buffer + offset, 0, signature_len);
    offset += signature_len;

    // 填充长度
    size_t handshake_length = offset - handshake_start - 4;
    buffer[handshake_length_pos] = (handshake_length >> 16) & 0xFF;
    buffer[handshake_length_pos + 1] = (handshake_length >> 8) & 0xFF;
    buffer[handshake_length_pos + 2] = handshake_length & 0xFF;

    size_t record_length = offset - record_length_pos - 2;
    buffer[record_length_pos] = (record_length >> 8) & 0xFF;
    buffer[record_length_pos + 1] = record_length & 0xFF;

    // 保存握手消息
    size_t handshake_msg_len = offset - handshake_start;
    if (session->handshake_messages_len + handshake_msg_len <= sizeof(session->handshake_messages)) {
        memcpy(session->handshake_messages + session->handshake_messages_len,
               buffer + handshake_start, handshake_msg_len);
        session->handshake_messages_len += handshake_msg_len;
    }

    // 发送
    if (send(session->socket_fd, buffer, offset, 0) < 0) {
        perror("send");
        return -1;
    }

    printf("[Server] ServerKeyExchange sent (%zu bytes)\n\n", offset);
    return 0;
}

// ============================================================================
// 发送 ServerHelloDone
// ============================================================================

int tls_send_server_hello_done(tls_session_t *session) {
    printf("[Server] Sending ServerHelloDone...\n");

    uint8_t buffer[128];
    size_t offset = 0;

    // TLS 记录头
    buffer[offset++] = TLS_CONTENT_HANDSHAKE;
    buffer[offset++] = (TLS_VERSION_1_2 >> 8) & 0xFF;
    buffer[offset++] = TLS_VERSION_1_2 & 0xFF;
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x04;  // 长度 = 4

    // 握手消息
    size_t handshake_start = offset;
    buffer[offset++] = TLS_HANDSHAKE_SERVER_HELLO_DONE;
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x00;  // 长度 = 0

    // 保存握手消息
    size_t handshake_msg_len = offset - handshake_start;
    if (session->handshake_messages_len + handshake_msg_len <= sizeof(session->handshake_messages)) {
        memcpy(session->handshake_messages + session->handshake_messages_len,
               buffer + handshake_start, handshake_msg_len);
        session->handshake_messages_len += handshake_msg_len;
    }

    // 发送
    if (send(session->socket_fd, buffer, offset, 0) < 0) {
        perror("send");
        return -1;
    }

    printf("[Server] ServerHelloDone sent (%zu bytes)\n\n", offset);
    return 0;
}

// ============================================================================
// 接收 ClientKeyExchange
// ============================================================================

int tls_receive_client_key_exchange(tls_session_t *session, uint8_t *client_public_key) {
    printf("[Server] Waiting for ClientKeyExchange...\n");

    uint8_t buffer[4096];
    int received = recv(session->socket_fd, buffer, sizeof(buffer), 0);

    if (received < 0) {
        perror("recv");
        return -1;
    }

    printf("[Server] Received %d bytes\n", received);

    // 解析 TLS 记录
    if (received < 5) {
        fprintf(stderr, "[Server] Invalid TLS record\n");
        return -1;
    }

    tls_record_header_t *rec_hdr = (tls_record_header_t *)buffer;

    if (rec_hdr->content_type != TLS_CONTENT_HANDSHAKE) {
        fprintf(stderr, "[Server] Expected Handshake\n");
        return -1;
    }

    // 解析握手消息
    uint8_t *handshake_data = buffer + 5;
    tls_handshake_header_t *hs_hdr = (tls_handshake_header_t *)handshake_data;

    if (hs_hdr->msg_type != TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE) {
        fprintf(stderr, "[Server] Expected ClientKeyExchange, got %d\n", hs_hdr->msg_type);
        return -1;
    }

    uint32_t hs_length = (hs_hdr->length[0] << 16) |
                         (hs_hdr->length[1] << 8) |
                         hs_hdr->length[2];

    // 保存握手消息
    if (session->handshake_messages_len + 4 + hs_length <= sizeof(session->handshake_messages)) {
        memcpy(session->handshake_messages + session->handshake_messages_len,
               handshake_data, 4 + hs_length);
        session->handshake_messages_len += 4 + hs_length;
    }

    // 提取客户端公钥
    uint8_t *key_data = handshake_data + 4;
    uint8_t key_len = key_data[0];

    if (key_len == 65) {
        memcpy(client_public_key, key_data + 1, 65);
        printf("[Server] Client public key received (65 bytes)\n");
    } else {
        fprintf(stderr, "[Server] Invalid client public key length: %d\n", key_len);
        return -1;
    }

    printf("[Server] ClientKeyExchange received successfully\n\n");
    return 0;
}

// ============================================================================
// 接收 ChangeCipherSpec
// ============================================================================

int tls_receive_change_cipher_spec(tls_session_t *session) {
    printf("[Server] Waiting for ChangeCipherSpec...\n");

    uint8_t buffer[256];
    int received = recv(session->socket_fd, buffer, sizeof(buffer), 0);

    if (received < 0) {
        perror("recv");
        return -1;
    }

    printf("[Server] Received %d bytes\n", received);

    if (received < 6) {
        fprintf(stderr, "[Server] Invalid ChangeCipherSpec\n");
        return -1;
    }

    tls_record_header_t *rec_hdr = (tls_record_header_t *)buffer;

    if (rec_hdr->content_type != TLS_CONTENT_CHANGE_CIPHER_SPEC) {
        fprintf(stderr, "[Server] Expected ChangeCipherSpec, got %d\n", rec_hdr->content_type);
        return -1;
    }

    printf("[Server] ChangeCipherSpec received\n\n");
    return 0;
}

// ============================================================================
// 接收客户端 Finished
// ============================================================================

int tls_receive_client_finished(tls_session_t *session) {
    printf("[Server] Waiting for client Finished (encrypted)...\n");

    uint8_t plaintext[128];

    int received = tls_receive_application_data(session, plaintext, sizeof(plaintext));

    if (received < 0) {
        fprintf(stderr, "[Server] Failed to receive Finished\n");
        return -1;
    }

    printf("[Server] Received encrypted Finished (%d bytes decrypted)\n", received);

    // 验证 Finished 消息
    // 计算期望的 verify_data
    uint8_t expected_verify_data[12];
    tls_compute_verify_data(session, "client finished", expected_verify_data);

    // 检查 Finished 消息格式
    if (received < 16) {  // 4 字节握手头 + 12 字节 verify_data
        fprintf(stderr, "[Server] Invalid Finished message length\n");
        return -1;
    }

    tls_handshake_header_t *hs_hdr = (tls_handshake_header_t *)plaintext;
    if (hs_hdr->msg_type != TLS_HANDSHAKE_FINISHED) {
        fprintf(stderr, "[Server] Expected Finished message\n");
        return -1;
    }

    // 比较 verify_data
    uint8_t *received_verify_data = plaintext + 4;
    if (memcmp(received_verify_data, expected_verify_data, 12) == 0) {
        printf("[Server] Client Finished verified successfully!\n\n");
        return 0;
    } else {
        fprintf(stderr, "[Server] Finished verification failed!\n");
        return -1;
    }
}

// ============================================================================
// 发送服务器 ChangeCipherSpec
// ============================================================================

int tls_send_server_change_cipher_spec(tls_session_t *session) {
    printf("[Server] Sending ChangeCipherSpec...\n");

    uint8_t buffer[16];
    size_t offset = 0;

    // TLS 记录头
    buffer[offset++] = TLS_CONTENT_CHANGE_CIPHER_SPEC;
    buffer[offset++] = (TLS_VERSION_1_2 >> 8) & 0xFF;
    buffer[offset++] = TLS_VERSION_1_2 & 0xFF;
    buffer[offset++] = 0x00;
    buffer[offset++] = 0x01;  // 长度 = 1

    // ChangeCipherSpec 消息
    buffer[offset++] = 0x01;

    // 发送
    if (send(session->socket_fd, buffer, offset, 0) < 0) {
        perror("send");
        return -1;
    }

    // 启用加密
    session->encryption_enabled = 1;

    printf("[Server] ChangeCipherSpec sent, encryption enabled\n\n");
    return 0;
}

// ============================================================================
// 发送服务器 Finished
// ============================================================================

int tls_send_server_finished(tls_session_t *session) {
    printf("[Server] Sending Finished (encrypted)...\n");

    // 计算 verify_data
    uint8_t verify_data[12];
    tls_compute_verify_data(session, "server finished", verify_data);

    // 构造 Finished 消息
    uint8_t finished_msg[16];
    finished_msg[0] = TLS_HANDSHAKE_FINISHED;
    finished_msg[1] = 0x00;
    finished_msg[2] = 0x00;
    finished_msg[3] = 0x0C;  // 长度 = 12
    memcpy(finished_msg + 4, verify_data, 12);

    // 发送加密的 Finished 消息
    if (tls_send_application_data(session, finished_msg, 16) < 0) {
        fprintf(stderr, "[Server] Failed to send Finished\n");
        return -1;
    }

    printf("[Server] Finished sent (encrypted)\n\n");
    return 0;
}

// ============================================================================
// 完整的服务器握手流程
// ============================================================================

int tls_server_handshake(tls_session_t *session, tls_server_certificate_t *cert) {
    printf("\n");
    printf("============================================================\n");
    printf("  TLS 1.2 Server Handshake - Educational Implementation\n");
    printf("============================================================\n\n");

    // 生成服务器的 ECDHE 密钥对
    uint8_t server_private_key[32];
    uint8_t server_public_key[65];
    generate_ecdhe_keypair(server_private_key, server_public_key);

    printf("[Server] Generated ECDHE keypair\n\n");

    // 1. 接收 ClientHello
    if (tls_receive_client_hello(session) < 0) {
        return -1;
    }

    // 2. 发送 ServerHello
    if (tls_send_server_hello(session) < 0) {
        return -1;
    }

    // 3. 发送 Certificate
    if (tls_send_certificate(session, cert) < 0) {
        return -1;
    }

    // 4. 发送 ServerKeyExchange
    if (tls_send_server_key_exchange(session, server_public_key) < 0) {
        return -1;
    }

    // 5. 发送 ServerHelloDone
    if (tls_send_server_hello_done(session) < 0) {
        return -1;
    }

    // 6. 接收 ClientKeyExchange
    uint8_t client_public_key[65];
    if (tls_receive_client_key_exchange(session, client_public_key) < 0) {
        return -1;
    }

    // 7. 计算共享密钥
    uint8_t shared_secret[32];
    compute_ecdhe_shared_secret(server_private_key, client_public_key, shared_secret);

    printf("[Server] Computed ECDHE shared secret\n\n");

    // 8. 派生主密钥
    tls_derive_master_secret(shared_secret, session);

    printf("[Server] Derived master secret\n\n");

    // 9. 派生会话密钥
    tls_derive_keys(session);

    printf("[Server] Derived session keys\n\n");

    // 10. 接收 ChangeCipherSpec
    if (tls_receive_change_cipher_spec(session) < 0) {
        return -1;
    }

    // 启用客户端加密（用于接收 Finished）
    session->encryption_enabled = 1;

    // 11. 接收客户端 Finished
    if (tls_receive_client_finished(session) < 0) {
        return -1;
    }

    // 12. 发送 ChangeCipherSpec
    if (tls_send_server_change_cipher_spec(session) < 0) {
        return -1;
    }

    // 13. 发送服务器 Finished
    if (tls_send_server_finished(session) < 0) {
        return -1;
    }

    printf("============================================================\n");
    printf("  TLS Handshake Complete!\n");
    printf("  Secure channel established\n");
    printf("============================================================\n\n");

    return 0;
}

// ============================================================================
// 证书辅助函数
// ============================================================================

tls_server_certificate_t* tls_generate_self_signed_certificate(void) {
    tls_server_certificate_t *cert = malloc(sizeof(tls_server_certificate_t));
    if (!cert) {
        return NULL;
    }

    // 使用内置证书
    cert->cert_len = sizeof(BUILTIN_CERTIFICATE);
    cert->cert_data = malloc(cert->cert_len);
    if (!cert->cert_data) {
        free(cert);
        return NULL;
    }

    memcpy(cert->cert_data, BUILTIN_CERTIFICATE, cert->cert_len);

    // 私钥（占位符）
    cert->private_key_len = 0;
    cert->private_key = NULL;

    return cert;
}

void tls_free_certificate(tls_server_certificate_t *cert) {
    if (cert) {
        if (cert->cert_data) {
            free(cert->cert_data);
        }
        if (cert->private_key) {
            free(cert->private_key);
        }
        free(cert);
    }
}

