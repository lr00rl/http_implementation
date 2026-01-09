// tls_handshake.c - TLS 握手协议实现
#include "tls_handshake.h"
#include "tls_record.h"
#include "tls_crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <unistd.h>

// ============================================================================
// 辅助函数
// ============================================================================

// 将 24-bit 整数写入缓冲区 (大端序)
static void write_uint24(uint8_t *buf, uint32_t value) {
    buf[0] = (value >> 16) & 0xFF;
    buf[1] = (value >> 8) & 0xFF;
    buf[2] = value & 0xFF;
}

// 从缓冲区读取 24-bit 整数 (大端序)
static uint32_t read_uint24(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 16) | ((uint32_t)buf[1] << 8) | buf[2];
}

// 添加握手消息到缓冲区 (用于计算 Finished)
static void record_handshake_message(tls_session_t *session, const uint8_t *data, size_t len) {
    if (session->handshake_messages_len + len <= sizeof(session->handshake_messages)) {
        memcpy(session->handshake_messages + session->handshake_messages_len, data, len);
        session->handshake_messages_len += len;
    }
}

// ============================================================================
// ClientHello
// ============================================================================

int tls_send_client_hello(tls_session_t *session, const char *hostname) {
    uint8_t client_hello[512];
    size_t offset = 0;

    // 生成客户端随机数
    uint32_t timestamp = time(NULL);
    session->client_random[0] = (timestamp >> 24) & 0xFF;
    session->client_random[1] = (timestamp >> 16) & 0xFF;
    session->client_random[2] = (timestamp >> 8) & 0xFF;
    session->client_random[3] = timestamp & 0xFF;
    tls_random_bytes(session->client_random + 4, 28);

    // 握手消息头
    client_hello[offset++] = TLS_HANDSHAKE_CLIENT_HELLO;
    offset += 3;  // 长度稍后填充

    size_t handshake_start = offset;

    // TLS 版本
    client_hello[offset++] = (TLS_VERSION_1_2 >> 8) & 0xFF;
    client_hello[offset++] = TLS_VERSION_1_2 & 0xFF;

    // 随机数 (32 字节)
    memcpy(client_hello + offset, session->client_random, 32);
    offset += 32;

    // Session ID (空)
    client_hello[offset++] = 0;

    // 加密套件列表
    client_hello[offset++] = 0;  // 长度 (2 字节)
    client_hello[offset++] = 2;
    client_hello[offset++] = (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 >> 8) & 0xFF;
    client_hello[offset++] = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 & 0xFF;

    // 压缩方法 (null)
    client_hello[offset++] = 1;
    client_hello[offset++] = 0;

    // 扩展
    size_t extensions_length_offset = offset;
    offset += 2;  // 扩展总长度稍后填充
    size_t extensions_start = offset;

    // SNI 扩展 (Server Name Indication)
    if (hostname) {
        size_t hostname_len = strlen(hostname);
        client_hello[offset++] = (TLS_EXT_SERVER_NAME >> 8) & 0xFF;
        client_hello[offset++] = TLS_EXT_SERVER_NAME & 0xFF;
        uint16_t ext_len = hostname_len + 5;
        client_hello[offset++] = (ext_len >> 8) & 0xFF;
        client_hello[offset++] = ext_len & 0xFF;
        // Server Name List Length
        client_hello[offset++] = ((hostname_len + 3) >> 8) & 0xFF;
        client_hello[offset++] = (hostname_len + 3) & 0xFF;
        // Server Name Type (0 = host_name)
        client_hello[offset++] = 0;
        // Server Name Length
        client_hello[offset++] = (hostname_len >> 8) & 0xFF;
        client_hello[offset++] = hostname_len & 0xFF;
        // Server Name
        memcpy(client_hello + offset, hostname, hostname_len);
        offset += hostname_len;
    }

    // Supported Groups 扩展 (椭圆曲线)
    client_hello[offset++] = (TLS_EXT_SUPPORTED_GROUPS >> 8) & 0xFF;
    client_hello[offset++] = TLS_EXT_SUPPORTED_GROUPS & 0xFF;
    client_hello[offset++] = 0;
    client_hello[offset++] = 4;  // 扩展数据长度
    client_hello[offset++] = 0;
    client_hello[offset++] = 2;  // 曲线列表长度
    client_hello[offset++] = (TLS_EC_CURVE_SECP256R1 >> 8) & 0xFF;
    client_hello[offset++] = TLS_EC_CURVE_SECP256R1 & 0xFF;

    // EC Point Formats 扩展
    client_hello[offset++] = (TLS_EXT_EC_POINT_FORMATS >> 8) & 0xFF;
    client_hello[offset++] = TLS_EXT_EC_POINT_FORMATS & 0xFF;
    client_hello[offset++] = 0;
    client_hello[offset++] = 2;  // 扩展数据长度
    client_hello[offset++] = 1;  // 格式列表长度
    client_hello[offset++] = 0;  // uncompressed

    // 填充扩展总长度
    uint16_t extensions_length = offset - extensions_start;
    client_hello[extensions_length_offset] = (extensions_length >> 8) & 0xFF;
    client_hello[extensions_length_offset + 1] = extensions_length & 0xFF;

    // 填充握手消息长度
    uint32_t handshake_length = offset - handshake_start;
    write_uint24(client_hello + 1, handshake_length);

    // 记录握手消息
    record_handshake_message(session, client_hello, offset);

    // 发送 ClientHello
    printf("[TLS] Sending ClientHello...\n");
    return tls_send_record(session, TLS_CONTENT_HANDSHAKE, client_hello, offset);
}

// ============================================================================
// ServerHello
// ============================================================================

int tls_receive_server_hello(tls_session_t *session) {
    uint8_t buffer[4096];
    uint8_t content_type;

    printf("[TLS] Waiting for ServerHello...\n");
    int len = tls_receive_record(session, &content_type, buffer, sizeof(buffer));
    if (len < 0) {
        fprintf(stderr, "Failed to receive ServerHello\n");
        return -1;
    }

    if (content_type != TLS_CONTENT_HANDSHAKE) {
        fprintf(stderr, "Expected handshake message, got type %d\n", content_type);
        return -1;
    }

    // 解析握手消息
    size_t offset = 0;
    while (offset < (size_t)len) {
        uint8_t msg_type = buffer[offset++];
        uint32_t msg_len = read_uint24(buffer + offset);
        offset += 3;

        if (msg_type == TLS_HANDSHAKE_SERVER_HELLO) {
            printf("[TLS] Received ServerHello\n");

            // 记录握手消息
            record_handshake_message(session, buffer + offset - 4, msg_len + 4);

            // 解析 ServerHello
            // uint16_t version = (buffer[offset] << 8) | buffer[offset + 1];  // 未使用
            offset += 2;

            // 服务器随机数
            memcpy(session->server_random, buffer + offset, 32);
            offset += 32;

            // Session ID
            uint8_t session_id_len = buffer[offset++];
            offset += session_id_len;

            // 加密套件
            uint16_t cipher_suite = (buffer[offset] << 8) | buffer[offset + 1];
            offset += 2;

            printf("[TLS] Selected cipher suite: 0x%04x\n", cipher_suite);

            // 压缩方法
            offset++;

            // 扩展 (如果有)
            if (offset < (size_t)len) {
                uint16_t ext_len = (buffer[offset] << 8) | buffer[offset + 1];
                offset += 2 + ext_len;
            }

            return 0;
        } else {
            // 跳过其他消息
            offset += msg_len;
        }
    }

    fprintf(stderr, "ServerHello not found\n");
    return -1;
}

// ============================================================================
// Certificate
// ============================================================================

int tls_receive_certificate(tls_session_t *session) {
    uint8_t buffer[8192];
    uint8_t content_type;

    printf("[TLS] Waiting for Certificate...\n");
    int len = tls_receive_record(session, &content_type, buffer, sizeof(buffer));
    if (len < 0) {
        return -1;
    }

    size_t offset = 0;
    uint8_t msg_type = buffer[offset++];
    uint32_t msg_len = read_uint24(buffer + offset);
    offset += 3;

    if (msg_type != TLS_HANDSHAKE_CERTIFICATE) {
        fprintf(stderr, "Expected Certificate message\n");
        return -1;
    }

    printf("[TLS] Received Certificate\n");

    // 记录握手消息
    record_handshake_message(session, buffer, msg_len + 4);

    // 注意：这里我们跳过证书验证（简化实现）
    // 生产环境必须验证证书链和签名

    return 0;
}

// ============================================================================
// ServerKeyExchange
// ============================================================================

int tls_receive_server_key_exchange(tls_session_t *session, uint8_t *server_public_key) {
    uint8_t buffer[4096];
    uint8_t content_type;

    printf("[TLS] Waiting for ServerKeyExchange...\n");
    int len = tls_receive_record(session, &content_type, buffer, sizeof(buffer));
    if (len < 0) {
        return -1;
    }

    size_t offset = 0;
    uint8_t msg_type = buffer[offset++];
    uint32_t msg_len = read_uint24(buffer + offset);
    offset += 3;

    if (msg_type != TLS_HANDSHAKE_SERVER_KEY_EXCHANGE) {
        fprintf(stderr, "Expected ServerKeyExchange message\n");
        return -1;
    }

    printf("[TLS] Received ServerKeyExchange\n");

    // 记录握手消息
    record_handshake_message(session, buffer, msg_len + 4);

    // 解析 ECDHE 参数
    // 注意：这是简化实现，实际需要解析完整的 ECDHE 参数和签名
    // uint8_t curve_type = buffer[offset++];  // 未使用
    offset++;  // 跳过 curve_type
    // uint16_t named_curve = (buffer[offset] << 8) | buffer[offset + 1];  // 未使用
    offset += 2;  // 跳过 named_curve
    uint8_t pubkey_len = buffer[offset++];

    if (pubkey_len > 65) {
        fprintf(stderr, "Invalid public key length\n");
        return -1;
    }

    memcpy(server_public_key, buffer + offset, pubkey_len);

    printf("[TLS] Extracted server public key (%d bytes)\n", pubkey_len);

    return pubkey_len;
}

// ============================================================================
// ServerHelloDone
// ============================================================================

int tls_receive_server_hello_done(tls_session_t *session) {
    uint8_t buffer[4096];
    uint8_t content_type;

    printf("[TLS] Waiting for ServerHelloDone...\n");
    int len = tls_receive_record(session, &content_type, buffer, sizeof(buffer));
    if (len < 0) {
        return -1;
    }

    size_t offset = 0;
    uint8_t msg_type = buffer[offset++];
    uint32_t msg_len = read_uint24(buffer + offset);
    offset += 3;

    if (msg_type != TLS_HANDSHAKE_SERVER_HELLO_DONE) {
        fprintf(stderr, "Expected ServerHelloDone message\n");
        return -1;
    }

    printf("[TLS] Received ServerHelloDone\n");

    // 记录握手消息
    record_handshake_message(session, buffer, msg_len + 4);

    return 0;
}

// ============================================================================
// ClientKeyExchange
// ============================================================================

int tls_send_client_key_exchange(tls_session_t *session, const uint8_t *client_public_key) {
    uint8_t message[256];
    size_t offset = 0;

    // 握手消息头
    message[offset++] = TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE;
    offset += 3;  // 长度稍后填充

    size_t handshake_start = offset;

    // ECDHE 公钥长度
    message[offset++] = 65;  // 未压缩点 (1 + 32 + 32)

    // ECDHE 公钥
    memcpy(message + offset, client_public_key, 65);
    offset += 65;

    // 填充握手消息长度
    uint32_t handshake_length = offset - handshake_start;
    write_uint24(message + 1, handshake_length);

    // 记录握手消息
    record_handshake_message(session, message, offset);

    printf("[TLS] Sending ClientKeyExchange...\n");
    return tls_send_record(session, TLS_CONTENT_HANDSHAKE, message, offset);
}

// ============================================================================
// ChangeCipherSpec
// ============================================================================

int tls_send_change_cipher_spec(tls_session_t *session) {
    uint8_t message[1] = {1};

    printf("[TLS] Sending ChangeCipherSpec...\n");
    int ret = tls_send_record(session, TLS_CONTENT_CHANGE_CIPHER_SPEC, message, 1);

    // 启用加密
    session->encryption_enabled = 1;
    session->client_seq_num = 0;

    return ret;
}

// ============================================================================
// Finished
// ============================================================================

void tls_compute_verify_data(tls_session_t *session, const char *label, uint8_t output[12]) {
    // verify_data = PRF(master_secret, label, Hash(handshake_messages))[0..11]
    uint8_t handshake_hash[32];
    sha256(session->handshake_messages, session->handshake_messages_len, handshake_hash);

    printf("[DEBUG] Computing verify_data for '%s'\n", label);
    printf("[DEBUG] Handshake messages length: %zu bytes\n", session->handshake_messages_len);
    print_hex("[DEBUG] Handshake hash", handshake_hash, 32);

    tls_prf_sha256(session->master_secret, 48, label, handshake_hash, 32, output, 12);
    print_hex("[DEBUG] Verify data", output, 12);
}

int tls_send_finished(tls_session_t *session) {
    uint8_t message[64];
    size_t offset = 0;

    // 握手消息头
    message[offset++] = TLS_HANDSHAKE_FINISHED;
    write_uint24(message + offset, 12);
    offset += 3;

    // 计算 verify_data
    tls_compute_verify_data(session, "client finished", message + offset);
    offset += 12;

    // 注意：Finished 消息需要在记录之前发送，因为它本身不包含在哈希中
    uint8_t finished_copy[16];
    memcpy(finished_copy, message, 16);

    printf("[TLS] Sending Finished...\n");
    int ret = tls_send_record(session, TLS_CONTENT_HANDSHAKE, message, offset);

    // 记录 Finished 消息（用于后续验证）
    record_handshake_message(session, finished_copy, 16);

    return ret;
}

int tls_receive_finished(tls_session_t *session) {
    uint8_t buffer[4096];
    uint8_t content_type;

    // 首先接收 ChangeCipherSpec
    printf("[TLS] Waiting for server ChangeCipherSpec...\n");
    int len = tls_receive_record(session, &content_type, buffer, sizeof(buffer));
    if (len < 0) {
        fprintf(stderr, "Failed to receive record (len=%d)\n", len);
        return -1;
    }
    if (content_type != TLS_CONTENT_CHANGE_CIPHER_SPEC) {
        fprintf(stderr, "Expected ChangeCipherSpec (0x14), got content_type=0x%02x, len=%d\n",
                content_type, len);
        if (content_type == TLS_CONTENT_ALERT && len >= 2) {
            fprintf(stderr, "Alert: level=%d, description=%d\n", buffer[0], buffer[1]);
        }
        return -1;
    }

    // 启用解密
    session->server_seq_num = 0;

    // 接收 Finished
    printf("[TLS] Waiting for server Finished...\n");
    len = tls_receive_record(session, &content_type, buffer, sizeof(buffer));
    if (len < 0) {
        return -1;
    }

    uint8_t msg_type = buffer[0];
    // uint32_t msg_len = read_uint24(buffer + 1);  // 未使用

    if (msg_type != TLS_HANDSHAKE_FINISHED) {
        fprintf(stderr, "Expected Finished message\n");
        return -1;
    }

    // 验证 verify_data
    uint8_t expected_verify_data[12];
    tls_compute_verify_data(session, "server finished", expected_verify_data);

    if (memcmp(buffer + 4, expected_verify_data, 12) != 0) {
        fprintf(stderr, "Finished verification failed\n");
        return -1;
    }

    printf("[TLS] Server Finished verified successfully\n");

    // 记录服务器的 Finished 消息
    record_handshake_message(session, buffer, 16);

    return 0;
}

// ============================================================================
// 密钥派生
// ============================================================================

void tls_derive_master_secret(const uint8_t *pre_master_secret, size_t secret_len, tls_session_t *session) {
    // master_secret = PRF(pre_master_secret, "master secret",
    //                     ClientHello.random + ServerHello.random)[0..47]
    uint8_t seed[64];
    memcpy(seed, session->client_random, 32);
    memcpy(seed + 32, session->server_random, 32);

    tls_prf_sha256(pre_master_secret, secret_len, "master secret", seed, 64,
                   session->master_secret, 48);

    printf("[TLS] Master secret derived\n");
}

void tls_derive_keys(tls_session_t *session) {
    // key_block = PRF(master_secret, "key expansion",
    //                 ServerHello.random + ClientHello.random)
    uint8_t seed[64];
    memcpy(seed, session->server_random, 32);
    memcpy(seed + 32, session->client_random, 32);

    // 需要的密钥材料：
    // client_write_MAC_key (0 for GCM)
    // server_write_MAC_key (0 for GCM)
    // client_write_key (16 bytes)
    // server_write_key (16 bytes)
    // client_write_IV (4 bytes for GCM)
    // server_write_IV (4 bytes for GCM)
    uint8_t key_block[40];
    tls_prf_sha256(session->master_secret, 48, "key expansion", seed, 64, key_block, 40);

    memcpy(session->client_write_key, key_block, 16);
    memcpy(session->server_write_key, key_block + 16, 16);
    memcpy(session->client_write_iv, key_block + 32, 4);
    memcpy(session->server_write_iv, key_block + 36, 4);

    printf("[TLS] Session keys derived\n");
    print_hex("Client write key", session->client_write_key, 16);
    print_hex("Server write key", session->server_write_key, 16);
}

// ============================================================================
// 完整握手流程
// ============================================================================

// 注意：这是一个简化的实现，使用固定的预主密钥
// 实际实现需要使用 ECDHE 进行密钥交换
int tls_handshake(tls_session_t *session, const char *hostname) {
    printf("\n========== TLS Handshake Start ==========\n\n");

    // 1. 发送 ClientHello
    if (tls_send_client_hello(session, hostname) < 0) {
        return -1;
    }

    // 2. 接收 ServerHello
    if (tls_receive_server_hello(session) < 0) {
        return -1;
    }

    // 3. 接收 Certificate
    if (tls_receive_certificate(session) < 0) {
        return -1;
    }

    // 4. 接收 ServerKeyExchange
    uint8_t server_public_key[65];
    int server_key_len = tls_receive_server_key_exchange(session, server_public_key);
    if (server_key_len < 0) {
        return -1;
    }

    // 5. 接收 ServerHelloDone
    if (tls_receive_server_hello_done(session) < 0) {
        return -1;
    }

    // 6. 使用 ECDHE 计算共享密钥
    uint8_t client_public_key[65];
    uint8_t shared_secret[32];

    printf("[TLS] Computing ECDHE shared secret...\n");
    if (ecdhe_compute_shared_secret(server_public_key, shared_secret, client_public_key) < 0) {
        fprintf(stderr, "Failed to compute ECDHE shared secret\n");
        return -1;
    }

    // 7. 派生主密钥
    // 在 ECDHE 中，预主密钥就是共享密钥（32 字节）
    tls_derive_master_secret(shared_secret, 32, session);

    // 8. 派生会话密钥
    tls_derive_keys(session);

    // 9. 发送 ClientKeyExchange
    if (tls_send_client_key_exchange(session, client_public_key) < 0) {
        return -1;
    }

    // 10. 发送 ChangeCipherSpec
    if (tls_send_change_cipher_spec(session) < 0) {
        return -1;
    }

    // 11. 发送 Finished
    if (tls_send_finished(session) < 0) {
        return -1;
    }

    // 12. 接收服务器的 ChangeCipherSpec 和 Finished
    if (tls_receive_finished(session) < 0) {
        return -1;
    }

    printf("\n========== TLS Handshake Complete ==========\n\n");
    printf("[TLS] Secure connection established!\n\n");

    return 0;
}

