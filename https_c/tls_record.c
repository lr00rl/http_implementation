// tls_record.c - TLS 记录层协议实现
#include "tls_record.h"
#include "tls_crypto.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>

// ============================================================================
// TLS 记录层实现
// ============================================================================

// 发送原始数据到套接字
static int send_all(int fd, const uint8_t *data, size_t len) {
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = write(fd, data + total_sent, len - total_sent);
        if (sent <= 0) {
            perror("write");
            return -1;
        }
        total_sent += sent;
    }
    return total_sent;
}

// 接收指定长度的数据
static int recv_all(int fd, uint8_t *buffer, size_t len) {
    size_t total_received = 0;
    while (total_received < len) {
        ssize_t received = read(fd, buffer + total_received, len - total_received);
        if (received <= 0) {
            if (received == 0) {
                fprintf(stderr, "Connection closed by peer\n");
            } else {
                perror("read");
            }
            return -1;
        }
        total_received += received;
    }
    return total_received;
}

int tls_send_record(tls_session_t *session, uint8_t content_type,
                    const uint8_t *data, size_t data_len) {
    uint8_t *record_data;
    size_t record_len;

    if (session->encryption_enabled && content_type == TLS_CONTENT_APPLICATION_DATA) {
        // 加密模式：使用 AES-128-GCM
        // GCM nonce = client_write_iv (4 字节) || 序列号 (8 字节)
        uint8_t nonce[12];
        memcpy(nonce, session->client_write_iv, 4);
        uint64_t seq = session->client_seq_num;
        int i;
        for (i = 0; i < 8; i++) {
            nonce[4 + i] = (seq >> (56 - i * 8)) & 0xFF;
        }

        // AAD (Additional Authenticated Data) = seq_num || TLS 记录头 (不含长度)
        uint8_t aad[13];
        for (i = 0; i < 8; i++) {
            aad[i] = (session->client_seq_num >> (56 - i * 8)) & 0xFF;
        }
        aad[8] = content_type;
        aad[9] = (TLS_VERSION_1_2 >> 8) & 0xFF;
        aad[10] = TLS_VERSION_1_2 & 0xFF;
        aad[11] = (data_len >> 8) & 0xFF;
        aad[12] = data_len & 0xFF;

        // 加密数据
        uint8_t *ciphertext = malloc(data_len);
        uint8_t tag[16];

        aes128_gcm_ctx_t gcm_ctx;
        aes128_gcm_init(&gcm_ctx, session->client_write_key);
        aes128_gcm_encrypt(&gcm_ctx, nonce, aad, 13, data, data_len, ciphertext, tag);

        // TLS 记录 = 显式 nonce (8 字节) || 密文 || 标签 (16 字节)
        record_len = 8 + data_len + 16;
        record_data = malloc(record_len);
        memcpy(record_data, nonce + 4, 8);  // 显式 nonce (序列号部分)
        memcpy(record_data + 8, ciphertext, data_len);
        memcpy(record_data + 8 + data_len, tag, 16);

        free(ciphertext);
        session->client_seq_num++;
    } else {
        // 明文模式
        record_len = data_len;
        record_data = malloc(record_len);
        memcpy(record_data, data, data_len);
    }

    // 构造 TLS 记录头
    uint8_t header[5];
    header[0] = content_type;
    header[1] = (TLS_VERSION_1_2 >> 8) & 0xFF;
    header[2] = TLS_VERSION_1_2 & 0xFF;
    header[3] = (record_len >> 8) & 0xFF;
    header[4] = record_len & 0xFF;

    // 发送记录头和数据
    if (send_all(session->socket_fd, header, 5) < 0) {
        free(record_data);
        return -1;
    }
    if (send_all(session->socket_fd, record_data, record_len) < 0) {
        free(record_data);
        return -1;
    }

    free(record_data);
    return record_len + 5;
}

int tls_receive_record(tls_session_t *session, uint8_t *content_type,
                       uint8_t *buffer, size_t buffer_size) {
    uint8_t header[5];

    // 接收记录头
    if (recv_all(session->socket_fd, header, 5) < 0) {
        return -1;
    }

    *content_type = header[0];
    // uint16_t version = (header[1] << 8) | header[2];  // 未使用
    uint16_t length = (header[3] << 8) | header[4];

    if (length > 16384 + 2048) {  // TLS 最大记录长度 + GCM 开销
        fprintf(stderr, "Record too large: %u bytes\n", length);
        return -1;
    }

    // 接收记录数据
    uint8_t *record_data = malloc(length);
    if (recv_all(session->socket_fd, record_data, length) < 0) {
        free(record_data);
        return -1;
    }

    size_t plaintext_len;

    if (session->encryption_enabled && *content_type == TLS_CONTENT_APPLICATION_DATA) {
        // 解密模式
        if (length < 24) {  // 至少需要 8 字节 nonce + 16 字节 tag
            fprintf(stderr, "Encrypted record too short\n");
            free(record_data);
            return -1;
        }

        // 提取显式 nonce
        uint8_t nonce[12];
        memcpy(nonce, session->server_write_iv, 4);
        memcpy(nonce + 4, record_data, 8);

        // 密文长度 = 总长度 - 显式 nonce (8) - 标签 (16)
        size_t ciphertext_len = length - 8 - 16;
        uint8_t *ciphertext = record_data + 8;
        uint8_t *tag = record_data + 8 + ciphertext_len;

        // 构造 AAD
        uint8_t aad[13];
        int i;
        for (i = 0; i < 8; i++) {
            aad[i] = (session->server_seq_num >> (56 - i * 8)) & 0xFF;
        }
        aad[8] = *content_type;
        aad[9] = (TLS_VERSION_1_2 >> 8) & 0xFF;
        aad[10] = TLS_VERSION_1_2 & 0xFF;
        aad[11] = (ciphertext_len >> 8) & 0xFF;
        aad[12] = ciphertext_len & 0xFF;

        // 解密
        aes128_gcm_ctx_t gcm_ctx;
        aes128_gcm_init(&gcm_ctx, session->server_write_key);

        if (ciphertext_len > buffer_size) {
            fprintf(stderr, "Buffer too small for plaintext\n");
            free(record_data);
            return -1;
        }

        if (aes128_gcm_decrypt(&gcm_ctx, nonce, aad, 13, ciphertext, ciphertext_len,
                               tag, buffer) < 0) {
            fprintf(stderr, "GCM authentication failed\n");
            free(record_data);
            return -1;
        }

        plaintext_len = ciphertext_len;
        session->server_seq_num++;
    } else {
        // 明文模式
        if (length > buffer_size) {
            fprintf(stderr, "Buffer too small for record\n");
            free(record_data);
            return -1;
        }
        memcpy(buffer, record_data, length);
        plaintext_len = length;
    }

    free(record_data);
    return plaintext_len;
}

int tls_send_application_data(tls_session_t *session,
                               const uint8_t *data, size_t data_len) {
    return tls_send_record(session, TLS_CONTENT_APPLICATION_DATA, data, data_len);
}

int tls_receive_application_data(tls_session_t *session,
                                  uint8_t *buffer, size_t buffer_size) {
    uint8_t content_type;
    return tls_receive_record(session, &content_type, buffer, buffer_size);
}

