// tls_handshake.h - TLS 握手协议
#ifndef TLS_HANDSHAKE_H
#define TLS_HANDSHAKE_H

#include "tls_types.h"
#include "tls_crypto.h"

// ============================================================================
// TLS 握手函数
// ============================================================================

// 执行完整的 TLS 握手
// session: TLS 会话
// hostname: 服务器主机名 (用于 SNI)
// 返回 0 表示成功，-1 表示失败
int tls_handshake(tls_session_t *session, const char *hostname);

// 发送 ClientHello 消息
int tls_send_client_hello(tls_session_t *session, const char *hostname);

// 接收并解析 ServerHello 消息
int tls_receive_server_hello(tls_session_t *session);

// 接收并解析 Certificate 消息
int tls_receive_certificate(tls_session_t *session);

// 接收并解析 ServerKeyExchange 消息
int tls_receive_server_key_exchange(tls_session_t *session, uint8_t *server_public_key);

// 接收并解析 ServerHelloDone 消息
int tls_receive_server_hello_done(tls_session_t *session);

// 发送 ClientKeyExchange 消息
int tls_send_client_key_exchange(tls_session_t *session, const uint8_t *client_public_key);

// 发送 ChangeCipherSpec 消息
int tls_send_change_cipher_spec(tls_session_t *session);

// 发送 Finished 消息
int tls_send_finished(tls_session_t *session);

// 接收并验证服务器的 Finished 消息
int tls_receive_finished(tls_session_t *session);

// ============================================================================
// 密钥派生函数
// ============================================================================

// 从预主密钥派生主密钥
// pre_master_secret: 预主密钥
// secret_len: 预主密钥长度 (RSA: 48字节, ECDHE: 32字节)
// session: TLS 会话
void tls_derive_master_secret(const uint8_t *pre_master_secret, size_t secret_len, tls_session_t *session);

// 从主密钥派生密钥材料
void tls_derive_keys(tls_session_t *session);

// 计算 Finished 消息的 verify_data
void tls_compute_verify_data(tls_session_t *session, const char *label, uint8_t output[12]);

#endif // TLS_HANDSHAKE_H

