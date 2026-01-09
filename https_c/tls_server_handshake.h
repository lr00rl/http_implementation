// tls_server_handshake.h - TLS 服务器端握手协议
#ifndef TLS_SERVER_HANDSHAKE_H
#define TLS_SERVER_HANDSHAKE_H

#include "tls_types.h"
#include "tls_crypto.h"

// ============================================================================
// 服务器证书结构（简化的教学实现）
// ============================================================================

typedef struct {
    uint8_t *cert_data;      // DER 编码的证书数据
    size_t cert_len;         // 证书长度
    uint8_t *private_key;    // 私钥数据（简化实现）
    size_t private_key_len;  // 私钥长度
} tls_server_certificate_t;

// ============================================================================
// TLS 服务器握手函数
// ============================================================================

// 执行完整的 TLS 服务器握手
// session: TLS 会话
// cert: 服务器证书（可以为 NULL，将使用内置的自签名证书）
// 返回 0 表示成功，-1 表示失败
int tls_server_handshake(tls_session_t *session, tls_server_certificate_t *cert);

// 接收并解析 ClientHello 消息
int tls_receive_client_hello(tls_session_t *session);

// 发送 ServerHello 消息
int tls_send_server_hello(tls_session_t *session);

// 发送 Certificate 消息
int tls_send_certificate(tls_session_t *session, tls_server_certificate_t *cert);

// 发送 ServerKeyExchange 消息
int tls_send_server_key_exchange(tls_session_t *session, const uint8_t *server_public_key);

// 发送 ServerHelloDone 消息
int tls_send_server_hello_done(tls_session_t *session);

// 接收并解析 ClientKeyExchange 消息
int tls_receive_client_key_exchange(tls_session_t *session, uint8_t *client_public_key);

// 接收 ChangeCipherSpec 消息
int tls_receive_change_cipher_spec(tls_session_t *session);

// 接收并验证客户端的 Finished 消息
int tls_receive_client_finished(tls_session_t *session);

// 发送服务器的 ChangeCipherSpec 消息
int tls_send_server_change_cipher_spec(tls_session_t *session);

// 发送服务器的 Finished 消息
int tls_send_server_finished(tls_session_t *session);

// ============================================================================
// 证书辅助函数
// ============================================================================

// 生成自签名证书（教学用途）
// 返回证书结构，使用完毕后需要调用 tls_free_certificate 释放
tls_server_certificate_t* tls_generate_self_signed_certificate(void);

// 释放证书资源
void tls_free_certificate(tls_server_certificate_t *cert);

#endif // TLS_SERVER_HANDSHAKE_H

