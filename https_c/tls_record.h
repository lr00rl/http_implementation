// tls_record.h - TLS 记录层协议
#ifndef TLS_RECORD_H
#define TLS_RECORD_H

#include "tls_types.h"

// ============================================================================
// TLS 记录层函数
// ============================================================================

// 发送 TLS 记录
// session: TLS 会话
// content_type: 内容类型
// data: 要发送的数据
// data_len: 数据长度
// 返回发送的字节数，失败返回 -1
int tls_send_record(tls_session_t *session, uint8_t content_type,
                    const uint8_t *data, size_t data_len);

// 接收 TLS 记录
// session: TLS 会话
// content_type: 期望的内容类型 (如果为 0 则接受任何类型)
// buffer: 接收缓冲区
// buffer_size: 缓冲区大小
// 返回接收的数据长度，失败返回 -1
int tls_receive_record(tls_session_t *session, uint8_t *content_type,
                       uint8_t *buffer, size_t buffer_size);

// 发送加密的应用数据
int tls_send_application_data(tls_session_t *session,
                               const uint8_t *data, size_t data_len);

// 接收加密的应用数据
int tls_receive_application_data(tls_session_t *session,
                                  uint8_t *buffer, size_t buffer_size);

#endif // TLS_RECORD_H

