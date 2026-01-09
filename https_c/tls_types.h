// tls_types.h - TLS 协议类型定义
#ifndef TLS_TYPES_H
#define TLS_TYPES_H

#include <stdint.h>
#include <stddef.h>

// ============================================================================
// TLS 协议常量定义
// ============================================================================

// TLS 版本号
#define TLS_VERSION_1_2     0x0303  // TLS 1.2
#define TLS_VERSION_1_3     0x0304  // TLS 1.3

// TLS 内容类型 (Content Type)
typedef enum {
    TLS_CONTENT_CHANGE_CIPHER_SPEC = 20,  // 更改加密规范
    TLS_CONTENT_ALERT = 21,                // 警告消息
    TLS_CONTENT_HANDSHAKE = 22,            // 握手消息
    TLS_CONTENT_APPLICATION_DATA = 23      // 应用数据
} tls_content_type_t;

// TLS 握手消息类型 (Handshake Type)
typedef enum {
    TLS_HANDSHAKE_HELLO_REQUEST = 0,       // 请求新握手
    TLS_HANDSHAKE_CLIENT_HELLO = 1,        // 客户端问候
    TLS_HANDSHAKE_SERVER_HELLO = 2,        // 服务器问候
    TLS_HANDSHAKE_CERTIFICATE = 11,        // 证书
    TLS_HANDSHAKE_SERVER_KEY_EXCHANGE = 12,// 服务器密钥交换
    TLS_HANDSHAKE_CERTIFICATE_REQUEST = 13,// 证书请求
    TLS_HANDSHAKE_SERVER_HELLO_DONE = 14,  // 服务器问候完成
    TLS_HANDSHAKE_CERTIFICATE_VERIFY = 15, // 证书验证
    TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE = 16,// 客户端密钥交换
    TLS_HANDSHAKE_FINISHED = 20            // 握手完成
} tls_handshake_type_t;

// TLS 加密套件 (Cipher Suite)
// 我们将实现 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  0xC02F

// 椭圆曲线类型
#define TLS_EC_CURVE_SECP256R1  23  // 也称为 P-256 或 prime256v1

// TLS 扩展类型
#define TLS_EXT_SERVER_NAME              0
#define TLS_EXT_SUPPORTED_GROUPS         10
#define TLS_EXT_EC_POINT_FORMATS         11
#define TLS_EXT_SIGNATURE_ALGORITHMS     13
#define TLS_EXT_ENCRYPT_THEN_MAC         22
#define TLS_EXT_EXTENDED_MASTER_SECRET   23

// ============================================================================
// TLS 记录层结构 (Record Layer)
// ============================================================================

// TLS 记录头 (5 字节)
typedef struct {
    uint8_t content_type;    // 内容类型
    uint16_t version;        // 协议版本
    uint16_t length;         // 数据长度
} __attribute__((packed)) tls_record_header_t;

// TLS 记录
typedef struct {
    tls_record_header_t header;
    uint8_t *data;           // 记录数据
} tls_record_t;

// ============================================================================
// TLS 握手层结构 (Handshake Layer)
// ============================================================================

// TLS 握手消息头 (4 字节)
typedef struct {
    uint8_t msg_type;        // 握手消息类型
    uint8_t length[3];       // 消息长度 (24-bit, 大端序)
} __attribute__((packed)) tls_handshake_header_t;

// ClientHello 消息
typedef struct {
    uint16_t version;                    // 客户端支持的最高 TLS 版本
    uint8_t random[32];                  // 32 字节随机数
    uint8_t session_id_length;           // 会话 ID 长度
    uint8_t *session_id;                 // 会话 ID
    uint16_t cipher_suites_length;       // 加密套件列表长度
    uint16_t *cipher_suites;             // 加密套件列表
    uint8_t compression_methods_length;  // 压缩方法长度
    uint8_t *compression_methods;        // 压缩方法
    uint16_t extensions_length;          // 扩展长度
    uint8_t *extensions;                 // 扩展数据
} tls_client_hello_t;

// ServerHello 消息
typedef struct {
    uint16_t version;                    // 服务器选择的 TLS 版本
    uint8_t random[32];                  // 32 字节随机数
    uint8_t session_id_length;           // 会话 ID 长度
    uint8_t *session_id;                 // 会话 ID
    uint16_t cipher_suite;               // 选择的加密套件
    uint8_t compression_method;          // 选择的压缩方法
    uint16_t extensions_length;          // 扩展长度
    uint8_t *extensions;                 // 扩展数据
} tls_server_hello_t;

// ============================================================================
// TLS 会话状态
// ============================================================================

typedef struct {
    // 连接信息
    int socket_fd;

    // 握手状态
    uint8_t client_random[32];      // 客户端随机数
    uint8_t server_random[32];      // 服务器随机数
    uint8_t master_secret[48];      // 主密钥 (48 字节)

    // 密钥材料
    uint8_t client_write_key[16];   // 客户端写密钥 (AES-128)
    uint8_t server_write_key[16];   // 服务器写密钥 (AES-128)
    uint8_t client_write_iv[4];     // 客户端写 IV (GCM 固定部分)
    uint8_t server_write_iv[4];     // 服务器写 IV (GCM 固定部分)

    // 序列号 (用于 GCM nonce)
    uint64_t client_seq_num;        // 客户端序列号
    uint64_t server_seq_num;        // 服务器序列号

    // 加密状态
    int encryption_enabled;         // 是否启用加密

    // 握手消息缓冲 (用于计算 Finished 消息)
    uint8_t handshake_messages[8192];
    size_t handshake_messages_len;

} tls_session_t;

// ============================================================================
// 函数声明
// ============================================================================

// 初始化 TLS 会话
void tls_session_init(tls_session_t *session, int socket_fd);

// 清理 TLS 会话
void tls_session_cleanup(tls_session_t *session);

#endif // TLS_TYPES_H

