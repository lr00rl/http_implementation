// tls_crypto.h - TLS 加密算法实现
#ifndef TLS_CRYPTO_H
#define TLS_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// ============================================================================
// SHA-256 实现
// ============================================================================

typedef struct {
    uint32_t state[8];      // 当前哈希状态
    uint64_t count;         // 处理的位数
    uint8_t buffer[64];     // 输入缓冲区
} sha256_ctx_t;

// 初始化 SHA-256 上下文
void sha256_init(sha256_ctx_t *ctx);

// 更新 SHA-256 (添加数据)
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);

// 完成 SHA-256 计算并输出结果
void sha256_final(sha256_ctx_t *ctx, uint8_t output[32]);

// 一次性计算 SHA-256
void sha256(const uint8_t *data, size_t len, uint8_t output[32]);

// ============================================================================
// HMAC-SHA256 实现
// ============================================================================

// HMAC-SHA256 计算
// key: 密钥
// key_len: 密钥长度
// data: 要认证的数据
// data_len: 数据长度
// output: 输出缓冲区 (32 字节)
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t output[32]);

// ============================================================================
// PRF (Pseudo-Random Function) - TLS 1.2 使用
// ============================================================================

// TLS 1.2 PRF 函数
// secret: 密钥材料
// secret_len: 密钥长度
// label: 标签字符串
// seed: 种子数据
// seed_len: 种子长度
// output: 输出缓冲区
// output_len: 需要的输出长度
void tls_prf_sha256(const uint8_t *secret, size_t secret_len,
                    const char *label,
                    const uint8_t *seed, size_t seed_len,
                    uint8_t *output, size_t output_len);

// ============================================================================
// AES-128 实现
// ============================================================================

typedef struct {
    uint32_t round_keys[44];  // 扩展密钥 (11 轮，每轮 4 个 32-bit 字)
} aes128_ctx_t;

// 初始化 AES-128 上下文
void aes128_init(aes128_ctx_t *ctx, const uint8_t key[16]);

// AES-128 加密一个块 (16 字节)
void aes128_encrypt_block(aes128_ctx_t *ctx, const uint8_t input[16], uint8_t output[16]);

// AES-128 解密一个块 (16 字节)
void aes128_decrypt_block(aes128_ctx_t *ctx, const uint8_t input[16], uint8_t output[16]);

// ============================================================================
// AES-128-GCM 实现
// ============================================================================

// GCM (Galois/Counter Mode) 是一种认证加密模式
// 它同时提供加密和消息认证

typedef struct {
    aes128_ctx_t aes_ctx;
    uint8_t h[16];           // GCM 的 H 值 (加密全零块得到)
} aes128_gcm_ctx_t;

// 初始化 AES-128-GCM 上下文
void aes128_gcm_init(aes128_gcm_ctx_t *ctx, const uint8_t key[16]);

// AES-128-GCM 加密
// ctx: GCM 上下文
// nonce: 随机数 (12 字节)
// aad: 附加认证数据
// aad_len: 附加认证数据长度
// plaintext: 明文
// plaintext_len: 明文长度
// ciphertext: 密文输出 (与明文等长)
// tag: 认证标签输出 (16 字节)
void aes128_gcm_encrypt(aes128_gcm_ctx_t *ctx,
                        const uint8_t nonce[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext,
                        uint8_t tag[16]);

// AES-128-GCM 解密
// 返回 0 表示成功，-1 表示认证失败
int aes128_gcm_decrypt(aes128_gcm_ctx_t *ctx,
                       const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t tag[16],
                       uint8_t *plaintext);

// ============================================================================
// 随机数生成
// ============================================================================

// 生成随机字节
void tls_random_bytes(uint8_t *output, size_t len);

// ============================================================================
// 辅助函数
// ============================================================================

// 打印十六进制数据 (用于调试)
void print_hex(const char *label, const uint8_t *data, size_t len);

#endif // TLS_CRYPTO_H

