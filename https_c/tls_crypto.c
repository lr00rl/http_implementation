// tls_crypto.c - TLS 加密算法实现
#include "tls_crypto.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

// ============================================================================
// SHA-256 实现
// 参考: FIPS 180-4 (Secure Hash Standard)
// ============================================================================

// SHA-256 常量 K (前 64 个素数的立方根的小数部分)
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// 位操作宏
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n) ((x) >> (n))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

// SHA-256 转换函数 (处理一个 512-bit 块)
static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    int i;

    // 准备消息调度 (Message Schedule)
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }

    // 初始化工作变量
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    // 主循环 (64 轮)
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // 更新状态
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(sha256_ctx_t *ctx) {
    // SHA-256 初始哈希值 (前 8 个素数的平方根的小数部分)
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t i;
    size_t index = (ctx->count / 8) % 64;

    ctx->count += len * 8;

    for (i = 0; i < len; i++) {
        ctx->buffer[index++] = data[i];
        if (index == 64) {
            sha256_transform(ctx, ctx->buffer);
            index = 0;
        }
    }
}

void sha256_final(sha256_ctx_t *ctx, uint8_t output[32]) {
    size_t index = (ctx->count / 8) % 64;
    size_t padlen = (index < 56) ? (56 - index) : (120 - index);
    uint8_t padding[64];
    int i;

    // 填充: 1 bit '1' 后跟若干 '0'
    padding[0] = 0x80;
    for (i = 1; i < (int)padlen; i++) {
        padding[i] = 0x00;
    }
    sha256_update(ctx, padding, padlen);

    // 添加长度 (64-bit 大端序)
    for (i = 0; i < 8; i++) {
        padding[i] = (ctx->count >> (56 - i * 8)) & 0xFF;
    }
    sha256_update(ctx, padding, 8);

    // 输出哈希值 (大端序)
    for (i = 0; i < 8; i++) {
        output[i * 4] = (ctx->state[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        output[i * 4 + 3] = ctx->state[i] & 0xFF;
    }
}

void sha256(const uint8_t *data, size_t len, uint8_t output[32]) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, output);
}

// ============================================================================
// HMAC-SHA256 实现
// 参考: RFC 2104
// ============================================================================

void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t output[32]) {
    uint8_t k[64];  // 填充后的密钥
    uint8_t ipad[64], opad[64];
    sha256_ctx_t ctx;
    uint8_t inner_hash[32];
    int i;

    // 准备密钥
    memset(k, 0, 64);
    if (key_len > 64) {
        // 如果密钥太长，先哈希
        sha256(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }

    // 准备 ipad 和 opad
    for (i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    // 计算内部哈希: H(K XOR ipad || data)
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_hash);

    // 计算外部哈希: H(K XOR opad || inner_hash)
    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, output);
}

// ============================================================================
// TLS PRF (Pseudo-Random Function) - TLS 1.2
// 参考: RFC 5246 Section 5
// ============================================================================

// P_hash 函数
static void p_hash(const uint8_t *secret, size_t secret_len,
                   const uint8_t *seed, size_t seed_len,
                   uint8_t *output, size_t output_len) {
    uint8_t a[32];  // A(i)
    uint8_t temp[64];
    size_t copied = 0;

    // A(1) = HMAC(secret, seed)
    hmac_sha256(secret, secret_len, seed, seed_len, a);

    while (copied < output_len) {
        // HMAC(secret, A(i) + seed)
        memcpy(temp, a, 32);
        memcpy(temp + 32, seed, seed_len);
        hmac_sha256(secret, secret_len, temp, 32 + seed_len, temp);

        size_t to_copy = (output_len - copied > 32) ? 32 : (output_len - copied);
        memcpy(output + copied, temp, to_copy);
        copied += to_copy;

        // A(i+1) = HMAC(secret, A(i))
        hmac_sha256(secret, secret_len, a, 32, a);
    }
}

void tls_prf_sha256(const uint8_t *secret, size_t secret_len,
                    const char *label,
                    const uint8_t *seed, size_t seed_len,
                    uint8_t *output, size_t output_len) {
    size_t label_len = strlen(label);
    uint8_t *full_seed = malloc(label_len + seed_len);

    memcpy(full_seed, label, label_len);
    memcpy(full_seed + label_len, seed, seed_len);

    p_hash(secret, secret_len, full_seed, label_len + seed_len, output, output_len);

    free(full_seed);
}

// ============================================================================
// AES-128 实现
// 参考: FIPS 197 (Advanced Encryption Standard)
// ============================================================================

// AES S-box
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// AES 逆 S-box
static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Rcon (轮常量)
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// 密钥扩展
void aes128_init(aes128_ctx_t *ctx, const uint8_t key[16]) {
    int i;
    uint32_t temp;

    // 复制原始密钥
    for (i = 0; i < 4; i++) {
        ctx->round_keys[i] = ((uint32_t)key[4 * i] << 24) |
                             ((uint32_t)key[4 * i + 1] << 16) |
                             ((uint32_t)key[4 * i + 2] << 8) |
                             ((uint32_t)key[4 * i + 3]);
    }

    // 生成轮密钥
    for (i = 4; i < 44; i++) {
        temp = ctx->round_keys[i - 1];
        if (i % 4 == 0) {
            // RotWord + SubWord + Rcon
            temp = ((uint32_t)sbox[(temp >> 16) & 0xff] << 24) |
                   ((uint32_t)sbox[(temp >> 8) & 0xff] << 16) |
                   ((uint32_t)sbox[temp & 0xff] << 8) |
                   (((uint32_t)sbox[(temp >> 24) & 0xff]) ^
                   ((uint32_t)rcon[i / 4] << 24));
        }
        ctx->round_keys[i] = ctx->round_keys[i - 4] ^ temp;
    }
}

// SubBytes 变换
static void sub_bytes(uint8_t state[16]) {
    int i;
    for (i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}

// 逆 SubBytes
static void inv_sub_bytes(uint8_t state[16]) {
    int i;
    for (i = 0; i < 16; i++) {
        state[i] = inv_sbox[state[i]];
    }
}

// ShiftRows 变换
static void shift_rows(uint8_t state[16]) {
    uint8_t temp;
    // 第二行左移 1 字节
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    // 第三行左移 2 字节
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    // 第四行左移 3 字节
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}

// 逆 ShiftRows
static void inv_shift_rows(uint8_t state[16]) {
    uint8_t temp;
    // 第二行右移 1 字节
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    // 第三行右移 2 字节
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    // 第四行右移 3 字节
    temp = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3] = temp;
}

// GF(2^8) 乘法
static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    int i;
    for (i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        int hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set) a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

// MixColumns 变换
static void mix_columns(uint8_t state[16]) {
    int i;
    uint8_t temp[4];
    for (i = 0; i < 4; i++) {
        temp[0] = state[i * 4];
        temp[1] = state[i * 4 + 1];
        temp[2] = state[i * 4 + 2];
        temp[3] = state[i * 4 + 3];
        state[i * 4] = gf_mul(temp[0], 2) ^ gf_mul(temp[1], 3) ^ temp[2] ^ temp[3];
        state[i * 4 + 1] = temp[0] ^ gf_mul(temp[1], 2) ^ gf_mul(temp[2], 3) ^ temp[3];
        state[i * 4 + 2] = temp[0] ^ temp[1] ^ gf_mul(temp[2], 2) ^ gf_mul(temp[3], 3);
        state[i * 4 + 3] = gf_mul(temp[0], 3) ^ temp[1] ^ temp[2] ^ gf_mul(temp[3], 2);
    }
}

// 逆 MixColumns
static void inv_mix_columns(uint8_t state[16]) {
    int i;
    uint8_t temp[4];
    for (i = 0; i < 4; i++) {
        temp[0] = state[i * 4];
        temp[1] = state[i * 4 + 1];
        temp[2] = state[i * 4 + 2];
        temp[3] = state[i * 4 + 3];
        state[i * 4] = gf_mul(temp[0], 0x0e) ^ gf_mul(temp[1], 0x0b) ^
                       gf_mul(temp[2], 0x0d) ^ gf_mul(temp[3], 0x09);
        state[i * 4 + 1] = gf_mul(temp[0], 0x09) ^ gf_mul(temp[1], 0x0e) ^
                           gf_mul(temp[2], 0x0b) ^ gf_mul(temp[3], 0x0d);
        state[i * 4 + 2] = gf_mul(temp[0], 0x0d) ^ gf_mul(temp[1], 0x09) ^
                           gf_mul(temp[2], 0x0e) ^ gf_mul(temp[3], 0x0b);
        state[i * 4 + 3] = gf_mul(temp[0], 0x0b) ^ gf_mul(temp[1], 0x0d) ^
                           gf_mul(temp[2], 0x09) ^ gf_mul(temp[3], 0x0e);
    }
}

// AddRoundKey
static void add_round_key(uint8_t state[16], const uint32_t *round_key) {
    int i;
    for (i = 0; i < 4; i++) {
        state[i * 4] ^= (round_key[i] >> 24) & 0xff;
        state[i * 4 + 1] ^= (round_key[i] >> 16) & 0xff;
        state[i * 4 + 2] ^= (round_key[i] >> 8) & 0xff;
        state[i * 4 + 3] ^= round_key[i] & 0xff;
    }
}

void aes128_encrypt_block(aes128_ctx_t *ctx, const uint8_t input[16], uint8_t output[16]) {
    uint8_t state[16];
    int round;

    memcpy(state, input, 16);

    // 初始轮密钥加
    add_round_key(state, &ctx->round_keys[0]);

    // 9 轮主循环
    for (round = 1; round < 10; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &ctx->round_keys[round * 4]);
    }

    // 最后一轮 (无 MixColumns)
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &ctx->round_keys[40]);

    memcpy(output, state, 16);
}

void aes128_decrypt_block(aes128_ctx_t *ctx, const uint8_t input[16], uint8_t output[16]) {
    uint8_t state[16];
    int round;

    memcpy(state, input, 16);

    // 初始轮密钥加
    add_round_key(state, &ctx->round_keys[40]);

    // 9 轮主循环 (逆序)
    for (round = 9; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &ctx->round_keys[round * 4]);
        inv_mix_columns(state);
    }

    // 最后一轮 (无 InvMixColumns)
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, &ctx->round_keys[0]);

    memcpy(output, state, 16);
}

// ============================================================================
// AES-128-GCM 实现
// 参考: NIST SP 800-38D
// ============================================================================

// GF(2^128) 乘法 (用于 GHASH)
static void gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t result[16]) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    int i, j;

    memcpy(v, y, 16);

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 8; j++) {
            if (x[i] & (1 << (7 - j))) {
                // z = z XOR v
                int k;
                for (k = 0; k < 16; k++) {
                    z[k] ^= v[k];
                }
            }

            // v = v >> 1
            int lsb = v[15] & 1;
            int k;
            for (k = 15; k > 0; k--) {
                v[k] = (v[k] >> 1) | (v[k - 1] << 7);
            }
            v[0] >>= 1;

            // 如果 LSB 为 1，则 v = v XOR R
            if (lsb) {
                v[0] ^= 0xe1;
            }
        }
    }

    memcpy(result, z, 16);
}

// GHASH 函数
static void ghash(const uint8_t h[16], const uint8_t *data, size_t len, uint8_t output[16]) {
    uint8_t y[16] = {0};
    size_t i;

    for (i = 0; i < len; i += 16) {
        uint8_t block[16] = {0};
        size_t block_len = (len - i > 16) ? 16 : (len - i);
        memcpy(block, data + i, block_len);

        // y = (y XOR block) * h
        int j;
        for (j = 0; j < 16; j++) {
            y[j] ^= block[j];
        }
        gf128_mul(y, h, y);
    }

    memcpy(output, y, 16);
}

// 增量函数 (用于 CTR 模式)
static void inc32(uint8_t block[16]) {
    int i;
    for (i = 15; i >= 12; i--) {
        if (++block[i] != 0) break;
    }
}

void aes128_gcm_init(aes128_gcm_ctx_t *ctx, const uint8_t key[16]) {
    uint8_t zero[16] = {0};
    aes128_init(&ctx->aes_ctx, key);
    // H = E(K, 0^128)
    aes128_encrypt_block(&ctx->aes_ctx, zero, ctx->h);
}

void aes128_gcm_encrypt(aes128_gcm_ctx_t *ctx,
                        const uint8_t nonce[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *ciphertext,
                        uint8_t tag[16]) {
    uint8_t j0[16];
    uint8_t counter[16];
    size_t i;

    // 构造初始计数器块 J0 = nonce || 0^31 || 1
    memcpy(j0, nonce, 12);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;

    // CTR 模式加密
    memcpy(counter, j0, 16);
    for (i = 0; i < plaintext_len; i += 16) {
        uint8_t keystream[16];
        size_t block_len = (plaintext_len - i > 16) ? 16 : (plaintext_len - i);

        inc32(counter);
        aes128_encrypt_block(&ctx->aes_ctx, counter, keystream);

        size_t j;
        for (j = 0; j < block_len; j++) {
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }
    }

    // 计算 GHASH
    uint8_t *ghash_input = malloc(aad_len + plaintext_len + 16);
    memcpy(ghash_input, aad, aad_len);
    memcpy(ghash_input + aad_len, ciphertext, plaintext_len);

    // 添加长度块
    uint64_t aad_bits = aad_len * 8;
    uint64_t ct_bits = plaintext_len * 8;
    for (i = 0; i < 8; i++) {
        ghash_input[aad_len + plaintext_len + i] = (aad_bits >> (56 - i * 8)) & 0xff;
        ghash_input[aad_len + plaintext_len + 8 + i] = (ct_bits >> (56 - i * 8)) & 0xff;
    }

    uint8_t s[16];
    ghash(ctx->h, ghash_input, aad_len + plaintext_len + 16, s);
    free(ghash_input);

    // Tag = GHASH(H, A || C || len(A) || len(C)) XOR E(K, J0)
    uint8_t ej0[16];
    aes128_encrypt_block(&ctx->aes_ctx, j0, ej0);
    for (i = 0; i < 16; i++) {
        tag[i] = s[i] ^ ej0[i];
    }
}

int aes128_gcm_decrypt(aes128_gcm_ctx_t *ctx,
                       const uint8_t nonce[12],
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *ciphertext, size_t ciphertext_len,
                       const uint8_t tag[16],
                       uint8_t *plaintext) {
    uint8_t computed_tag[16];
    uint8_t j0[16];
    uint8_t counter[16];
    size_t i;

    // 验证标签
    uint8_t *ghash_input = malloc(aad_len + ciphertext_len + 16);
    memcpy(ghash_input, aad, aad_len);
    memcpy(ghash_input + aad_len, ciphertext, ciphertext_len);

    uint64_t aad_bits = aad_len * 8;
    uint64_t ct_bits = ciphertext_len * 8;
    for (i = 0; i < 8; i++) {
        ghash_input[aad_len + ciphertext_len + i] = (aad_bits >> (56 - i * 8)) & 0xff;
        ghash_input[aad_len + ciphertext_len + 8 + i] = (ct_bits >> (56 - i * 8)) & 0xff;
    }

    uint8_t s[16];
    ghash(ctx->h, ghash_input, aad_len + ciphertext_len + 16, s);
    free(ghash_input);

    memcpy(j0, nonce, 12);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;

    uint8_t ej0[16];
    aes128_encrypt_block(&ctx->aes_ctx, j0, ej0);
    for (i = 0; i < 16; i++) {
        computed_tag[i] = s[i] ^ ej0[i];
    }

    // 固定时间比较
    int tag_match = 0;
    for (i = 0; i < 16; i++) {
        tag_match |= (computed_tag[i] ^ tag[i]);
    }

    if (tag_match != 0) {
        return -1;  // 认证失败
    }

    // CTR 模式解密
    memcpy(counter, j0, 16);
    for (i = 0; i < ciphertext_len; i += 16) {
        uint8_t keystream[16];
        size_t block_len = (ciphertext_len - i > 16) ? 16 : (ciphertext_len - i);

        inc32(counter);
        aes128_encrypt_block(&ctx->aes_ctx, counter, keystream);

        size_t j;
        for (j = 0; j < block_len; j++) {
            plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
        }
    }

    return 0;  // 成功
}

// ============================================================================
// 随机数生成
// ============================================================================

void tls_random_bytes(uint8_t *output, size_t len) {
    // 这是一个简化的实现，生产环境应该使用 /dev/urandom 或更安全的 CSPRNG
    static int initialized = 0;
    if (!initialized) {
        srand(time(NULL));
        initialized = 1;
    }

    size_t i;
    for (i = 0; i < len; i++) {
        output[i] = rand() & 0xFF;
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

void print_hex(const char *label, const uint8_t *data, size_t len) {
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) {
            printf("\n%*s", (int)strlen(label) + 2, "");
        }
    }
    printf("\n");
}

