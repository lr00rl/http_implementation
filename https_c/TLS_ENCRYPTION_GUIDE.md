# TLS 加密原理深度解析

本文档详细解释 TLS 协议中使用的加密技术和实现细节。

## 目录

1. [对称加密 - AES](#对称加密---aes)
2. [哈希函数 - SHA-256](#哈希函数---sha-256)
3. [消息认证码 - HMAC](#消息认证码---hmac)
4. [认证加密 - GCM](#认证加密---gcm)
5. [密钥派生 - PRF](#密钥派生---prf)
6. [TLS 握手流程](#tls-握手流程)
7. [密钥交换 - ECDHE](#密钥交换---ecdhe)

---

## 对称加密 - AES

### 什么是 AES？

AES (Advanced Encryption Standard) 是美国国家标准与技术研究院 (NIST) 在 2001 年确立的加密标准，用于替代 DES。

**基本参数：**
- 分组长度：128 bits (16 bytes)
- 密钥长度：128/192/256 bits（本实现使用 128 bits）
- 轮数：10/12/14 轮（AES-128 为 10 轮）

### AES 工作原理

AES 是一个**分组密码**，将 128-bit 的明文块转换为 128-bit 的密文块。

#### 1. 状态矩阵 (State)

AES 将 16 字节的数据排列成 4×4 的矩阵：

```
输入: [b0, b1, b2, ..., b15]

State 矩阵:
┌──────────────┐
│ b0  b4  b8  b12 │
│ b1  b5  b9  b13 │
│ b2  b6  b10 b14 │
│ b3  b7  b11 b15 │
└──────────────┘
```

#### 2. 密钥扩展 (Key Expansion)

从 128-bit 的原始密钥生成 11 个 128-bit 的轮密钥。

```c
// 密钥扩展算法
void aes128_init(aes128_ctx_t *ctx, const uint8_t key[16]) {
    // 复制原始密钥到前 4 个字
    for (i = 0; i < 4; i++) {
        ctx->round_keys[i] = WORD(key, i);
    }

    // 生成剩余 40 个字 (总共 44 个字 = 11 个轮密钥)
    for (i = 4; i < 44; i++) {
        temp = ctx->round_keys[i - 1];
        if (i % 4 == 0) {
            // 每 4 个字应用特殊变换
            temp = SubWord(RotWord(temp)) XOR Rcon[i/4];
        }
        ctx->round_keys[i] = ctx->round_keys[i - 4] XOR temp;
    }
}
```

#### 3. 加密过程

AES-128 加密包含 10 轮变换：

```
明文
  ↓
AddRoundKey(轮密钥 0)
  ↓
┌─────────────────┐
│ 第 1-9 轮:      │
│   SubBytes      │  ← S-box 字节替换
│   ShiftRows     │  ← 行移位
│   MixColumns    │  ← 列混合
│   AddRoundKey   │  ← 轮密钥加
└─────────────────┘
  ↓
第 10 轮:
  SubBytes
  ShiftRows
  AddRoundKey(轮密钥 10)
  ↓
密文
```

##### 3.1 SubBytes - S-box 替换

使用预定义的 S-box 表替换每个字节：

```c
static void sub_bytes(uint8_t state[16]) {
    for (i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
}
```

S-box 是一个 256 字节的查找表，提供非线性变换：

```
sbox[0x00] = 0x63
sbox[0x01] = 0x7c
...
```

**为什么需要 S-box？**
- 提供**非线性性**，防止线性密码分析
- 使加密算法更难以破解

##### 3.2 ShiftRows - 行移位

循环移位状态矩阵的每一行：

```
移位前:                移位后:
┌──────────────┐      ┌──────────────┐
│ b0  b4  b8  b12 │      │ b0  b4  b8  b12 │ (第 0 行不移位)
│ b1  b5  b9  b13 │  →  │ b5  b9  b13 b1  │ (左移 1 字节)
│ b2  b6  b10 b14 │      │ b10 b14 b2  b6  │ (左移 2 字节)
│ b3  b7  b11 b15 │      │ b15 b3  b7  b11 │ (左移 3 字节)
└──────────────┘      └──────────────┘
```

**为什么需要 ShiftRows？**
- 提供**扩散性**，使每个输入位影响多个输出位
- 配合 MixColumns 实现全局扩散

##### 3.3 MixColumns - 列混合

对每一列进行 GF(2^8) 域上的矩阵乘法：

```
┌──┐   ┌──────────┐   ┌──┐
│s0│   │02 03 01 01│   │s0│
│s1│ = │01 02 03 01│ × │s1│
│s2│   │01 01 02 03│   │s2│
│s3│   │03 01 01 02│   │s3│
└──┘   └──────────┘   └──┘
```

在 GF(2^8) 域中：
- 加法 = XOR
- 乘法需要特殊处理

```c
static void mix_columns(uint8_t state[16]) {
    for (i = 0; i < 4; i++) {
        uint8_t *col = &state[i * 4];
        uint8_t tmp[4];
        memcpy(tmp, col, 4);

        col[0] = gf_mul(tmp[0], 2) ^ gf_mul(tmp[1], 3) ^ tmp[2] ^ tmp[3];
        col[1] = tmp[0] ^ gf_mul(tmp[1], 2) ^ gf_mul(tmp[2], 3) ^ tmp[3];
        col[2] = tmp[0] ^ tmp[1] ^ gf_mul(tmp[2], 2) ^ gf_mul(tmp[3], 3);
        col[3] = gf_mul(tmp[0], 3) ^ tmp[1] ^ tmp[2] ^ gf_mul(tmp[3], 2);
    }
}
```

##### 3.4 AddRoundKey - 轮密钥加

将状态与轮密钥进行 XOR：

```c
static void add_round_key(uint8_t state[16], const uint32_t *round_key) {
    for (i = 0; i < 4; i++) {
        state[i*4]   ^= (round_key[i] >> 24) & 0xff;
        state[i*4+1] ^= (round_key[i] >> 16) & 0xff;
        state[i*4+2] ^= (round_key[i] >> 8)  & 0xff;
        state[i*4+3] ^= round_key[i] & 0xff;
    }
}
```

#### 4. GF(2^8) 域乘法

AES 中的乘法在有限域 GF(2^8) 中进行，模多项式为 `x^8 + x^4 + x^3 + x + 1`。

```c
static uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (i = 0; i < 8; i++) {
        if (b & 1) p ^= a;

        uint8_t hi_bit = (a & 0x80);
        a <<= 1;
        if (hi_bit) a ^= 0x1b;  // 模约简 (x^8 + x^4 + x^3 + x + 1)

        b >>= 1;
    }
    return p;
}
```

---

## 哈希函数 - SHA-256

### 什么是 SHA-256？

SHA-256 (Secure Hash Algorithm 256-bit) 是一个密码学哈希函数，将任意长度的输入映射为固定长度的 256-bit 输出。

**特性：**
- 单向性：从哈希值无法反推原始数据
- 抗碰撞：难以找到两个不同输入产生相同哈希
- 雪崩效应：输入的微小变化导致输出巨大变化

### SHA-256 工作原理

#### 1. 消息填充

将消息填充为 512-bit 的倍数：

```
原始消息: M (任意长度)
  ↓
添加 '1' bit
  ↓
添加若干 '0' bits (使总长度 ≡ 448 mod 512)
  ↓
添加 64-bit 消息长度
  ↓
填充后的消息 (长度为 512 的倍数)
```

示例：
```
原始: "abc" = 0x616263 (24 bits)
填充: 61 62 63 80 00 00 ... 00 00 00 00 00 00 00 18
      └─────┘ └┘ └─────────┘ └───────────────┘
       消息   1   零填充        长度 (24 bits)
```

#### 2. 初始哈希值

使用前 8 个素数的平方根的小数部分：

```c
H0 = 0x6a09e667  // sqrt(2)
H1 = 0xbb67ae85  // sqrt(3)
H2 = 0x3c6ef372  // sqrt(5)
H3 = 0xa54ff53a  // sqrt(7)
H4 = 0x510e527f  // sqrt(11)
H5 = 0x9b05688c  // sqrt(13)
H6 = 0x1f83d9ab  // sqrt(17)
H7 = 0x5be0cd19  // sqrt(19)
```

#### 3. 消息调度

将每个 512-bit 块扩展为 64 个 32-bit 字：

```c
// 前 16 个字直接从消息块复制
for (i = 0; i < 16; i++) {
    W[i] = WORD(block, i);
}

// 后 48 个字通过公式计算
for (i = 16; i < 64; i++) {
    W[i] = σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16];
}

// 其中:
σ0(x) = ROTR(x, 7) XOR ROTR(x, 18) XOR SHR(x, 3)
σ1(x) = ROTR(x, 17) XOR ROTR(x, 19) XOR SHR(x, 10)
```

#### 4. 压缩函数

对每个 512-bit 块进行 64 轮变换：

```c
// 初始化工作变量
a = H0; b = H1; c = H2; d = H3;
e = H4; f = H5; g = H6; h = H7;

// 64 轮主循环
for (i = 0; i < 64; i++) {
    T1 = h + Σ1(e) + Ch(e, f, g) + K[i] + W[i];
    T2 = Σ0(a) + Maj(a, b, c);

    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
}

// 更新哈希值
H0 += a; H1 += b; H2 += c; H3 += d;
H4 += e; H5 += f; H6 += g; H7 += h;
```

**辅助函数：**

```c
Ch(x, y, z)  = (x AND y) XOR (NOT x AND z)  // 选择函数
Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)  // 多数函数

Σ0(x) = ROTR(x, 2) XOR ROTR(x, 13) XOR ROTR(x, 22)
Σ1(x) = ROTR(x, 6) XOR ROTR(x, 11) XOR ROTR(x, 25)
```

#### 5. 输出

连接 8 个哈希值得到 256-bit 的最终哈希：

```
Hash = H0 || H1 || H2 || H3 || H4 || H5 || H6 || H7
```

---

## 消息认证码 - HMAC

### 什么是 HMAC？

HMAC (Hash-based Message Authentication Code) 是基于哈希函数的消息认证码，用于验证消息的完整性和真实性。

**用途：**
- 验证消息未被篡改
- 验证消息来自预期的发送者
- 在 TLS 中用于 PRF 和 Finished 消息

### HMAC 工作原理

```
HMAC(K, M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))

其中:
- K: 密钥
- M: 消息
- H: 哈希函数 (SHA-256)
- opad: 0x5c5c5c...5c (64 字节)
- ipad: 0x3636...36 (64 字节)
- ||: 连接
- ⊕: XOR
```

**实现步骤：**

```c
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t output[32]) {
    uint8_t k[64];  // 填充后的密钥

    // 步骤 1: 准备密钥
    if (key_len > 64) {
        // 密钥太长，先哈希
        sha256(key, key_len, k);
        memset(k + 32, 0, 32);
    } else {
        // 密钥不够长，补零
        memcpy(k, key, key_len);
        memset(k + key_len, 0, 64 - key_len);
    }

    // 步骤 2: 计算内部哈希
    uint8_t ipad[64], opad[64];
    for (i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    uint8_t inner_hash[32];
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_hash);

    // 步骤 3: 计算外部哈希
    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, inner_hash, 32);
    sha256_final(&ctx, output);
}
```

**为什么使用两层哈希？**
- 防止长度扩展攻击
- 提供更强的安全性保证

---

## 认证加密 - GCM

### 什么是 GCM？

GCM (Galois/Counter Mode) 是一种**认证加密**模式，同时提供：
- **机密性** (Confidentiality) - 通过 CTR 模式加密
- **完整性** (Integrity) - 通过 GHASH 认证

### GCM 工作原理

#### 1. 整体结构

```
输入:
- Key (128 bits)         - 加密密钥
- Nonce (96 bits)        - 随机数
- AAD (可变长度)         - 附加认证数据（不加密但需认证）
- Plaintext (可变长度)   - 明文

输出:
- Ciphertext (与明文等长) - 密文
- Tag (128 bits)         - 认证标签
```

#### 2. 初始化

```c
// 计算 H (用于 GHASH)
H = AES(Key, 0^128)

// 构造初始计数器 J0
J0 = Nonce || 0^31 || 1
```

#### 3. CTR 模式加密

使用计数器模式加密明文：

```c
Counter = J0
for each 16-byte block of plaintext:
    Counter = inc32(Counter)  // 增加计数器
    Keystream = AES(Key, Counter)
    Ciphertext_block = Plaintext_block XOR Keystream
```

**inc32** 函数增加计数器的最后 32 bits：

```c
static void inc32(uint8_t block[16]) {
    for (i = 15; i >= 12; i--) {
        if (++block[i] != 0) break;  // 处理进位
    }
}
```

#### 4. GHASH 认证

GHASH 是一个基于 Galois 域的哈希函数：

```
GHASH(H, X) = X1•H^n ⊕ X2•H^(n-1) ⊕ ... ⊕ Xn•H

其中:
- H: 128-bit 哈希密钥
- X = X1 || X2 || ... || Xn: 输入数据（分成 16 字节块）
- •: GF(2^128) 乘法
- ⊕: XOR
```

**GF(2^128) 乘法实现：**

```c
static void gf128_mul(const uint8_t x[16], const uint8_t y[16],
                      uint8_t result[16]) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    memcpy(v, y, 16);

    for (i = 0; i < 128; i++) {
        // 如果 x 的第 i 位为 1
        if (x[i/8] & (1 << (7 - i%8))) {
            // z = z ⊕ v
            for (j = 0; j < 16; j++) {
                z[j] ^= v[j];
            }
        }

        // v = v >> 1 (右移)
        uint8_t lsb = v[15] & 1;
        for (j = 15; j > 0; j--) {
            v[j] = (v[j] >> 1) | (v[j-1] << 7);
        }
        v[0] >>= 1;

        // 如果 LSB 为 1，则 v = v ⊕ R
        if (lsb) {
            v[0] ^= 0xe1;  // R = 11100001 || 0^120
        }
    }

    memcpy(result, z, 16);
}
```

#### 5. 生成认证标签

```c
// 构造 GHASH 输入
GHASH_input = AAD || 0^padding1 ||
              Ciphertext || 0^padding2 ||
              len(AAD) || len(Ciphertext)

// 计算 GHASH
S = GHASH(H, GHASH_input)

// 生成标签
Tag = S ⊕ AES(Key, J0)
```

#### 6. GCM 加密完整流程

```
加密:
  1. H = AES(Key, 0^128)
  2. J0 = Nonce || 0^31 || 1
  3. Ciphertext = CTR_encrypt(Plaintext, Key, J0)
  4. S = GHASH(H, AAD || Ciphertext || lengths)
  5. Tag = S ⊕ AES(Key, J0)
  6. 返回 (Ciphertext, Tag)

解密:
  1. H = AES(Key, 0^128)
  2. J0 = Nonce || 0^31 || 1
  3. S = GHASH(H, AAD || Ciphertext || lengths)
  4. Expected_Tag = S ⊕ AES(Key, J0)
  5. 如果 Tag ≠ Expected_Tag，返回错误 (认证失败)
  6. Plaintext = CTR_decrypt(Ciphertext, Key, J0)
  7. 返回 Plaintext
```

---

## 密钥派生 - PRF

### 什么是 TLS PRF？

TLS PRF (Pseudo-Random Function) 是 TLS 协议用于从密钥材料派生任意长度密钥的函数。

**用途：**
- 从预主密钥派生主密钥
- 从主密钥派生会话密钥
- 计算 Finished 消息的 verify_data

### TLS 1.2 PRF 定义

```
PRF(secret, label, seed) = P_SHA256(secret, label + seed)
```

### P_hash 函数

P_hash 是一个基于 HMAC 的扩展函数：

```
P_hash(secret, seed) = HMAC(secret, A(1) + seed) +
                       HMAC(secret, A(2) + seed) +
                       HMAC(secret, A(3) + seed) + ...

其中:
A(0) = seed
A(i) = HMAC(secret, A(i-1))
```

**实现：**

```c
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

        // 复制到输出
        size_t to_copy = MIN(32, output_len - copied);
        memcpy(output + copied, temp, to_copy);
        copied += to_copy;

        // A(i+1) = HMAC(secret, A(i))
        hmac_sha256(secret, secret_len, a, 32, a);
    }
}
```

### TLS 密钥派生示例

#### 1. 派生主密钥

```c
// master_secret = PRF(pre_master_secret, "master secret",
//                     ClientHello.random + ServerHello.random)[0..47]

uint8_t seed[64];
memcpy(seed, client_random, 32);
memcpy(seed + 32, server_random, 32);

tls_prf_sha256(pre_master_secret, 48,
               "master secret",
               seed, 64,
               master_secret, 48);
```

#### 2. 派生会话密钥

```c
// key_block = PRF(master_secret, "key expansion",
//                 ServerHello.random + ClientHello.random)

uint8_t seed[64];
memcpy(seed, server_random, 32);
memcpy(seed + 32, client_random, 32);

// 需要 40 字节密钥材料:
// - client_write_key (16)
// - server_write_key (16)
// - client_write_IV (4)
// - server_write_IV (4)
uint8_t key_block[40];
tls_prf_sha256(master_secret, 48,
               "key expansion",
               seed, 64,
               key_block, 40);

// 分配密钥材料
memcpy(client_write_key, key_block, 16);
memcpy(server_write_key, key_block + 16, 16);
memcpy(client_write_IV, key_block + 32, 4);
memcpy(server_write_IV, key_block + 36, 4);
```

---

## TLS 握手流程

### 完整握手流程图

```
客户端                                        服务器

ClientHello          ────────────────────────>
                                               ServerHello
                                               Certificate
                                               ServerKeyExchange
                     <────────────────────────  ServerHelloDone

ClientKeyExchange    ────────────────────────>
ChangeCipherSpec
Finished             ────────────────────────>
                                               ChangeCipherSpec
                     <────────────────────────  Finished

应用数据             <───────────────────────> 应用数据
```

### 详细步骤

#### 1. ClientHello

客户端发送支持的参数：

```
ClientHello {
    client_version: 0x0303 (TLS 1.2)
    random: 32 bytes
        ├─ gmt_unix_time: 4 bytes (当前时间戳)
        └─ random_bytes: 28 bytes
    session_id: 0 bytes (新会话)
    cipher_suites: [
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
    ]
    compression_methods: [null (0)]
    extensions: [
        server_name: "example.com"
        supported_groups: [secp256r1]
        ec_point_formats: [uncompressed]
    ]
}
```

#### 2. ServerHello

服务器选择参数：

```
ServerHello {
    server_version: 0x0303 (TLS 1.2)
    random: 32 bytes
    session_id: 32 bytes (可选)
    cipher_suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    compression_method: null
    extensions: [...]
}
```

#### 3. Certificate

服务器发送 X.509 证书链：

```
Certificate {
    certificate_list: [
        cert1 (服务器证书),
        cert2 (中间 CA 证书),
        ...
    ]
}
```

#### 4. ServerKeyExchange

服务器发送 ECDHE 参数：

```
ServerKeyExchange {
    curve_type: named_curve (3)
    named_curve: secp256r1 (23)
    public_key: 65 bytes (未压缩点)
        ├─ 0x04 (未压缩标记)
        ├─ X 坐标: 32 bytes
        └─ Y 坐标: 32 bytes
    signature_algorithm: rsa_pkcs1_sha256
    signature: ... (RSA 签名)
}
```

#### 5. ClientKeyExchange

客户端发送 ECDHE 公钥：

```
ClientKeyExchange {
    public_key: 65 bytes
}
```

双方计算共享密钥：

```
// ECDH 计算
shared_secret = ECDH(client_private_key, server_public_key)
              = ECDH(server_private_key, client_public_key)

// 派生预主密钥
pre_master_secret = shared_secret
```

#### 6. ChangeCipherSpec

通知对方切换到加密模式：

```
ChangeCipherSpec {
    type: 1
}
```

#### 7. Finished

发送加密的握手验证消息：

```
Finished {
    verify_data: PRF(master_secret,
                     "client finished",
                     SHA256(所有握手消息))[0..11]
}
```

---

## 密钥交换 - ECDHE

### 什么是 ECDHE？

ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) 是基于椭圆曲线的临时密钥交换协议。

**优点：**
- **前向保密性** - 即使长期密钥泄露，过去的会话仍然安全
- **高效** - 比 RSA 更短的密钥长度提供相同安全性
- **临时性** - 每次握手使用不同的密钥

### 椭圆曲线基础

TLS 使用 secp256r1 (P-256) 曲线：

```
y² = x³ - 3x + b (mod p)

其中:
p = 2^256 - 2^224 + 2^192 + 2^96 - 1
b = 41058363725152142129326129780047268409114441015993725554835256314039467401291
```

### ECDH 密钥交换

```
客户端:                                    服务器:
1. 生成随机私钥 dC                         1. 生成随机私钥 dS
2. 计算公钥 QC = dC × G                   2. 计算公钥 QS = dS × G
3. 发送 QC ───────────────────────────────>
                                           3. 计算共享密钥 S = dS × QC
4. 接收 QS <───────────────────────────────
5. 计算共享密钥 S = dC × QS

结果: S = dC × QS = dC × (dS × G) = (dC × dS) × G
            = dS × (dC × G) = dS × QC
```

### 公钥编码

未压缩点格式（65 字节）：

```
┌────┬────────────────┬────────────────┐
│0x04│  X 坐标 (32)  │  Y 坐标 (32)  │
└────┴────────────────┴────────────────┘
```

### 简化实现

本项目使用简化的实现（不进行真实的 ECDH 计算）：

```c
// 注意：这是简化实现，仅用于教学
uint8_t pre_master_secret[48];
pre_master_secret[0] = (TLS_VERSION_1_2 >> 8) & 0xFF;
pre_master_secret[1] = TLS_VERSION_1_2 & 0xFF;
tls_random_bytes(pre_master_secret + 2, 46);
```

**真实实现需要：**
1. 椭圆曲线点运算库
2. 大数运算库
3. ECDH 密钥协商算法

推荐参考 OpenSSL 或 mbedTLS 的实现。

---

## 总结

TLS 协议使用多层加密技术保护通信安全：

1. **对称加密 (AES-GCM)** - 快速加密大量数据
2. **哈希函数 (SHA-256)** - 验证数据完整性
3. **消息认证码 (HMAC)** - 防止消息篡改
4. **密钥派生 (PRF)** - 从少量密钥材料生成所需密钥
5. **密钥交换 (ECDHE)** - 安全地协商共享密钥

这些技术共同工作，提供：
- ✅ 机密性 - 数据加密，防止窃听
- ✅ 完整性 - 消息认证，防止篡改
- ✅ 真实性 - 证书验证，防止冒充
- ✅ 前向保密 - 临时密钥，保护历史数据

---

**参考资料：**
- [RFC 5246 - TLS 1.2](https://tools.ietf.org/html/rfc5246)
- [FIPS 197 - AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [FIPS 180-4 - SHA-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [NIST SP 800-38D - GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)

