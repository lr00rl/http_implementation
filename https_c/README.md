# HTTPS 客户端 - 自定义 TLS 实现

这是一个**教学性质**的 HTTPS 客户端实现，从零开始手动实现 TLS/SSL 协议的核心功能，帮助您深入理解 HTTPS 加密通信的工作原理。

## ⚠️ 重要声明

**本项目仅用于学习和教学目的！**

- ✅ 适合学习 TLS 协议原理
- ✅ 适合理解加密算法实现
- ✅ 适合研究网络安全基础
- ❌ **不要在生产环境使用**
- ❌ **未经过安全审计**
- ❌ **缺少完整的错误处理和安全检查**

生产环境请使用经过严格审计的成熟库，如 OpenSSL、BoringSSL 或 mbedTLS。

## 📚 项目特点

### 手动实现的加密算法

1. **SHA-256** (Secure Hash Algorithm)
   - 完整实现 FIPS 180-4 标准
   - 用于消息摘要和 HMAC
   - 256-bit 输出

2. **HMAC-SHA256** (Hash-based Message Authentication Code)
   - 基于 SHA-256 的消息认证码
   - 用于 TLS PRF 和数据完整性验证

3. **AES-128** (Advanced Encryption Standard)
   - 完整实现 FIPS 197 标准
   - 10 轮加密/解密
   - 支持 ECB 模式（用于 GCM）

4. **AES-128-GCM** (Galois/Counter Mode)
   - 认证加密模式
   - 同时提供机密性和完整性
   - NIST SP 800-38D 标准

5. **TLS PRF** (Pseudo-Random Function)
   - TLS 1.2 密钥派生函数
   - 基于 HMAC-SHA256
   - 用于生成主密钥和会话密钥

### TLS 协议实现

1. **TLS 记录层** (Record Layer)
   - 数据分段和重组
   - 加密和解密
   - 消息认证

2. **TLS 握手协议** (Handshake Protocol)
   - ClientHello / ServerHello
   - Certificate 交换
   - ServerKeyExchange / ClientKeyExchange
   - ChangeCipherSpec
   - Finished 消息验证

3. **密钥派生**
   - 预主密钥 → 主密钥
   - 主密钥 → 会话密钥
   - 客户端/服务器独立密钥

## 🏗️ 项目结构

```
https_c/
├── client.c              # HTTPS 客户端主程序
├── server.c              # HTTPS 服务器（原始版本）
├── tls_types.h           # TLS 协议类型定义
├── tls_crypto.h/c        # 加密算法实现
├── tls_record.h/c        # TLS 记录层协议
├── tls_handshake.h/c     # TLS 握手协议
├── tls_session.c         # TLS 会话管理
├── Makefile              # 构建脚本
└── README.md             # 本文档
```

## 🔧 编译和运行

### 编译

```bash
# 编译客户端和服务器
make

# 或者单独编译客户端
gcc -Wall -Wextra -o https_client \
    client.c tls_crypto.c tls_record.c tls_handshake.c tls_session.c
```

### 运行

```bash
# 运行客户端（连接到 example.com）
./https_client

# 或者指定主机和端口
./https_client <hostname/ip> <port>
```

### 示例输出

```

