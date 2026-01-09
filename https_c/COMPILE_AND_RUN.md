# 编译和运行指南

## 快速开始

### 1. 编译

```bash
cd https_c
make
```

编译成功后会生成两个可执行文件：
- `https_client` - HTTPS 客户端
- `https_server` - HTTPS 服务器（原始版本）

### 2. 运行客户端

```bash
# 运行默认示例（连接到 example.com）
./https_client

# 或者指定主机和端口
./https_client <IP地址> <端口>
```

## 详细编译选项

### 手动编译

如果不使用 Makefile，可以手动编译：

```bash
gcc -Wall -Wextra -g -O2 -o https_client \
    client.c \
    tls_crypto.c \
    tls_record.c \
    tls_handshake.c \
    tls_session.c
```

### 调试模式

启用调试符号和更详细的输出：

```bash
make clean
make debug
```

### 清理

```bash
make clean
```

## 运行示例

### 示例 1: 基本运行

```bash
$ ./https_client

