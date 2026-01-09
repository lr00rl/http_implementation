# Makefile for HTTPS Client with Custom TLS Implementation

CC = gcc
CFLAGS = -Wall -Wextra -g -O2
LDFLAGS =

# 源文件
SOURCES = client.c tls_crypto.c tls_record.c tls_handshake.c tls_session.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = https_client

# 服务器程序
SERVER_TARGET = https_server
SERVER_SOURCES = server.c tls_crypto.c tls_record.c tls_handshake.c tls_session.c tls_server_handshake.c
SERVER_OBJECTS = $(SERVER_SOURCES:.c=.o)

# 测试客户端程序
TEST_CLIENT_TARGET = test_client
TEST_CLIENT_SOURCES = test_client.c tls_crypto.c tls_record.c tls_handshake.c tls_session.c
TEST_CLIENT_OBJECTS = $(TEST_CLIENT_SOURCES:.c=.o)

all: $(TARGET) $(SERVER_TARGET) $(TEST_CLIENT_TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ HTTPS client built successfully!"

$(SERVER_TARGET): $(SERVER_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ HTTPS server built successfully!"

$(TEST_CLIENT_TARGET): $(TEST_CLIENT_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ Test client built successfully!"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(SERVER_OBJECTS) $(TEST_CLIENT_OBJECTS) $(TARGET) $(SERVER_TARGET) $(TEST_CLIENT_TARGET)
	@echo "✓ Cleaned build files"

run: $(TARGET)
	./$(TARGET)

run-server: $(SERVER_TARGET)
	./$(SERVER_TARGET)

run-test: $(TEST_CLIENT_TARGET)
	./$(TEST_CLIENT_TARGET)

# 调试模式
debug: CFLAGS += -DDEBUG -g3
debug: clean $(TARGET)

# 帮助信息
help:
	@echo "Available targets:"
	@echo "  make          - Build the HTTPS client and server"
	@echo "  make clean    - Remove build files"
	@echo "  make run      - Build and run the HTTPS client"
	@echo "  make run-server - Build and run the HTTPS server"
	@echo "  make debug    - Build with debug symbols"
	@echo "  make help     - Show this help message"

.PHONY: all clean run run-server debug help

