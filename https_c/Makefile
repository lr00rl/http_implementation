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
SERVER_SOURCES = server.c

all: $(TARGET) $(SERVER_TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ HTTPS client built successfully!"

$(SERVER_TARGET): $(SERVER_SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ HTTPS server built successfully!"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET) $(SERVER_TARGET)
	@echo "✓ Cleaned build files"

run: $(TARGET)
	./$(TARGET)

run-server: $(SERVER_TARGET)
	./$(SERVER_TARGET)

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

