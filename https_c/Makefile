CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

TARGET = client
OBJS = client.o tls_client.o tls_crypto.o tls_record.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

client.o: client.c tls_client.h
	$(CC) $(CFLAGS) -c client.c

tls_client.o: tls_client.c tls_client.h
	$(CC) $(CFLAGS) -c tls_client.c

tls_crypto.o: tls_crypto.c tls_crypto.h
	$(CC) $(CFLAGS) -c tls_crypto.c

tls_record.o: tls_record.c tls_record.h tls_crypto.h
	$(CC) $(CFLAGS) -c tls_record.c

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
