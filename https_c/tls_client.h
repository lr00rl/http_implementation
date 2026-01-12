#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
    int sock;
} tls_client_t;

int tls_client_init(tls_client_t *client);
int tls_client_connect(tls_client_t *client, int sock, const char *hostname);
int tls_client_write(tls_client_t *client, const void *buf, int len);
int tls_client_read(tls_client_t *client, void *buf, int len);
void tls_client_close(tls_client_t *client);

#endif
