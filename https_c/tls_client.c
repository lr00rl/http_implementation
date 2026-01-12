#include "tls_client.h"
#include <stdio.h>
#include <string.h>

int tls_client_init(tls_client_t *client) {
    memset(client, 0, sizeof(*client));

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    client->ctx = SSL_CTX_new(TLS_client_method());
    if (!client->ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Set minimum TLS version to 1.2
    SSL_CTX_set_min_proto_version(client->ctx, TLS1_2_VERSION);

    // Load default trusted CA certificates
    if (!SSL_CTX_set_default_verify_paths(client->ctx)) {
        fprintf(stderr, "Failed to load default CA certificates\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(client->ctx);
        return -1;
    }

    return 0;
}

int tls_client_connect(tls_client_t *client, int sock, const char *hostname) {
    client->sock = sock;
    client->ssl = SSL_new(client->ctx);
    if (!client->ssl) {
        fprintf(stderr, "Failed to create SSL structure\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Set SNI (Server Name Indication)
    SSL_set_tlsext_host_name(client->ssl, hostname);

    // Set hostname for certificate verification
    SSL_set1_host(client->ssl, hostname);

    // Associate socket with SSL
    SSL_set_fd(client->ssl, sock);

    // Perform TLS handshake
    int ret = SSL_connect(client->ssl);
    if (ret != 1) {
        fprintf(stderr, "TLS handshake failed: ");
        int err = SSL_get_error(client->ssl, ret);
        switch (err) {
            case SSL_ERROR_ZERO_RETURN:
                fprintf(stderr, "Connection closed\n");
                break;
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                fprintf(stderr, "Non-blocking I/O\n");
                break;
            case SSL_ERROR_SYSCALL:
                fprintf(stderr, "I/O error\n");
                break;
            case SSL_ERROR_SSL:
                fprintf(stderr, "SSL protocol error\n");
                ERR_print_errors_fp(stderr);
                break;
            default:
                fprintf(stderr, "Unknown error %d\n", err);
                break;
        }
        SSL_free(client->ssl);
        client->ssl = NULL;
        return -1;
    }

    printf("TLS handshake successful\n");
    printf("Protocol: %s\n", SSL_get_version(client->ssl));
    printf("Cipher: %s\n", SSL_get_cipher(client->ssl));

    return 0;
}

int tls_client_write(tls_client_t *client, const void *buf, int len) {
    if (!client->ssl) return -1;

    int total_sent = 0;
    while (total_sent < len) {
        int sent = SSL_write(client->ssl, (char*)buf + total_sent, len - total_sent);
        if (sent <= 0) {
            int err = SSL_get_error(client->ssl, sent);
            fprintf(stderr, "SSL_write error: %d\n", err);
            return -1;
        }
        total_sent += sent;
    }
    return total_sent;
}

int tls_client_read(tls_client_t *client, void *buf, int len) {
    if (!client->ssl) return -1;

    int received = SSL_read(client->ssl, buf, len);
    if (received < 0) {
        int err = SSL_get_error(client->ssl, received);
        fprintf(stderr, "SSL_read error: %d\n", err);
        return -1;
    }
    return received;
}

void tls_client_close(tls_client_t *client) {
    if (client->ssl) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
    if (client->ctx) {
        SSL_CTX_free(client->ctx);
        client->ctx = NULL;
    }
}
