#include "tls_client.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/x509.h> // For X509 certificate handling
#include <openssl/evp.h>  // For EVP_PKEY handling
#include <openssl/err.h>  // For error printing
#include <openssl/ssl.h>  // Explicitly include for SSL_* functions used in msg_callback and tls_client_connect

// Helper function to print hex data
void hex_dump(const char *prefix, const unsigned char *buf, size_t len) {
    size_t i;
    fprintf(stderr, "%s", prefix);
    for (i = 0; i < len; i++) {
        fprintf(stderr, "%02x", buf[i]);
        if ((i + 1) % 16 == 0 && (i + 1) < len) {
            fprintf(stderr, "\n%s", prefix);
        } else if ((i + 1) < len) {
            fprintf(stderr, " ");
        }
    }
    fprintf(stderr, "\n");
}

// Simplified info callback - mainly for state changes and alerts
void msg_callback(const SSL *ssl, int type, int val) {
    if (type & SSL_CB_LOOP) {
        fprintf(stderr, "[%s] Loop: %s\n", SSL_state_string_long(ssl), SSL_state_string_long(ssl));
    } else if (type & SSL_CB_ALERT) {
        const char *direction = (type & SSL_CB_WRITE) ? "SEND" : "RECV";
        const char *alert_type = (val & 0xFF00) == (SSL3_AL_FATAL << 8) ? "FATAL" : "WARNING";
        const char *alert_desc = SSL_alert_desc_string_long(val);
        fprintf(stderr, "[%s] %s %s Alert: %s\n",
                SSL_state_string_long(ssl), direction, alert_type, alert_desc);
    } else if (type & SSL_CB_EXIT) {
        fprintf(stderr, "[%s] Exit (Result: %d)\n", SSL_state_string_long(ssl), val);
    } else if (type & SSL_CB_HANDSHAKE_START) {
        fprintf(stderr, "[%s] Handshake Started.\n", SSL_state_string_long(ssl));
    } else if (type & SSL_CB_HANDSHAKE_DONE) {
        fprintf(stderr, "[%s] Handshake Done.\n", SSL_state_string_long(ssl));
    }
}


int tls_client_init(tls_client_t *client) {
    memset(client, 0, sizeof(*client));

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif

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

    // Register our info callback
    SSL_CTX_set_info_callback(client->ctx, msg_callback);

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
    // This is important for hostname validation against the certificate
    SSL_set1_host(client->ssl, hostname);

    // Associate socket with SSL
    SSL_set_fd(client->ssl, sock);

    // Perform TLS handshake
    fprintf(stderr, "Performing TLS handshake...\n");
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
                ERR_print_errors_fp(stderr); // Print OpenSSL specific errors
                break;
            case SSL_ERROR_SSL:
                fprintf(stderr, "SSL protocol error\n");
                ERR_print_errors_fp(stderr); // Print OpenSSL specific errors
                break;
            default:
                fprintf(stderr, "Unknown error %d\n", err);
                break;
        }
        SSL_free(client->ssl);
        client->ssl = NULL;
        return -1;
    }

    fprintf(stderr, "\n--- TLS Handshake Successful ---\n");
    fprintf(stderr, "Protocol: %s\n", SSL_get_version(client->ssl));
    fprintf(stderr, "Cipher: %s\n", SSL_get_cipher(client->ssl));


    // --- Extract and print cryptographic parameters ---

    // 1. Client Random
    unsigned char client_random[SSL3_RANDOM_SIZE];
    SSL_get_client_random(client->ssl, client_random, SSL3_RANDOM_SIZE);
    hex_dump("Client Random:  ", client_random, SSL3_RANDOM_SIZE);

    // 2. Server Random
    unsigned char server_random[SSL3_RANDOM_SIZE];
    SSL_get_server_random(client->ssl, server_random, SSL3_RANDOM_SIZE);
    hex_dump("Server Random:  ", server_random, SSL3_RANDOM_SIZE);

    // 3. Master Secret (derived from Pre-Master Secret, Client/Server Random)
    //    SSL_export_keying_material can be used to export various secrets.
    //    For master_secret, we use "EXPORTER-master secret" label, but it's not strictly standard.
    //    The master secret is stored in the SSL_SESSION.
    //    Let's use SSL_SESSION_get_master_key.
    unsigned char master_key[SSL_MAX_MASTER_KEY_LENGTH];
    size_t master_key_len = SSL_SESSION_get_master_key(SSL_get_session(client->ssl), master_key, sizeof(master_key));
    if (master_key_len > 0) {
        hex_dump("Master Secret:  ", master_key, master_key_len);
    } else {
        fprintf(stderr, "Failed to get Master Secret.\n");
    }

    // 4. Server Certificate Information
    X509 *server_cert = SSL_get_peer_certificate(client->ssl);
    if (server_cert) {
        fprintf(stderr, "Server Certificate:\n");
        X509_NAME *subj = X509_get_subject_name(server_cert);
        if (subj) {
            char *subject_str = X509_NAME_oneline(subj, NULL, 0);
            fprintf(stderr, "  Subject: %s\n", subject_str);
            OPENSSL_free(subject_str);
        }
        X509_NAME *issuer = X509_get_issuer_name(server_cert);
        if (issuer) {
            char *issuer_str = X509_NAME_oneline(issuer, NULL, 0);
            fprintf(stderr, "  Issuer:  %s\n", issuer_str);
            OPENSSL_free(issuer_str);
        }
        EVP_PKEY *pubkey = X509_get0_pubkey(server_cert);
        if (pubkey) {
            fprintf(stderr, "  Public Key Type: %s\n", EVP_PKEY_get0_type_name(pubkey));
            fprintf(stderr, "  Public Key Bits: %d\n", EVP_PKEY_get_bits(pubkey));
        }

        // Verify result (server certificate chain validation status)
        long verify_result = SSL_get_verify_result(client->ssl);
        if (verify_result == X509_V_OK) {
            fprintf(stderr, "  Certificate Verification: OK\n");
        } else {
            fprintf(stderr, "  Certificate Verification: FAILED (%s)\n", X509_verify_cert_error_string(verify_result));
        }

        X509_free(server_cert); // Free the reference obtained by SSL_get_peer_certificate
    } else {
        fprintf(stderr, "No server certificate received.\n");
    }

    fprintf(stderr, "--------------------------------\n");

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
