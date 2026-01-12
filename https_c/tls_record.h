#ifndef TLS_RECORD_H
#define TLS_RECORD_H

#include <stdint.h>
#include <stddef.h>

// TLS Content Types
#define TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC 20
#define TLS_CONTENT_TYPE_ALERT              21
#define TLS_CONTENT_TYPE_HANDSHAKE          22
#define TLS_CONTENT_TYPE_APPLICATION_DATA   23

// TLS Versions
#define TLS_VERSION_1_2  0x0303
#define TLS_VERSION_1_3  0x0304

// TLS Record header
typedef struct {
    uint8_t content_type;
    uint16_t version;
    uint16_t length;
} __attribute__((packed)) tls_record_header_t;

typedef struct {
    uint8_t write_key[32];
    uint8_t write_iv[12];
    uint8_t read_key[32];
    uint8_t read_iv[12];
    uint64_t write_seq;
    uint64_t read_seq;
    int cipher_suite;
    int encrypted;
} tls_record_state_t;

void tls_record_init(tls_record_state_t *state);

int tls_record_send(int sock, tls_record_state_t *state,
                    uint8_t content_type, const uint8_t *data, size_t len);

int tls_record_recv(int sock, tls_record_state_t *state,
                    uint8_t *content_type, uint8_t *data, size_t max_len);

#endif
