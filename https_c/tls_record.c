#include "tls_record.h"
#include "tls_crypto.h"
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>

void tls_record_init(tls_record_state_t *state) {
    memset(state, 0, sizeof(*state));
    state->encrypted = 0;
}

static int send_all(int sock, const uint8_t *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(sock, data + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

static int recv_all(int sock, uint8_t *data, size_t len) {
    size_t received = 0;
    while (received < len) {
        int n = recv(sock, data + received, len - received, 0);
        if (n <= 0) return -1;
        received += n;
    }
    return 0;
}

int tls_record_send(int sock, tls_record_state_t *state,
                    uint8_t content_type, const uint8_t *data, size_t len) {
    uint8_t record[16384];
    size_t record_len = 0;

    if (!state->encrypted) {
        // Unencrypted record
        record[0] = content_type;
        record[1] = (TLS_VERSION_1_2 >> 8) & 0xff;
        record[2] = TLS_VERSION_1_2 & 0xff;
        record[3] = (len >> 8) & 0xff;
        record[4] = len & 0xff;
        memcpy(record + 5, data, len);
        record_len = 5 + len;
    } else {
        // TLS 1.3 encrypted record
        uint8_t plaintext[16384];
        memcpy(plaintext, data, len);
        plaintext[len] = content_type;

        uint8_t nonce[12];
        memcpy(nonce, state->write_iv, 12);
        for (int i = 0; i < 8; i++) {
            nonce[11 - i] ^= (state->write_seq >> (i * 8)) & 0xff;
        }

        uint8_t aad[5];
        aad[0] = TLS_CONTENT_TYPE_APPLICATION_DATA;
        aad[1] = (TLS_VERSION_1_2 >> 8) & 0xff;
        aad[2] = TLS_VERSION_1_2 & 0xff;
        uint16_t ciphertext_len = len + 1 + 16;
        aad[3] = (ciphertext_len >> 8) & 0xff;
        aad[4] = ciphertext_len & 0xff;

        uint8_t ciphertext[16384];
        uint8_t tag[16];
        aes_128_gcm_encrypt(state->write_key, nonce, 12,
                           aad, 5,
                           plaintext, len + 1,
                           ciphertext, tag);

        record[0] = TLS_CONTENT_TYPE_APPLICATION_DATA;
        record[1] = (TLS_VERSION_1_2 >> 8) & 0xff;
        record[2] = TLS_VERSION_1_2 & 0xff;
        record[3] = (ciphertext_len >> 8) & 0xff;
        record[4] = ciphertext_len & 0xff;
        memcpy(record + 5, ciphertext, len + 1);
        memcpy(record + 5 + len + 1, tag, 16);
        record_len = 5 + len + 1 + 16;

        state->write_seq++;
    }

    return send_all(sock, record, record_len);
}

int tls_record_recv(int sock, tls_record_state_t *state,
                    uint8_t *content_type, uint8_t *data, size_t max_len) {
    uint8_t header[5];
    if (recv_all(sock, header, 5) < 0) {
        return -1;
    }

    *content_type = header[0];
    uint16_t length = (header[3] << 8) | header[4];

    if (length > max_len + 256) {
        return -1;
    }

    uint8_t payload[16384];
    if (recv_all(sock, payload, length) < 0) {
        return -1;
    }

    if (!state->encrypted || *content_type != TLS_CONTENT_TYPE_APPLICATION_DATA) {
        memcpy(data, payload, length);
        return length;
    }

    // TLS 1.3 encrypted record
    uint8_t nonce[12];
    memcpy(nonce, state->read_iv, 12);
    for (int i = 0; i < 8; i++) {
        nonce[11 - i] ^= (state->read_seq >> (i * 8)) & 0xff;
    }

    uint8_t aad[5];
    memcpy(aad, header, 5);

    uint8_t tag[16];
    memcpy(tag, payload + length - 16, 16);

    uint8_t plaintext[16384];
    int plaintext_len = aes_128_gcm_decrypt(state->read_key, nonce, 12,
                                           aad, 5,
                                           payload, length - 16,
                                           tag, plaintext);

    if (plaintext_len < 0) {
        return -1;
    }

    state->read_seq++;

    // Remove content type padding
    while (plaintext_len > 0 && plaintext[plaintext_len - 1] == 0) {
        plaintext_len--;
    }

    if (plaintext_len == 0) {
        return -1;
    }

    *content_type = plaintext[plaintext_len - 1];
    plaintext_len--;

    memcpy(data, plaintext, plaintext_len);
    return plaintext_len;
}
