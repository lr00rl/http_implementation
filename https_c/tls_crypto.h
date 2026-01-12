#ifndef TLS_CRYPTO_H
#define TLS_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// SHA256
void sha256(const uint8_t *data, size_t len, uint8_t *hash);

// HMAC-SHA256
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out);

// AES-128-CBC
void aes_128_cbc_encrypt(const uint8_t *key, const uint8_t *iv,
                         const uint8_t *in, size_t len, uint8_t *out);
void aes_128_cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                         const uint8_t *in, size_t len, uint8_t *out);

// AES-128-GCM
int aes_128_gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *in, size_t in_len,
                        uint8_t *out, uint8_t *tag);
int aes_128_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *in, size_t in_len,
                        const uint8_t *tag, uint8_t *out);

// Random bytes
void get_random_bytes(uint8_t *buf, size_t len);

#endif
