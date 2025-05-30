#ifndef CRYPTO_MODE_SLOTH_H
#define CRYPTO_MODE_SLOTH_H

#include <stddef.h>
#include <stdint.h>
#include "../params.h"

typedef void (*block_cipher_fn)(const uint8_t *input, uint8_t *output, const uint8_t *ks);

typedef struct {
    block_cipher_fn block_encrypt;
    block_cipher_fn block_decrypt;
    uint8_t ks1[SERPENT_KSSIZE_SLOTH];
    uint8_t ks2[SERPENT_KSSIZE_SLOTH];
    size_t key_length;
} XTS_CTX;

#ifdef __cplusplus
extern "C" {
#endif

// GCM Encryption Function
void gcm_encrypt_sloth(const uint8_t* data, size_t length, const uint8_t* key, const uint8_t* iv, uint8_t* tag, uint8_t* encrypted_data);

// GCM Decryption Function
int gcm_decrypt_sloth(uint8_t* data, size_t length, const uint8_t* key, const uint8_t* iv, const uint8_t* tag);

// CTR Enc
void ctr_encrypt_sloth(const uint8_t* data, size_t length, const uint8_t* key, uint64_t offset_bytes, uint8_t* encrypted_data, const uint8_t* ks, const uint8_t* nonce);

// CTR Dec
void ctr_decrypt_sloth(uint8_t* data, size_t length, const uint8_t* key, uint64_t block_offset, const uint8_t* ks, const uint8_t* nonce);

// KDF Wrapper for FUSE using
void sloth_kdf(const char* password, const unsigned char* salt, unsigned char* out_key);

int xts_enc_sloth(const uint8_t key1[], const uint8_t key2[], const uint8_t plain[], size_t len, uint8_t ciphertext[], int sec_size, int sec_num);

// int xts_dec_sloth(const uint8_t key1[], const uint8_t key2[], const uint8_t ciphertext[], uint8_t *decrypted[]);
void serpent_encrypt_fn(const uint8_t *in, uint8_t *out, const uint8_t *ks);
void serpent_decrypt_fn(const uint8_t *in, uint8_t *out, const uint8_t *ks);
void xts_encrypt(XTS_CTX *ctx, const uint8_t *input, uint8_t *output, size_t length, uint64_t sector_number, size_t sector_size);

void xts_decrypt(XTS_CTX *ctx, const uint8_t *input, uint8_t *output, size_t length, uint64_t sector_number, size_t sector_size);
#ifdef __cplusplus
}
#endif

#endif // CRYPTO_MODE_SLOTH_H
