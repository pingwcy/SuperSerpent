#ifndef CRYPTO_MODE_SLOTH_H
#define CRYPTO_MODE_SLOTH_H

#include <stddef.h>
#include <stdint.h>

// GCM 加密函数
void gcm_encrypt_sloth(const uint8_t* data, size_t length, const uint8_t* key, const uint8_t* iv, uint8_t* tag, uint8_t* encrypted_data);

// GCM 解密函数
int gcm_decrypt_sloth(uint8_t* data, size_t length, const uint8_t* key, const uint8_t* iv, const uint8_t* tag);

// CTR Enc
void ctr_encrypt_sloth(const uint8_t* data, size_t length, const uint8_t* key, uint64_t offset_bytes, uint8_t* encrypted_data, const uint8_t* ks, const uint8_t* nonce);

// CTR Dec
void ctr_decrypt_sloth(uint8_t* data, size_t length, const uint8_t* key, uint64_t block_offset, const uint8_t* ks, const uint8_t* nonce);

// KDF Wrapper for FUSE using
void sloth_kdf(const char* password, const unsigned char* salt, unsigned char* out_key);

#endif // CRYPTO_MODE_SLOTH_H
