#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../params.h"
#include "../vcserpent/SerpentFast.h" 
#include "../pbkdf2/pbkdf2.h"
#include "../rand/rand.h"
#include "../core/crypto_mode_sloth.h"
#include "../core/utils_sloth.h"

static void increment_counter(uint8_t counter[16]) {
	for (int i = 15; i >= 12; i--) {
		if (++counter[i] != 0) {
			break;
		}
	}
}

// 安全封装的大端写入宏
static inline void store64_be(uint8_t out[8], uint64_t val) {
	for (int i = 0; i < 8; i++) {
		out[i] = (uint8_t)(val >> (56 - 8 * i));
	}
}

// 安全获取比特位（明确大端位序，MSB first）
static inline int get_bit_be(const uint8_t* data, int bit_index) {
	uint8_t byte = data[bit_index / 8];
	int bit_offset = 7 - (bit_index % 8);  // MSB first
	return (byte >> bit_offset) & 1;
}

// Galois 乘法（GF(2^128)）安全版
static void galois_mult(const uint8_t* X, const uint8_t* Y, uint8_t* result) {
	memset(result, 0, BLOCK_SIZE_SLOTH);
	uint8_t Z[BLOCK_SIZE_SLOTH] = { 0 };
	uint8_t V[BLOCK_SIZE_SLOTH];
	memcpy(V, Y, BLOCK_SIZE_SLOTH);

	for (int i = 0; i < 128; i++) {
		if (get_bit_be(X, i)) {
			for (int j = 0; j < BLOCK_SIZE_SLOTH; j++) {
				Z[j] ^= V[j];
			}
		}

		uint8_t carry = V[15] & 1;
		for (int j = 15; j > 0; j--) {
			V[j] = (V[j] >> 1) | (V[j - 1] << 7);
		}
		V[0] >>= 1;

		if (carry) {
			V[0] ^= 0xE1;
		}
	}
	memcpy(result, Z, BLOCK_SIZE_SLOTH);
}

// GHASH（加固长度处理）
static void ghash(const uint8_t* H, const uint8_t* data, size_t length, uint8_t* tag) {
	uint8_t Y[BLOCK_SIZE_SLOTH] = { 0 };
	uint8_t temp[BLOCK_SIZE_SLOTH];
	uint8_t block[BLOCK_SIZE_SLOTH];

	for (size_t i = 0; i < length; i += BLOCK_SIZE_SLOTH) {
		memset(block, 0, BLOCK_SIZE_SLOTH);
		size_t chunk = (length - i >= BLOCK_SIZE_SLOTH) ? BLOCK_SIZE_SLOTH : (length - i);
		memcpy(block, data + i, chunk);

		for (int j = 0; j < BLOCK_SIZE_SLOTH; j++) {
			Y[j] ^= block[j];
		}
		galois_mult(Y, H, temp);
		memcpy(Y, temp, BLOCK_SIZE_SLOTH);
	}

	// 添加长度字段（大端格式，平台无关）
	uint8_t len_block[BLOCK_SIZE_SLOTH] = { 0 };
	uint64_t aad_bitlen = 0;  // AAD 为 0
	uint64_t ciphertext_bitlen = ((uint64_t)length) * 8;

	store64_be(len_block, aad_bitlen);                 // 前 8 字节
	store64_be(len_block + 8, ciphertext_bitlen);      // 后 8 字节

	for (int j = 0; j < BLOCK_SIZE_SLOTH; j++) {
		Y[j] ^= len_block[j];
	}
	galois_mult(Y, H, temp);
	memcpy(tag, temp, BLOCK_SIZE_SLOTH);
}


// GCM 加密
void gcm_encrypt_sloth(const uint8_t* data, size_t length, const uint8_t* key, const uint8_t* iv, uint8_t* tag, uint8_t* encrypted_data) {
	if (!data || !key || !iv || !tag || !encrypted_data) return;

	uint8_t ks[SERPENT_KSSIZE_SLOTH];
	serpent_set_key(key, ks);

	uint8_t counter[BLOCK_SIZE_SLOTH] = { 0 };
	uint8_t tag_counter[BLOCK_SIZE_SLOTH];
	uint8_t keystream[BLOCK_SIZE_SLOTH];
	uint8_t H[BLOCK_SIZE_SLOTH] = { 0 };
	uint8_t zero_block[BLOCK_SIZE_SLOTH] = { 0 };

	memcpy(counter, iv, NONCE_SIZE_SLOTH);
	memset(counter + NONCE_SIZE_SLOTH, 0, 4);
	counter[15] = 1;
	memcpy(tag_counter, counter, BLOCK_SIZE_SLOTH);

	serpent_encrypt(zero_block, H, ks);

	for (size_t i = 0; i < length; i += BLOCK_SIZE_SLOTH) {
		increment_counter(counter);
		serpent_encrypt(counter, keystream, ks);
		size_t chunk = (length - i >= BLOCK_SIZE_SLOTH) ? BLOCK_SIZE_SLOTH : (length - i);
		for (size_t j = 0; j < chunk; j++) {
			encrypted_data[i + j] = data[i + j] ^ keystream[j];
		}
	}

	uint8_t S[BLOCK_SIZE_SLOTH];
	ghash(H, encrypted_data, length, S);

	serpent_encrypt(tag_counter, keystream, ks);
	for (int i = 0; i < BLOCK_SIZE_SLOTH; i++) {
		tag[i] = keystream[i] ^ S[i];
	}
}

// GCM 解密
int gcm_decrypt_sloth(uint8_t* data, size_t length, const uint8_t* key, const uint8_t* iv, const uint8_t* tag) {
	if (!data || !key || !iv || !tag) return -1;

	uint8_t ks[SERPENT_KSSIZE_SLOTH];
	serpent_set_key(key, ks);

	uint8_t counter[BLOCK_SIZE_SLOTH] = { 0 };
	uint8_t tag_counter[BLOCK_SIZE_SLOTH];
	uint8_t keystream[BLOCK_SIZE_SLOTH];
	uint8_t H[BLOCK_SIZE_SLOTH];
	uint8_t zero_block[BLOCK_SIZE_SLOTH] = { 0 };

	memcpy(counter, iv, NONCE_SIZE_SLOTH);
	memset(counter + NONCE_SIZE_SLOTH, 0, 4);
	counter[15] = 1;
	memcpy(tag_counter, counter, BLOCK_SIZE_SLOTH);

	serpent_encrypt(zero_block, H, ks);

	uint8_t S[BLOCK_SIZE_SLOTH], expected_tag[BLOCK_SIZE_SLOTH];
	ghash(H, data, length, S);
	serpent_encrypt(tag_counter, keystream, ks);
	for (int i = 0; i < BLOCK_SIZE_SLOTH; i++) {
		expected_tag[i] = keystream[i] ^ S[i];
	}
	if (!constant_time_compare_sloth(expected_tag, tag, TAG_SIZE_SLOTH)) {
		return -1;
	}

	for (size_t i = 0; i < length; i += BLOCK_SIZE_SLOTH) {
		increment_counter(counter);
		serpent_encrypt(counter, keystream, ks);
		size_t chunk = (length - i >= BLOCK_SIZE_SLOTH) ? BLOCK_SIZE_SLOTH : (length - i);
		for (size_t j = 0; j < chunk; j++) {
			data[i + j] ^= keystream[j];
		}
	}
	return 0;
}
