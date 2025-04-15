#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../params.h"
#include "../vcserpent/SerpentFast.h" 
#include "../pbkdf2/pbkdf2.h"
#include "../rand/rand.h"
#include "../core/crypto_mode_sloth.h"


// GF(2^128) 乘法（Galois 字段乘法）,for GCM MODE
static void galois_mult(const uint8_t* X, const uint8_t* Y, uint8_t* result) {
	uint8_t Z[16] = { 0 };
	uint8_t V[16];
	memcpy(V, Y, 16);

	for (int i = 0; i < 128; i++) {
		if ((X[i / 8] >> (7 - (i % 8))) & 1) {
			for (int j = 0; j < 16; j++) {
				Z[j] ^= V[j];
			}
		}

		// 右移 V 并处理 GF(2^128) 进位
		uint8_t carry = V[15] & 1;
		for (int j = 15; j > 0; j--) {
			V[j] = (V[j] >> 1) | (V[j - 1] << 7);
		}
		V[0] >>= 1;

		if (carry) {
			V[0] ^= 0xE1;  // 多项式 0xE1
		}
	}
	memcpy(result, Z, 16);
}
// GHASH 计算, for GCM
static void ghash(const uint8_t* H, const uint8_t* data, size_t length, uint8_t* tag) {
	uint8_t Y[16] = { 0 };
	uint8_t temp[16];

	for (size_t i = 0; i < length; i += 16) {
		for (int j = 0; j < 16 && i + j < length; j++) {
			Y[j] ^= data[i + j];
		}
		galois_mult(Y, H, temp);
		memcpy(Y, temp, 16);
	}
	memcpy(tag, Y, 16);
}

// 修正 GCM 加密函数
void gcm_encrypt_sloth(const uint8_t* data, size_t length, const uint8_t* key, uint8_t* iv, uint8_t* tag, uint8_t* encrypted_data) {
	uint8_t ks[SERPENT_KSSIZE_SLOTH];  // Serpent 可能使用较大的密钥调度表
	serpent_set_key(key, ks);  // 初始化密钥调度表

	uint8_t counter[16] = { 0 };  // 计数器，初始化为 0
	uint8_t keystream[16];
	uint8_t H[16] = { 0 };  // H = E(K, 0)

	// 确保 nonce 仅 12 字节，并正确设置计数器
	memcpy(counter, iv, 12);  // 只复制 12 字节
	counter[15] = 1;  // GCM 规范要求从 1 开始

	// 计算 H
	serpent_encrypt(H, H, ks);
	// 加密数据
	for (size_t i = 0; i < length; i += 16) {
		serpent_encrypt(counter, keystream, ks);
		for (size_t j = 0; j < 16 && (i + j) < length; j++) {
			encrypted_data[i + j] = data[i + j] ^ keystream[j];
		}

		// 更新计数器（正确处理溢出）
		for (int j = 15; j >= 0; j--) {
			if (++counter[j]) break;
		}
	}

	// 计算 GHASH 认证标签
	ghash(H, encrypted_data, length, tag);
	serpent_encrypt(tag, tag, ks);
}

// 修正 GCM 解密函数
int gcm_decrypt_sloth(uint8_t* data, size_t length, const uint8_t* key, uint8_t* iv, uint8_t* tag) {
	uint8_t ks[SERPENT_KSSIZE_SLOTH];  // Serpent 可能使用较大的密钥调度表
	serpent_set_key(key, ks);  // 初始化密钥调度表

	uint8_t counter[16] = { 0 };
	uint8_t keystream[16];
	uint8_t H[16] = { 0 };
	uint8_t computed_tag[TAG_SIZE_SLOTH];

	memcpy(counter, iv, NONCE_SIZE_SLOTH);
	counter[15] = 1;

	serpent_encrypt(H, H, ks);
	ghash(H, data, length, computed_tag);
	serpent_encrypt(computed_tag, computed_tag, ks);

	if (memcmp(computed_tag, tag, TAG_SIZE_SLOTH) != 0) {
		return -1;  // 认证失败
	}

	for (size_t i = 0; i < length; i += 16) {
		serpent_encrypt(counter, keystream, ks);
		for (size_t j = 0; j < 16 && (i + j) < length; j++) {
			data[i + j] ^= keystream[j];
		}

		for (int j = 15; j >= 0; j--) {
			if (++counter[j]) break;
		}
	}

	return 0;
}