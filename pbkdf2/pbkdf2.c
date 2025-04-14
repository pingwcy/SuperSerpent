#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "pbkdf2.h"
#include "whirlpool/Whirlpool.h"  // 假设 WHIRLPOOL_* API 定义在这个头文件中

void HMAC_Whirlpool_Init(HMAC_Whirlpool_CTX* ctx, const uint8_t* key, size_t key_len) {
	uint8_t key_block[BLOCK_SIZE_WHIRLPOOL_SLOTH];
	uint8_t i_key_pad[BLOCK_SIZE_WHIRLPOOL_SLOTH];
	int i;

	// Step 1: 处理 key
	if (key_len > BLOCK_SIZE_WHIRLPOOL_SLOTH) {
		WHIRLPOOL_CTX key_ctx;
		WHIRLPOOL_init(&key_ctx);
		WHIRLPOOL_add(key, key_len, &key_ctx);
		WHIRLPOOL_finalize(&key_ctx, key_block);
		memset(key_block + OUTPUT_SIZE_SLOTH, 0, BLOCK_SIZE_WHIRLPOOL_SLOTH - OUTPUT_SIZE_SLOTH);
	}
	else {
		memcpy(key_block, key, key_len);
		memset(key_block + key_len, 0, BLOCK_SIZE_WHIRLPOOL_SLOTH - key_len);
	}

	// Step 2: 创建 i_key_pad 和 o_key_pad
	for (i = 0; i < BLOCK_SIZE_WHIRLPOOL_SLOTH; i++) {
		i_key_pad[i] = key_block[i] ^ 0x36;
		ctx->o_key_pad[i] = key_block[i] ^ 0x5c;
	}

	// Step 3: 初始化内部哈希
	WHIRLPOOL_init(&ctx->inner);
	WHIRLPOOL_add(i_key_pad, BLOCK_SIZE_WHIRLPOOL_SLOTH, &ctx->inner);
}

void HMAC_Whirlpool_Update(HMAC_Whirlpool_CTX* ctx, const uint8_t* data, size_t len) {
	WHIRLPOOL_add(data, len, &ctx->inner);
}

void HMAC_Whirlpool_Final(HMAC_Whirlpool_CTX* ctx, uint8_t* output) {
	uint8_t inner_hash[OUTPUT_SIZE_SLOTH];

	// Step 1: 完成内部哈希
	WHIRLPOOL_finalize(&ctx->inner, inner_hash);

	// Step 2: 初始化外部哈希
	WHIRLPOOL_init(&ctx->outer);
	WHIRLPOOL_add(ctx->o_key_pad, BLOCK_SIZE_WHIRLPOOL_SLOTH, &ctx->outer);
	WHIRLPOOL_add(inner_hash, OUTPUT_SIZE_SLOTH, &ctx->outer);
	WHIRLPOOL_finalize(&ctx->outer, output);
}

// 包装器：一步式 HMAC（调用三段式）
void HMAC_Whirlpool(
	const uint8_t* key, size_t key_len,
	const uint8_t* message, size_t message_len,
	uint8_t* output)
{
	HMAC_Whirlpool_CTX ctx;

	HMAC_Whirlpool_Init(&ctx, key, key_len);
	HMAC_Whirlpool_Update(&ctx, message, message_len);
	HMAC_Whirlpool_Final(&ctx, output);
}



void PBKDF2_HMAC_Whirlpool(const uint8_t* password, int password_len,
	const uint8_t* salt, int salt_len,
	int iterations, int key_len,
	uint8_t* output) {
	int hash_len = OUTPUT_SIZE_SLOTH;
	int block_count = (key_len + hash_len - 1) / hash_len; // 计算需要多少块
	uint8_t U[OUTPUT_SIZE_SLOTH], T[OUTPUT_SIZE_SLOTH];

	for (int i = 1; i <= block_count; i++) {
		// 动态分配 salt_block，避免固定大小问题
		uint8_t* salt_block = (uint8_t*)malloc(salt_len + 4);
		if (!salt_block) {
			fprintf(stderr, "Memory allocation failed\n");
			return;
		}

		memcpy(salt_block, salt, salt_len);
		salt_block[salt_len] = (i >> 24) & 0xFF;
		salt_block[salt_len + 1] = (i >> 16) & 0xFF;
		salt_block[salt_len + 2] = (i >> 8) & 0xFF;
		salt_block[salt_len + 3] = i & 0xFF;

		// 计算 U1 = HMAC(password, salt || i)
		HMAC_Whirlpool(password, password_len, salt_block, salt_len + 4, U);
		memcpy(T, U, hash_len);

		free(salt_block);  // 释放 salt_block

		// 进行 iterations-1 次迭代
		for (int j = 1; j < iterations; j++) {
			HMAC_Whirlpool(password, password_len, U, hash_len, U);
			for (int k = 0; k < hash_len; k++) {
				T[k] ^= U[k]; // T = T ⊕ Uj
			}
		}

		// 复制 T 到输出
		int offset = (i - 1) * hash_len;
		int copy_len = (key_len - offset > hash_len) ? hash_len : (key_len - offset);
		memcpy(output + offset, T, copy_len);
		memset(U, 0, sizeof(U));
		memset(T, 0, sizeof(T));

	}
}

// 测试函数
/*
int main() {
	unsigned char password[] = "password";
	unsigned char salt[] = "salt";
	int iterations = 1000;
	int key_len = 32; // 这里可以选择更大
	unsigned char output[64];

	PBKDF2_HMAC_Whirlpool(password, strlen((char*)password),
						  salt, strlen((char*)salt),
						  iterations, key_len, output);

	// 打印密钥
	printf("Derived Key: ");
	for (int i = 0; i < key_len; i++) {
		printf("%02x", output[i]);
	}
	printf("\n");

	return 0;
}
*/