#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "pbkdf2.h"
#include "whirlpool/misc.h"
#include "whirlpool/Tcdefs.h"
#include "../core/utils_sloth.h"
#include "whirlpool/Whirlpool.h"  //  WHIRLPOOL_* API Define
void HMAC_Whirlpool_Init(HMAC_Whirlpool_CTX* ctx, const uint8_t* key, size_t key_len) {
	uint8_t key_block[BLOCK_SIZE_WHIRLPOOL_SLOTH];
	uint8_t i_key_pad[BLOCK_SIZE_WHIRLPOOL_SLOTH];
	uint8_t hashed_key[OUTPUT_SIZE_SLOTH];

	// Step 1: Hash long key
	if (key_len > BLOCK_SIZE_WHIRLPOOL_SLOTH) {
		WHIRLPOOL_CTX key_ctx;
		WHIRLPOOL_init(&key_ctx);
		WHIRLPOOL_add(key, key_len, &key_ctx);
		WHIRLPOOL_finalize(&key_ctx, hashed_key);
		ct_memcpy_sloth(key_block, hashed_key, OUTPUT_SIZE_SLOTH);
		if (OUTPUT_SIZE_SLOTH < BLOCK_SIZE_WHIRLPOOL_SLOTH) {
			memset(key_block + OUTPUT_SIZE_SLOTH, 0, BLOCK_SIZE_WHIRLPOOL_SLOTH - OUTPUT_SIZE_SLOTH);
		}
		secure_memzero_sloth(&key_ctx, sizeof(key_ctx));
		secure_memzero_sloth(hashed_key, sizeof(hashed_key));
	}
	else {
		ct_memcpy_sloth(key_block, key, key_len);
		if (key_len < BLOCK_SIZE_WHIRLPOOL_SLOTH) {
			memset(key_block + key_len, 0, BLOCK_SIZE_WHIRLPOOL_SLOTH - key_len);
		}
	}

	// Step 2: Create inner and outer pads
	ct_xor_sloth(i_key_pad, key_block, 0x36, BLOCK_SIZE_WHIRLPOOL_SLOTH);
	ct_xor_sloth(ctx->o_key_pad, key_block, 0x5c, BLOCK_SIZE_WHIRLPOOL_SLOTH);

	// Step 3: Start inner hash
	WHIRLPOOL_init(&ctx->inner);
	WHIRLPOOL_add(i_key_pad, BLOCK_SIZE_WHIRLPOOL_SLOTH, &ctx->inner);

	// Zero Memory
	secure_memzero_sloth(i_key_pad, sizeof(i_key_pad));
	secure_memzero_sloth(key_block, sizeof(key_block));

}

void HMAC_Whirlpool_Update(HMAC_Whirlpool_CTX* ctx, const uint8_t* data, size_t len) {
	WHIRLPOOL_add(data, len, &ctx->inner);
}

void HMAC_Whirlpool_Final(HMAC_Whirlpool_CTX* ctx, uint8_t* output) {
	uint8_t inner_hash[OUTPUT_SIZE_SLOTH];

	// Complete Inner Hash
	WHIRLPOOL_finalize(&ctx->inner, inner_hash);

	// Using another CTX for Outter Hash to Avoid Corrouption
	WHIRLPOOL_CTX outer;
	WHIRLPOOL_init(&outer);
	WHIRLPOOL_add(ctx->o_key_pad, BLOCK_SIZE_WHIRLPOOL_SLOTH, &outer);
	WHIRLPOOL_add(inner_hash, OUTPUT_SIZE_SLOTH, &outer);
	WHIRLPOOL_finalize(&outer, output);

	// Zero Memory
	secure_memzero_sloth(inner_hash, sizeof(inner_hash));
	secure_memzero_sloth(&outer, sizeof(outer));

}

// Wrapper to complete HMAC in one step
void HMAC_Whirlpool(
	const uint8_t* key, size_t key_len,
	const uint8_t* message, size_t message_len,
	uint8_t* output)
{
	HMAC_Whirlpool_CTX ctx;

	HMAC_Whirlpool_Init(&ctx, key, key_len);
	HMAC_Whirlpool_Update(&ctx, message, message_len);
	HMAC_Whirlpool_Final(&ctx, output);
	secure_memzero_sloth(&ctx, sizeof(ctx));
}



void PBKDF2_HMAC_Whirlpool(const uint8_t* password, int password_len,
	const uint8_t* salt, int salt_len,
	int iterations, int key_len,
	uint8_t* output) {
	if (iterations == 0 || key_len == 0 || output == NULL) return;

	size_t hash_len = OUTPUT_SIZE_SLOTH;
	size_t block_count = (key_len + hash_len - 1) / hash_len;
	uint8_t U[OUTPUT_SIZE_SLOTH];
	uint8_t T[OUTPUT_SIZE_SLOTH];

	for (uint32_t i = 1; i <= block_count; i++) {
		uint8_t int_block[4];
		int_block[0] = (i >> 24) & 0xFF;
		int_block[1] = (i >> 16) & 0xFF;
		int_block[2] = (i >> 8) & 0xFF;
		int_block[3] = i & 0xFF;

		// Make: salt || INT(i)
		uint8_t* salt_block = (uint8_t*)malloc(salt_len + 4);
		if (!salt_block) {
			fprintf(stderr, "Memory allocation failed\n");
			// Zero Memory to Avoiding Using Incomplete Key
			secure_memzero_sloth(output, key_len);
			return;
		}
		ct_memcpy_sloth(salt_block, salt, salt_len);
		ct_memcpy_sloth(salt_block + salt_len, int_block, 4);

		// U_1 = PRF(password, salt || i)
		HMAC_Whirlpool(password, password_len, salt_block, salt_len + 4, U);
		ct_memcpy_sloth(T, U, hash_len);
		free(salt_block);

		// Then U_j
		for (uint32_t j = 1; j < iterations; j++) {
			HMAC_Whirlpool(password, password_len, U, hash_len, U);
			for (size_t k = 0; k < hash_len; k++) {
				T[k] ^= U[k];
			}
		}

		// Output block
		size_t offset = (i - 1) * hash_len;
		size_t copy_len = (key_len - offset > hash_len) ? hash_len : (key_len - offset);
		ct_memcpy_sloth(output + offset, T, copy_len);

		secure_memzero_sloth(U, sizeof(U));
		secure_memzero_sloth(T, sizeof(T));
	}
}


// Test Function
/*
int main() {
	unsigned char password[] = "password";
	unsigned char salt[] = "salt";
	int iterations = 1000;
	int key_len = 32; 
	unsigned char output[64];

	PBKDF2_HMAC_Whirlpool(password, strlen((char*)password),
						  salt, strlen((char*)salt),
						  iterations, key_len, output);

	
	printf("Derived Key: ");
	for (int i = 0; i < key_len; i++) {
		printf("%02x", output[i]);
	}
	printf("\n");

	return 0;
}
*/