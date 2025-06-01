#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../params.h"
#include "../vcserpent/SerpentFast.h" 
#include "../pbkdf2/pbkdf2.h"
#include "../rand/rand.h"
#include "../core/crypto_mode_sloth.h"
#include "../core/utils_sloth.h"
#include "utils_sloth.h"
static void increment_counter(uint8_t counter[16]) {
	for (int i = 15; i >= 12; i--) {
		if (++counter[i] != 0) {
			break;
		}
	}
}

// Big endian Writtting Macro
static inline void store64_be(uint8_t out[8], uint64_t val) {
	for (int i = 0; i < 8; i++) {
		out[i] = (uint8_t)(val >> (56 - 8 * i));
	}
}

// MSB first get Bit
static inline int get_bit_be(const uint8_t* data, int bit_index) {
	uint8_t byte = data[bit_index / 8];
	int bit_offset = 7 - (bit_index % 8);  // MSB first
	return (byte >> bit_offset) & 1;
}

// Galois Mul (GF(2^128))
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

// GHASH Compute
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

	// Add Length (Big Endian)
	uint8_t len_block[BLOCK_SIZE_SLOTH] = { 0 };
	uint64_t aad_bitlen = 0;  // AAD is 0
	uint64_t ciphertext_bitlen = ((uint64_t)length) * 8;

	store64_be(len_block, aad_bitlen);                 // Before 8 Bytes
	store64_be(len_block + 8, ciphertext_bitlen);      // After 8 Bytes 

	for (int j = 0; j < BLOCK_SIZE_SLOTH; j++) {
		Y[j] ^= len_block[j];
	}
	galois_mult(Y, H, temp);
	memcpy(tag, temp, BLOCK_SIZE_SLOTH);

	secure_memzero_sloth(temp, BLOCK_SIZE_SLOTH);
	secure_memzero_sloth(block, BLOCK_SIZE_SLOTH);
	secure_memzero_sloth(len_block, BLOCK_SIZE_SLOTH);
	secure_memzero_sloth(Y, BLOCK_SIZE_SLOTH);
}


// GCM Encryption Function
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
	secure_memzero_sloth(keystream, BLOCK_SIZE_SLOTH);
	secure_memzero_sloth(H, BLOCK_SIZE_SLOTH);
	secure_memzero_sloth(counter, BLOCK_SIZE_SLOTH);

}

// GCM Decryption Function
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
	secure_memzero_sloth(keystream, BLOCK_SIZE_SLOTH);
	secure_memzero_sloth(H, BLOCK_SIZE_SLOTH);
	secure_memzero_sloth(counter, BLOCK_SIZE_SLOTH);

	return 0;
}
void ctr_encrypt_sloth(const uint8_t* data, size_t length, const uint8_t* key, uint64_t offset_bytes, uint8_t* encrypted_data, const uint8_t* ks, const uint8_t* nonce) {
	if (!data || !key || !encrypted_data || !ks || !nonce) return;
	//fprintf(stderr, "[ctr_encrypt_sloth] key=%02x%02x%02x...\n",key[0],key[1],key[2]);
	//printf(user_password);
	//printf("\n");

	uint8_t counter[BLOCK_SIZE_SLOTH];
	uint8_t keystream[BLOCK_SIZE_SLOTH];
	size_t i = 0;

	while (i < length) {
		uint64_t block_index = (offset_bytes + i) / BLOCK_SIZE_SLOTH;
		size_t block_offset = (offset_bytes + i) % BLOCK_SIZE_SLOTH;

		// Get counter
		memcpy(counter, nonce, NONCE_SIZE_SLOTH);
		counter[12] = (block_index >> 24) & 0xFF;
		counter[13] = (block_index >> 16) & 0xFF;
		counter[14] = (block_index >> 8) & 0xFF;
		counter[15] = (block_index >> 0) & 0xFF;

		serpent_encrypt(counter, keystream, ks);

		size_t chunk = BLOCK_SIZE_SLOTH - block_offset;
		if (chunk > length - i) chunk = length - i;

		for (size_t j = 0; j < chunk; j++) {
			encrypted_data[i] = data[i] ^ keystream[block_offset + j];
			i++;
		}
	}
}

void ctr_decrypt_sloth(uint8_t* data, size_t length, const uint8_t* key, uint64_t block_offset, const uint8_t* ks, const uint8_t* nonce) {
	ctr_encrypt_sloth(data, length, key, block_offset, data, ks, nonce);
}

void sloth_kdf(const char* password, const unsigned char* salt, unsigned char* out_key) {
	const int iterations = ITERATIONS_SLOTH;
	PBKDF2_HMAC_Whirlpool(
		(const uint8_t*)password, strlen(password),
		salt, 16,
		iterations,
		KEY_SIZE_SLOTH,
		out_key
	);
}

//XTS Implementation

static void xts_mul_alpha(uint8_t *tweak) {
    uint8_t carry_in = 0, carry_out;
    for (int i = 0; i < BLOCK_SIZE_SLOTH; i++) {
        carry_out = tweak[i] >> 7;
        tweak[i] = (tweak[i] << 1) | carry_in;
        carry_in = carry_out;
    }
    if (carry_in) {
        tweak[0] ^= 0x87;
    }
}


static void xts_generate_tweak(XTS_CTX *ctx, uint64_t sector_number, uint8_t *tweak) {
    uint8_t sector_buf[BLOCK_SIZE_SLOTH] = {0};
    for (int i = 0; i < 8; i++) {
        sector_buf[i] = (sector_number >> (i * 8)) & 0xFF;
    }
    ctx->block_encrypt(sector_buf, tweak, ctx->ks2);
}

void xts_encrypt(XTS_CTX *ctx, const uint8_t *input, uint8_t *output, 
                 size_t length, uint64_t sector_number, uint64_t sector_size) {
    if (length == 0) return;

    uint8_t tweak[BLOCK_SIZE_SLOTH], pp[BLOCK_SIZE_SLOTH], cc[BLOCK_SIZE_SLOTH];
    size_t i, j, blocks = length / BLOCK_SIZE_SLOTH;
    size_t last_len = length % BLOCK_SIZE_SLOTH;

    xts_generate_tweak(ctx, sector_number, tweak);

    // Normal Blocks
    for (i = 0; i < blocks; i++) {
        for (j = 0; j < BLOCK_SIZE_SLOTH; j++) {
            pp[j] = input[i * BLOCK_SIZE_SLOTH + j] ^ tweak[j];
        }
        ctx->block_encrypt(pp, cc, ctx->ks1);
        for (j = 0; j < BLOCK_SIZE_SLOTH; j++) {
            output[i * BLOCK_SIZE_SLOTH + j] = cc[j] ^ tweak[j];
        }
        xts_mul_alpha(tweak);
    }

    // partial block
    if (last_len) {
        uint8_t final_tweak[BLOCK_SIZE_SLOTH];
        memcpy(final_tweak, tweak, BLOCK_SIZE_SLOTH);  // Save current tweak
        xts_mul_alpha(final_tweak);                    // final tweak = tweak * α

        // Last two
        uint8_t c_full[BLOCK_SIZE_SLOTH];
        const uint8_t *last_full_block = input + (blocks - 1) * BLOCK_SIZE_SLOTH;
        for (j = 0; j < BLOCK_SIZE_SLOTH; j++) {
            pp[j] = last_full_block[j] ^ tweak[j];
        }
        ctx->block_encrypt(pp, cc, ctx->ks1);
        for (j = 0; j < BLOCK_SIZE_SLOTH; j++) {
            c_full[j] = cc[j] ^ tweak[j];
        }

        // c_full to partial block cipher
        memcpy(output + blocks * BLOCK_SIZE_SLOTH, c_full, last_len);

        // Process partial block
        uint8_t last_block[BLOCK_SIZE_SLOTH] = {0};
        memcpy(last_block, input + blocks * BLOCK_SIZE_SLOTH, last_len);
        memcpy(last_block + last_len, c_full + last_len, BLOCK_SIZE_SLOTH - last_len);

        
        for (j = 0; j < BLOCK_SIZE_SLOTH; j++) {
            pp[j] = last_block[j] ^ final_tweak[j];
        }
        ctx->block_encrypt(pp, cc, ctx->ks1);
        for (j = 0; j < BLOCK_SIZE_SLOTH; j++) {
            cc[j] ^= final_tweak[j];
        }

        // Output
        memcpy(output + (blocks - 1) * BLOCK_SIZE_SLOTH, cc, BLOCK_SIZE_SLOTH);
    }
}

void xts_decrypt(XTS_CTX *ctx, const uint8_t *input, uint8_t *output,
                 size_t length, uint64_t sector_number, uint64_t sector_size) {
    if (length == 0) return;

    uint8_t tweak[BLOCK_SIZE_SLOTH], pp[BLOCK_SIZE_SLOTH], cc[BLOCK_SIZE_SLOTH];
    size_t i, j, blocks = length / BLOCK_SIZE_SLOTH;
    size_t last_len = length % BLOCK_SIZE_SLOTH;

    xts_generate_tweak(ctx, sector_number, tweak);

    // If partial block, remain later to process, process N-1 blocks first
    if (last_len && blocks >= 1) {
        blocks -= 1;
    }

    // Normal decryption
    for (i = 0; i < blocks; i++) {
        for (j = 0; j < BLOCK_SIZE_SLOTH; j++) {
            cc[j] = input[i * BLOCK_SIZE_SLOTH + j] ^ tweak[j];
        }
        ctx->block_decrypt(cc, pp, ctx->ks1);
        for (j = 0; j < BLOCK_SIZE_SLOTH; j++) {
            output[i * BLOCK_SIZE_SLOTH + j] = pp[j] ^ tweak[j];
        }
        xts_mul_alpha(tweak);
    }

    // Process CTS
    if (last_len) {
        uint8_t final_tweak[BLOCK_SIZE_SLOTH];
        memcpy(final_tweak, tweak, BLOCK_SIZE_SLOTH);  // Save current tweak
        xts_mul_alpha(final_tweak);                    // final_tweak = tweak * α

        // cc = Cn
        const uint8_t *cn = input + blocks * BLOCK_SIZE_SLOTH;
        for (j = 0; j < BLOCK_SIZE_SLOTH; j++) {
            cc[j] = cn[j] ^ final_tweak[j];
        }
        ctx->block_decrypt(cc, pp, ctx->ks1);
        for (j = 0; j < BLOCK_SIZE_SLOTH; j++) {
            pp[j] ^= final_tweak[j];
        }

        // output last
        memcpy(output + (blocks + 1) * BLOCK_SIZE_SLOTH, pp, last_len);

        // To recover last two
        uint8_t c_full[BLOCK_SIZE_SLOTH];
        memcpy(c_full, cn, last_len);  // last_len From Cn
        memcpy(c_full + last_len, input + blocks * BLOCK_SIZE_SLOTH + last_len,
               BLOCK_SIZE_SLOTH - last_len); // Last half from Cn-1 last

        for (j = 0; j < BLOCK_SIZE_SLOTH; j++) {
            cc[j] = c_full[j] ^ tweak[j];
        }
        ctx->block_decrypt(cc, pp, ctx->ks1);
        for (j = 0; j < BLOCK_SIZE_SLOTH; j++) {
            pp[j] ^= tweak[j];
        }

        // Recover last two
        memcpy(output + blocks * BLOCK_SIZE_SLOTH, pp, BLOCK_SIZE_SLOTH);
    }
}

void xts_init(XTS_CTX *ctx, block_cipher_fn encrypt_fn, block_cipher_fn decrypt_fn, 
              const uint8_t *key1, const uint8_t *key2, size_t key_schedule_size) {
    ctx->block_encrypt = encrypt_fn;
    ctx->block_decrypt = decrypt_fn;
    memcpy(ctx->ks1, key1, key_schedule_size);
    memcpy(ctx->ks2, key2, key_schedule_size);
    ctx->key_length = key_schedule_size;
}

void serpent_encrypt_fn(const uint8_t *in, uint8_t *out, const uint8_t *ks) {
    serpent_encrypt(in, out, (uint8_t *)ks);
}

void serpent_decrypt_fn(const uint8_t *in, uint8_t *out, const uint8_t *ks) {
    serpent_decrypt(in, out, (uint8_t *)ks);
}

int xts_enc_sloth(const uint8_t key1[], const uint8_t key2[], const uint8_t plain[], size_t len, uint8_t ciphertext[], uint64_t sec_size, uint64_t sec_num) {
    XTS_CTX ctx;
    uint8_t ks1[SERPENT_KSSIZE_SLOTH];
    uint8_t ks2[SERPENT_KSSIZE_SLOTH];

    serpent_set_key(key1, ks1);
    serpent_set_key(key2, ks2);

    xts_init(&ctx, serpent_encrypt_fn, serpent_decrypt_fn, ks1, ks2, SERPENT_KSSIZE_SLOTH);
    xts_encrypt(&ctx, plain, ciphertext, len, sec_num, sec_size);

    return 0;
}

