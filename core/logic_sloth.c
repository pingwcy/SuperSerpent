#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "logic_sloth.h"
#include "../pbkdf2/whirlpool/Whirlpool.h"
#include "../params.h"
#include "../vcserpent/SerpentFast.h" 
#include "../pbkdf2/pbkdf2.h"
#include "../rand/rand.h"
#include "utils_sloth.h"
#include "crypto_mode_sloth.h"

int enc_sloth(int mode) {
	uint8_t salt[SALT_SIZE_SLOTH], derived_key[KEY_SIZE_SLOTH];
	char password[PWD_MAX_LENGTH_SLOTH], plaintext[PLAINTEXT_MAX_LENGTH_SLOTH];
	size_t plaintext_len;

	if (get_user_input("Please enter password: ", password, sizeof(password)) != 0) {
		return 1;
	}
	if (get_user_input("Please enter plaintext: ", plaintext, sizeof(plaintext)) != 0) {
		secure_memzero_sloth(password, sizeof(password));
		return 1;
	}
	plaintext_len = strlen(plaintext);

	//printf("Password: %s\n", password);
	if (secure_random(salt, sizeof(salt)) != 0) {
		secure_memzero_sloth(password, sizeof(password));
		fprintf(stderr, "Failed to generate salt.\n");
		return 1;
	}
	print_hex_sloth("Salt", salt, sizeof(salt));

	if (mode == 0) {
		uint8_t master_key[KEY_SIZE_SLOTH + HMAC_WHIRLPOOL_KEY_SIZE_SLOTH], hmac_key[HMAC_WHIRLPOOL_KEY_SIZE_SLOTH], iv[IV_SIZE_SLOTH], ks[SERPENT_KSSIZE_SLOTH], hmac_output[64];
		unsigned char padded_text[PADDEDTEXT_MAX_LENGTH_SLOTH];
		size_t padded_len;


		if (secure_random(iv, sizeof(iv)) != 0) {
			secure_memzero_sloth(password, sizeof(password));
			fprintf(stderr, "Failed to generate IV.\n");
			return 1;
		}
		print_hex_sloth("IV", iv, sizeof(iv));

		padded_len = pkcs7_pad_sloth((unsigned char*)plaintext, plaintext_len, padded_text);

		if (!padded_len) {
			secure_memzero_sloth(password, sizeof(password));
			fprintf(stderr, "Padding error.\n");
			return 1;
		}
		print_hex_sloth("Padded text", padded_text, padded_len);

		PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS_SLOTH, sizeof(master_key), master_key);
		memcpy(derived_key, master_key, KEY_SIZE_SLOTH);
		memcpy(hmac_key, master_key + KEY_SIZE_SLOTH, HMAC_WHIRLPOOL_KEY_SIZE_SLOTH);
		print_hex_sloth("derived_key", derived_key, sizeof(derived_key));
		print_hex_sloth("hmac_key", hmac_key, sizeof(hmac_key));

		serpent_set_key(derived_key, ks);

		unsigned char* ciphertext = (unsigned char*)malloc(padded_len);
		if (!ciphertext) {
			secure_memzero_sloth(master_key, sizeof(master_key));
			secure_memzero_sloth(derived_key, sizeof(derived_key));
			secure_memzero_sloth(hmac_key, sizeof(hmac_key));
			secure_memzero_sloth(iv, sizeof(iv));
			secure_memzero_sloth(ks, sizeof(ks));
			secure_memzero_sloth(padded_text, sizeof(padded_text));
			secure_memzero_sloth(password, sizeof(password));
			fprintf(stderr, "Memory allocation failed for ciphertext.\n");
			return 1;
		}

		unsigned char block[BLOCK_SIZE_SLOTH];
		unsigned char* prev_cipher = iv;

		for (size_t i = 0; i < padded_len; i += BLOCK_SIZE_SLOTH) {
			for (size_t j = 0; j < BLOCK_SIZE_SLOTH; j++) {
				block[j] = padded_text[i + j] ^ prev_cipher[j];
			}
			print_hex_sloth("Block", block, sizeof(block));
			serpent_encrypt(block, ciphertext + i, ks);
			prev_cipher = ciphertext + i;
		}

		size_t data_to_auth_len = sizeof(salt) + sizeof(iv) + padded_len;
		unsigned char* data_to_auth = (unsigned char*)malloc(data_to_auth_len);
		if (!data_to_auth) {
			secure_memzero_sloth(master_key, sizeof(master_key));
			secure_memzero_sloth(derived_key, sizeof(derived_key));
			secure_memzero_sloth(hmac_key, sizeof(hmac_key));
			secure_memzero_sloth(iv, sizeof(iv));
			secure_memzero_sloth(ks, sizeof(ks));
			secure_memzero_sloth(padded_text, sizeof(padded_text));
			secure_memzero_sloth(password, sizeof(password));
			free(ciphertext);
			fprintf(stderr, "Memory allocation failed for data to auth.\n");
			return 1;
		}
		memcpy(data_to_auth, salt, sizeof(salt));
		memcpy(data_to_auth + sizeof(salt), iv, sizeof(iv));
		memcpy(data_to_auth + sizeof(salt) + sizeof(iv), ciphertext, padded_len);

		HMAC_Whirlpool(hmac_key, sizeof(hmac_key), data_to_auth, data_to_auth_len, hmac_output);
		print_hex_sloth("HMAC", hmac_output, sizeof(hmac_output));
		free(data_to_auth);

		// -----------------------------
		// Link: salt + iv + ciphertext + hmac
		// -----------------------------
		size_t total_len = sizeof(salt) + sizeof(iv) + padded_len + sizeof(hmac_output);
		unsigned char* output = (unsigned char*)malloc(total_len);
		if (!output) {
			secure_memzero_sloth(master_key, sizeof(master_key));
			secure_memzero_sloth(hmac_key, sizeof(hmac_key));
			secure_memzero_sloth(derived_key, sizeof(derived_key));
			secure_memzero_sloth(iv, sizeof(iv));
			secure_memzero_sloth(ks, sizeof(ks));
			secure_memzero_sloth(padded_text, sizeof(padded_text));
			secure_memzero_sloth(password, sizeof(password));
			free(ciphertext);
			fprintf(stderr, "Memory allocation failed for output.\n");
			return 1;
		}
		memcpy(output, salt, sizeof(salt));
		memcpy(output + sizeof(salt), iv, sizeof(iv));
		memcpy(output + sizeof(salt) + sizeof(iv), ciphertext, padded_len);
		memcpy(output + sizeof(salt) + sizeof(iv) + padded_len, hmac_output, sizeof(hmac_output));

		char* hex_output = uint8_to_hex_string_sloth(output, total_len);
		printf("Encrypted (Salt + IV + Ciphertext + HMAC) HEX:\n%s\n", hex_output);
		secure_memzero_sloth(master_key, sizeof(master_key));
		secure_memzero_sloth(hmac_key, sizeof(hmac_key));
		secure_memzero_sloth(iv, sizeof(iv));
		secure_memzero_sloth(ks, sizeof(ks));
		secure_memzero_sloth(block, sizeof(block));
		secure_memzero_sloth(padded_text, sizeof(padded_text));
		free(hex_output);
		free(ciphertext);
		free(output);
	}
	else if (mode == 1) {
		uint8_t nonce[NONCE_SIZE_SLOTH], tag[TAG_SIZE_SLOTH];

		PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS_SLOTH, sizeof(derived_key), derived_key);
		print_hex_sloth("derived_key", derived_key, sizeof(derived_key));


		if (secure_random(nonce, sizeof(nonce)) != 0) {
			secure_memzero_sloth(password, sizeof(password));
			secure_memzero_sloth(derived_key, sizeof(derived_key));
			fprintf(stderr, "Failed to generate nonce.\n");
			return 1;
		}
		print_hex_sloth("nonce", nonce, sizeof(nonce));

		unsigned char* encrypted_text = (unsigned char*)malloc(plaintext_len);
		if (!encrypted_text) {
			secure_memzero_sloth(password, sizeof(password));
			secure_memzero_sloth(derived_key, sizeof(derived_key));
			fprintf(stderr, "Memory allocation failed for encrypted text.\n");
			return 1;
		}

		gcm_encrypt_sloth((unsigned char*)plaintext, plaintext_len, derived_key, nonce, tag, encrypted_text);

		printf("Encrypted: ");
		for (size_t i = 0; i < plaintext_len; i++) printf("%02X ", plaintext[i]);
		printf("\nTag: ");
		for (size_t i = 0; i < TAG_SIZE_SLOTH; i++) printf("%02X ", tag[i]);
		printf("\n");

		size_t total_len = sizeof(salt) + sizeof(nonce) + sizeof(tag) + plaintext_len;
		unsigned char* output = (unsigned char*)malloc(total_len);

		memcpy(output, salt, sizeof(salt));
		memcpy(output + sizeof(salt), nonce, sizeof(nonce));
		memcpy(output + sizeof(salt) + sizeof(nonce), tag, sizeof(tag));
		memcpy(output + sizeof(salt) + sizeof(nonce) + sizeof(tag), encrypted_text, plaintext_len);

		char* hex_output = uint8_to_hex_string_sloth(output, total_len);
		printf("Encrypted (Salt + nonce + Ciphertext) HEX:\n%s\n", hex_output);
		secure_memzero_sloth(nonce, sizeof(nonce));
		secure_memzero_sloth(tag, sizeof(tag));
		free(hex_output);
		free(output);
		free(encrypted_text);
	}
	secure_memzero_sloth(password, sizeof(password));
	secure_memzero_sloth(plaintext, sizeof(plaintext));
	secure_memzero_sloth(derived_key, sizeof(derived_key));
	secure_memzero_sloth(salt, sizeof(salt)); // Zero Memory

	return 0;
}
int dec_sloth(int mode) {
	uint8_t salt[SALT_SIZE_SLOTH], derived_key[KEY_SIZE_SLOTH];
	char password[PWD_MAX_LENGTH_SLOTH], hex_input[HEXINPUT_MAX_LENGTH_SLOTH];
	unsigned char* ciphertext;
	size_t ciphertext_len;

	if (get_user_input("Please enter password: ", password, sizeof(password)) != 0) {
		return 1;
	}
	if (get_user_input("Please enter encrypted HEX: ", hex_input, sizeof(hex_input)) != 0) {
		secure_memzero_sloth(password, sizeof(password));
		return 1;
	}

	if (mode == 0) {
		uint8_t iv[IV_SIZE_SLOTH], master_key[KEY_SIZE_SLOTH + HMAC_WHIRLPOOL_KEY_SIZE_SLOTH], hmac_key[HMAC_WHIRLPOOL_KEY_SIZE_SLOTH], hmac_expected[OUTPUT_SIZE_SLOTH], hmac_actual[OUTPUT_SIZE_SLOTH], ks[SERPENT_KSSIZE_SLOTH], decrypted_block[BLOCK_SIZE_SLOTH];
		size_t total_len = strlen(hex_input) / 2;
		unsigned char block[BLOCK_SIZE_SLOTH];
		unsigned char prev_cipher[BLOCK_SIZE_SLOTH];

		if (total_len < sizeof(salt) + sizeof(iv) + OUTPUT_SIZE_SLOTH) {
			fprintf(stderr, "Invalid input length.\n");
			return 1;
		}

		// Get Message Length
		size_t header_len = sizeof(salt) + sizeof(iv);
		size_t hmac_len = OUTPUT_SIZE_SLOTH;
		ciphertext_len = total_len - header_len - hmac_len;

		// Hex to Uint8
		hex_to_uint8_sloth(hex_input, salt, sizeof(salt));
		hex_to_uint8_sloth(hex_input + 2 * sizeof(salt), iv, sizeof(iv));

		ciphertext = (unsigned char*)malloc(ciphertext_len);
		if (!ciphertext) {
			fprintf(stderr, "Memory allocation error.\n");
			secure_memzero_sloth(password, sizeof(password));
			return 1;
		}
		hex_to_uint8_sloth(hex_input + 2 * (sizeof(salt) + sizeof(iv)), ciphertext, ciphertext_len);
		hex_to_uint8_sloth(hex_input + 2 * (sizeof(salt) + sizeof(iv) + ciphertext_len), hmac_expected, sizeof(hmac_expected));

		print_hex_sloth("Salt", salt, sizeof(salt));
		print_hex_sloth("IV", iv, sizeof(iv));
		print_hex_sloth("HMAC(expected)", hmac_expected, sizeof(hmac_expected));

		// Get two Keys
		PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS_SLOTH, sizeof(master_key), master_key);
		memcpy(derived_key, master_key, KEY_SIZE_SLOTH);
		memcpy(hmac_key, master_key + KEY_SIZE_SLOTH, HMAC_WHIRLPOOL_KEY_SIZE_SLOTH);
		print_hex_sloth("Key", derived_key, sizeof(derived_key));
		print_hex_sloth("hmac_key", hmac_key, sizeof(hmac_key));

		// Compute HMAC
		size_t auth_data_len = sizeof(salt) + sizeof(iv) + ciphertext_len;
		uint8_t* auth_data = (uint8_t*)malloc(auth_data_len);
		memcpy(auth_data, salt, sizeof(salt));
		memcpy(auth_data + sizeof(salt), iv, sizeof(iv));
		memcpy(auth_data + sizeof(salt) + sizeof(iv), ciphertext, ciphertext_len);

		HMAC_Whirlpool(hmac_key, sizeof(hmac_key), auth_data, auth_data_len, hmac_actual);
		print_hex_sloth("HMAC(actual)", hmac_actual, sizeof(hmac_actual));
		free(auth_data);

		if (!constant_time_compare_sloth(hmac_expected, hmac_actual, 64)) {
			fprintf(stderr, "HMAC verification failed! Data may be tampered.\n");
			free(ciphertext);
			secure_memzero_sloth(master_key, sizeof(master_key));
			secure_memzero_sloth(hmac_key, sizeof(hmac_key));
			secure_memzero_sloth(ks, sizeof(ks));
			secure_memzero_sloth(derived_key, sizeof(derived_key));
			secure_memzero_sloth(password, sizeof(password));
			return 1;
		}

		// Key Schdule
		serpent_set_key(derived_key, ks);

		unsigned char* decrypted_text = (unsigned char*)malloc(ciphertext_len);
		if (!decrypted_text) {
			free(ciphertext);
			secure_memzero_sloth(master_key, sizeof(master_key));
			secure_memzero_sloth(hmac_key, sizeof(hmac_key));
			secure_memzero_sloth(ks, sizeof(ks));
			secure_memzero_sloth(derived_key, sizeof(derived_key));
			secure_memzero_sloth(password, sizeof(password));
			fprintf(stderr, "Memory allocation error.\n");
			return 1;
		}

		memcpy(prev_cipher, iv, BLOCK_SIZE_SLOTH);

		for (size_t i = 0; i < ciphertext_len; i += BLOCK_SIZE_SLOTH) {
			memcpy(block, ciphertext + i, BLOCK_SIZE_SLOTH);
			serpent_decrypt(block, decrypted_block, ks);
			for (size_t j = 0; j < BLOCK_SIZE_SLOTH; j++) {
				decrypted_text[i + j] = decrypted_block[j] ^ prev_cipher[j];
			}
			memcpy(prev_cipher, ciphertext + i, BLOCK_SIZE_SLOTH);
		}

		size_t plain_len = pkcs7_unpad_sloth(decrypted_text, ciphertext_len);

		printf("Decrypted plaintext: ");
		fwrite(decrypted_text, 1, plain_len, stdout);
		printf("\n");

		secure_memzero_sloth(master_key, sizeof(master_key));
		secure_memzero_sloth(hmac_key, sizeof(hmac_key));
		secure_memzero_sloth(hmac_actual, sizeof(hmac_actual));
		secure_memzero_sloth(hmac_expected, sizeof(hmac_expected));
		secure_memzero_sloth(ks, sizeof(ks));
		secure_memzero_sloth(block, sizeof(block));
		secure_memzero_sloth(prev_cipher, sizeof(prev_cipher));


		if (ciphertext) {
			secure_memzero_sloth(ciphertext, ciphertext_len);
			free(ciphertext);
		}
		if (decrypted_text) {
			secure_memzero_sloth(decrypted_text, ciphertext_len);
			free(decrypted_text);
		}

	}
	else if (mode == 1) {
		uint8_t  tag[TAG_SIZE_SLOTH], nonce[NONCE_SIZE_SLOTH];
		size_t total_len = strlen(hex_input) / 2;
		if (total_len < sizeof(salt) + sizeof(nonce) + sizeof(tag)) {
			secure_memzero_sloth(password, sizeof(password));
			fprintf(stderr, "Invalid input length.\n");
			return 1;
		}

		hex_to_uint8_sloth(hex_input, salt, sizeof(salt));
		hex_to_uint8_sloth(hex_input + 2 * sizeof(salt), nonce, sizeof(nonce));
		hex_to_uint8_sloth(hex_input + 2 * (sizeof(salt) + sizeof(nonce)), tag, sizeof(tag));

		ciphertext_len = total_len - sizeof(salt) - sizeof(nonce) - sizeof(tag);
		ciphertext = (unsigned char*)malloc(ciphertext_len);
		if (!ciphertext) {
			secure_memzero_sloth(password, sizeof(password));
			fprintf(stderr, "Memory allocation error.\n");
			return 1;
		}

		hex_to_uint8_sloth(hex_input + 2 * (sizeof(salt) + sizeof(nonce) + sizeof(tag)), ciphertext, ciphertext_len);

		print_hex_sloth("Salt", salt, sizeof(salt));
		print_hex_sloth("Nonce", nonce, sizeof(nonce));
		print_hex_sloth("Tag", tag, sizeof(tag));


		PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS_SLOTH, sizeof(derived_key), derived_key);
		print_hex_sloth("Key", derived_key, sizeof(derived_key));


		if (gcm_decrypt_sloth(ciphertext, ciphertext_len, derived_key, nonce, tag) == 0) {
			printf("Decrypted: ");
			fwrite(ciphertext, 1, ciphertext_len, stdout);
			printf("\n");

		}
		else {
			printf("Authentication failed!\n");
			secure_memzero_sloth(password, sizeof(password));
			secure_memzero_sloth(derived_key, sizeof(derived_key));
			secure_memzero_sloth(salt, sizeof(salt));
			if (ciphertext) {
				secure_memzero_sloth(ciphertext, ciphertext_len);
				free(ciphertext);
			}
			return -1;
		}
		secure_memzero_sloth(nonce, sizeof(nonce));
		secure_memzero_sloth(tag, sizeof(tag));

		if (ciphertext) {
			secure_memzero_sloth(ciphertext, ciphertext_len);
			free(ciphertext);
		}
		//free(decrypted_text);
	}
	secure_memzero_sloth(password, sizeof(password));
	secure_memzero_sloth(derived_key, sizeof(derived_key));
	secure_memzero_sloth(salt, sizeof(salt));
	return 0;

}
int enc_file_sloth(int mode) {
	char input_path[ROUTE_LENGTH_SLOTH], output_path[ROUTE_LENGTH_SLOTH], password[PWD_MAX_LENGTH_SLOTH];
	uint8_t salt[SALT_SIZE_SLOTH], derived_key[KEY_SIZE_SLOTH];

	if (get_user_input("Please enter password: ", password, sizeof(password)) != 0) {
		return 1;
	}
	if (get_user_input("Enter input file path: ", input_path, sizeof(input_path)) != 0) {
		secure_memzero_sloth(password, sizeof(password));
		return 1;
	}
	if (get_user_input("Enter output file path: ", output_path, sizeof(output_path)) != 0) {
		secure_memzero_sloth(password, sizeof(password));
		return 1;
	}
	FILE* infile, * outfile;
	infile = fopen(input_path, "rb");
	if (!infile) {
		fprintf(stderr, "Error opening input file.\n");
		secure_memzero_sloth(password, sizeof(password));
		return 1;
	}
	outfile = fopen(output_path, "wb");
	if (!outfile) {
		fprintf(stderr, "Error opening output file.\n");
		secure_memzero_sloth(password, sizeof(password));
		fclose(infile);
		return 1;
	}
	if (secure_random(salt, sizeof(salt)) != 0) {
		secure_memzero_sloth(password, sizeof(password));
		fclose(outfile);
		fclose(infile);
		fprintf(stderr, "Failed to generate salt.\n");
		return 1;
	}

	if (mode == 0) {
		uint8_t iv[IV_SIZE_SLOTH], hmac_output[OUTPUT_SIZE_SLOTH];
		uint8_t master_key[KEY_SIZE_SLOTH + HMAC_WHIRLPOOL_KEY_SIZE_SLOTH], hmac_key[HMAC_WHIRLPOOL_KEY_SIZE_SLOTH];

		PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS_SLOTH, sizeof(master_key), master_key);
		memcpy(derived_key, master_key, KEY_SIZE_SLOTH);
		memcpy(hmac_key, master_key + KEY_SIZE_SLOTH, HMAC_WHIRLPOOL_KEY_SIZE_SLOTH);

		print_hex_sloth("Salt", salt, sizeof(salt));
		print_hex_sloth("Key", derived_key, sizeof(derived_key));
		print_hex_sloth("hmac_key", hmac_key, sizeof(hmac_key));

		if (secure_random(iv, sizeof(iv)) != 0) {
			fprintf(stderr, "Failed to generate iv.\n");
			secure_memzero_sloth(master_key, sizeof(master_key));
			secure_memzero_sloth(hmac_key, sizeof(hmac_key));
			secure_memzero_sloth(password, sizeof(password));
			secure_memzero_sloth(derived_key, sizeof(derived_key));
			fclose(outfile);
			fclose(infile);
			return 1;
		}
		HMAC_Whirlpool_CTX hmac_ctx;
		HMAC_Whirlpool_Init(&hmac_ctx, hmac_key, sizeof(hmac_key));
		HMAC_Whirlpool_Update(&hmac_ctx, salt, SALT_SIZE_SLOTH);
		HMAC_Whirlpool_Update(&hmac_ctx, iv, IV_SIZE_SLOTH);

		uint8_t ks[SERPENT_KSSIZE_SLOTH];
		serpent_set_key(derived_key, ks);

		fwrite(salt, 1, sizeof(salt), outfile);
		fwrite(iv, 1, sizeof(iv), outfile);

		uint8_t buffer[BLOCK_SIZE_SLOTH], padded_block[BLOCK_SIZE_SLOTH], cipher_block[BLOCK_SIZE_SLOTH];
		size_t read_len;
		uint8_t prev_cipher[BLOCK_SIZE_SLOTH];
		memcpy(prev_cipher, iv, BLOCK_SIZE_SLOTH);  // Initial IV
		int last_block_full = 0;

		while ((read_len = fread(buffer, 1, BLOCK_SIZE_SLOTH, infile)) > 0) {
			memset(padded_block, 0, BLOCK_SIZE_SLOTH);

			if (read_len < BLOCK_SIZE_SLOTH) {
				pkcs7_pad_sloth(buffer, read_len, padded_block);
				last_block_full = 0;
			}
			else {
				memcpy(padded_block, buffer, BLOCK_SIZE_SLOTH);
				last_block_full = 1;
			}

			// CBC XOR
			for (size_t i = 0; i < BLOCK_SIZE_SLOTH; i++) {
				padded_block[i] ^= prev_cipher[i];
			}

			serpent_encrypt(padded_block, cipher_block, ks);
			memcpy(prev_cipher, cipher_block, BLOCK_SIZE_SLOTH);

			fwrite(cipher_block, 1, BLOCK_SIZE_SLOTH, outfile);
			HMAC_Whirlpool_Update(&hmac_ctx, cipher_block, BLOCK_SIZE_SLOTH);
		}

		// Make Sure full padding
		if (last_block_full == 1) {
			memset(buffer, BLOCK_SIZE_SLOTH, BLOCK_SIZE_SLOTH);  // Fill with padding value
			for (size_t i = 0; i < BLOCK_SIZE_SLOTH; i++) {
				buffer[i] ^= prev_cipher[i];
			}

			serpent_encrypt(buffer, cipher_block, ks);
			fwrite(cipher_block, 1, BLOCK_SIZE_SLOTH, outfile);
			HMAC_Whirlpool_Update(&hmac_ctx, cipher_block, BLOCK_SIZE_SLOTH);
		}
		HMAC_Whirlpool_Final(&hmac_ctx, hmac_output);
		fwrite(hmac_output, 1, OUTPUT_SIZE_SLOTH, outfile);
		secure_memzero_sloth(hmac_key, sizeof(hmac_key));
		secure_memzero_sloth(hmac_output, sizeof(hmac_output));
		secure_memzero_sloth(master_key, sizeof(master_key));
		secure_memzero_sloth(ks, sizeof(ks));
		secure_memzero_sloth(buffer, sizeof(buffer));
		secure_memzero_sloth(padded_block, sizeof(padded_block));
		secure_memzero_sloth(prev_cipher, sizeof(prev_cipher));
	}
	else if (mode == 1) {

		uint8_t nonce[NONCE_SIZE_SLOTH], tag[TAG_SIZE_SLOTH];
		uint8_t* buffer = (uint8_t*)malloc(GCM_BLOCK_SIZE_SLOTH);
		uint8_t* cipher = (uint8_t*)malloc(GCM_BLOCK_SIZE_SLOTH);

		if (!buffer || !cipher) {
			handle_error_sloth("Memory allocation failed");
			secure_memzero_sloth(password, sizeof(password));
			if (buffer) free(buffer);
			if (cipher) free(cipher);
			fclose(outfile);
			fclose(infile);
			return 1;
		}

		PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS_SLOTH, sizeof(derived_key), derived_key);
		print_hex_sloth("Salt", salt, sizeof(salt));
		print_hex_sloth("Key", derived_key, sizeof(derived_key));


		fwrite(salt, 1, sizeof(salt), outfile);
		size_t bytes_read;
		while ((bytes_read = fread(buffer, 1, GCM_BLOCK_SIZE_SLOTH, infile)) > 0) {
			if (secure_random(nonce, NONCE_SIZE_SLOTH) != 0) {
				secure_memzero_sloth(password, sizeof(password));
				secure_memzero_sloth(derived_key, sizeof(derived_key));
				handle_error_sloth("Failed to generate nonce");
			}
			gcm_encrypt_sloth(buffer, bytes_read, derived_key, nonce, tag, cipher);

			fwrite(nonce, 1, NONCE_SIZE_SLOTH, outfile);
			fwrite(tag, 1, TAG_SIZE_SLOTH, outfile);
			fwrite(cipher, 1, bytes_read, outfile);

			print_hex_sloth("Nonce", nonce, sizeof(nonce));
			print_hex_sloth("Tag", tag, sizeof(tag));
		}
		secure_memzero_sloth(nonce, sizeof(nonce));
		secure_memzero_sloth(tag, sizeof(tag));
		if (buffer) {
			secure_memzero_sloth(buffer, GCM_BLOCK_SIZE_SLOTH);
			free(buffer);
		}
		if (cipher) {
			secure_memzero_sloth(cipher, GCM_BLOCK_SIZE_SLOTH);
			free(cipher);
		}
	}

	secure_memzero_sloth(password, sizeof(password));
	secure_memzero_sloth(derived_key, sizeof(derived_key));
	secure_memzero_sloth(salt, sizeof(salt));

	fclose(outfile);
	fclose(infile);
	return 0;
}

int dec_file_sloth(int mode) {

	//Intial all shared variables
	char password[PWD_MAX_LENGTH_SLOTH], input_path[ROUTE_LENGTH_SLOTH], output_path[ROUTE_LENGTH_SLOTH];
	uint8_t salt[SALT_SIZE_SLOTH], derived_key[KEY_SIZE_SLOTH];

	//Get all needed user input
	if (get_user_input("Please enter password: ", password, sizeof(password)) != 0) {
		return 1;
	}
	if (get_user_input("Enter input file path: ", input_path, sizeof(input_path)) != 0) {
		secure_memzero_sloth(password, sizeof(password));
		return 1;
	}
	if (get_user_input("Enter output file path: ", output_path, sizeof(output_path)) != 0) {
		secure_memzero_sloth(password, sizeof(password));
		return 1;
	}

	//Open file
	FILE* infile, * outfile;
	infile = fopen(input_path, "rb");
	if (!infile) {
		fprintf(stderr, "Error opening input file.\n");
		secure_memzero_sloth(password, sizeof(password));
		return 1;
	}
	outfile = fopen(output_path, "wb");
	if (!outfile) {
		fprintf(stderr, "Error opening output file.\n");
		secure_memzero_sloth(password, sizeof(password));
		fclose(infile);
		return 1;
	}

	//Read salt
	if (mode == 0) {
		uint8_t iv[IV_SIZE_SLOTH], tag[OUTPUT_SIZE_SLOTH], hmac_output[OUTPUT_SIZE_SLOTH];
		uint8_t master_key[KEY_SIZE_SLOTH + HMAC_WHIRLPOOL_KEY_SIZE_SLOTH], hmac_key[HMAC_WHIRLPOOL_KEY_SIZE_SLOTH], ks[SERPENT_KSSIZE_SLOTH];

		// Get Fise Size
		fseek(infile, 0, SEEK_END);
		size_t file_size = ftell(infile);
		fseek(infile, 0, SEEK_SET);

		if (fread(salt, 1, SALT_SIZE_SLOTH, infile) != SALT_SIZE_SLOTH) handle_error_sloth("Failed to read salt");
		fread(iv, 1, IV_SIZE_SLOTH, infile);

		if (file_size < SALT_SIZE_SLOTH + IV_SIZE_SLOTH + OUTPUT_SIZE_SLOTH) {
			secure_memzero_sloth(password, sizeof(password));
			fprintf(stderr, "File too small.\n");
			fclose(infile);
			fclose(outfile);
			return 1;
		}

		//Initial 512-bits master key and hmac key
		//Get master key and devide two key for encrypt and hmac
		PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS_SLOTH, sizeof(master_key), master_key);
		memcpy(derived_key, master_key, KEY_SIZE_SLOTH);
		memcpy(hmac_key, master_key + KEY_SIZE_SLOTH, HMAC_WHIRLPOOL_KEY_SIZE_SLOTH);
		print_hex_sloth("Key", derived_key, sizeof(derived_key));
		print_hex_sloth("hmac_key", hmac_key, sizeof(hmac_key));


		size_t ciphertext_size = file_size - SALT_SIZE_SLOTH - IV_SIZE_SLOTH - OUTPUT_SIZE_SLOTH;

		HMAC_Whirlpool_CTX hmac_ctx;
		HMAC_Whirlpool_Init(&hmac_ctx, hmac_key, sizeof(hmac_key));
		HMAC_Whirlpool_Update(&hmac_ctx, salt, SALT_SIZE_SLOTH);
		HMAC_Whirlpool_Update(&hmac_ctx, iv, IV_SIZE_SLOTH);

		// KS and Prepare CBC
		serpent_set_key(derived_key, ks);
		uint8_t prev_block[BLOCK_SIZE_SLOTH];
		memcpy(prev_block, iv, BLOCK_SIZE_SLOTH);

		// Decryption
		uint8_t block[BLOCK_SIZE_SLOTH], decrypted[BLOCK_SIZE_SLOTH];
		size_t total_read = 0;
		size_t write_len;

		while (total_read < ciphertext_size &&
			fread(block, 1, BLOCK_SIZE_SLOTH, infile) == BLOCK_SIZE_SLOTH) {

			HMAC_Whirlpool_Update(&hmac_ctx, block, BLOCK_SIZE_SLOTH);

			serpent_decrypt(block, decrypted, ks);
			for (size_t i = 0; i < BLOCK_SIZE_SLOTH; ++i)
				decrypted[i] ^= prev_block[i];

			memcpy(prev_block, block, BLOCK_SIZE_SLOTH);

			// Unpad
			total_read += BLOCK_SIZE_SLOTH;
			if (total_read == ciphertext_size) {
				write_len = pkcs7_unpad_sloth(decrypted, BLOCK_SIZE_SLOTH);
			}
			else {
				write_len = BLOCK_SIZE_SLOTH;
			}
			fwrite(decrypted, 1, write_len, outfile);
		}

		// Compute HMAC
		fread(tag, 1, OUTPUT_SIZE_SLOTH, infile);
		HMAC_Whirlpool_Final(&hmac_ctx, hmac_output);

		if (!constant_time_compare_sloth(tag, hmac_output, OUTPUT_SIZE_SLOTH)) {
			fprintf(stderr, "HMAC verification failed!\n");
			secure_memzero_sloth(hmac_key, sizeof(hmac_key));
			secure_memzero_sloth(hmac_output, sizeof(hmac_output));
			secure_memzero_sloth(master_key, sizeof(master_key));
			secure_memzero_sloth(ks, sizeof(ks));
			secure_memzero_sloth(block, sizeof(block));
			secure_memzero_sloth(decrypted, sizeof(decrypted));
			secure_memzero_sloth(prev_block, sizeof(prev_block));
			secure_memzero_sloth(password, sizeof(password));
			secure_memzero_sloth(derived_key, sizeof(derived_key));
			fclose(infile); fclose(outfile);
			return 1;
		}
		secure_memzero_sloth(hmac_key, sizeof(hmac_key));
		secure_memzero_sloth(hmac_output, sizeof(hmac_output));
		secure_memzero_sloth(master_key, sizeof(master_key));
		secure_memzero_sloth(ks, sizeof(ks));
		secure_memzero_sloth(block, sizeof(block));
		secure_memzero_sloth(decrypted, sizeof(decrypted));
		secure_memzero_sloth(prev_block, sizeof(prev_block));

	}
	else if (mode == 1) {
		if (fread(salt, 1, SALT_SIZE_SLOTH, infile) != SALT_SIZE_SLOTH) handle_error_sloth("Failed to read salt");

		PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS_SLOTH, sizeof(derived_key), derived_key);
		print_hex_sloth("Key", derived_key, sizeof(derived_key));

		uint8_t nonce[NONCE_SIZE_SLOTH], tag[TAG_SIZE_SLOTH];
		uint8_t* ciphertext = (uint8_t*)malloc(GCM_BLOCK_SIZE_SLOTH);
		if (!ciphertext) handle_error_sloth("Memory allocation failed");
		size_t bytes_read;
		while ((bytes_read = fread(nonce, 1, NONCE_SIZE_SLOTH, infile)) == NONCE_SIZE_SLOTH) {
			print_hex_sloth("Nonce", nonce, sizeof(nonce));
			if (fread(tag, 1, TAG_SIZE_SLOTH, infile) != TAG_SIZE_SLOTH) {
				handle_error_sloth("Failed to read tag");
			}
			print_hex_sloth("TAG", tag, sizeof(tag));
			size_t ciphertext_len = fread(ciphertext, 1, GCM_BLOCK_SIZE_SLOTH, infile);
			if (ciphertext_len == 0) {
				handle_error_sloth("Failed to read ciphertext");
			}
			if (gcm_decrypt_sloth(ciphertext, ciphertext_len, derived_key, nonce, tag) != 0) {
				handle_error_sloth("Authentication failed!");
			}
			fwrite(ciphertext, 1, ciphertext_len, outfile);
		}
		secure_memzero_sloth(nonce, NONCE_SIZE_SLOTH); // Zero nonce
		secure_memzero_sloth(tag, TAG_SIZE_SLOTH); // Zero tag
		if (ciphertext) {
			secure_memzero_sloth(ciphertext, GCM_BLOCK_SIZE_SLOTH);
			free(ciphertext);
		}
	}
	secure_memzero_sloth(password, sizeof(password));
	secure_memzero_sloth(derived_key, sizeof(derived_key));
	secure_memzero_sloth(salt, sizeof(salt));

	fclose(infile);
	fclose(outfile);

	return 0;
}
int hashstr_sloth() {
	char plaintext[PLAINTEXT_MAX_LENGTH_SLOTH];
	uint8_t key_block[BLOCK_SIZE_WHIRLPOOL_SLOTH];
	if (get_user_input("Please enter text: ", plaintext, sizeof(plaintext)) != 0) {
		return 1;
	}
	WHIRLPOOL_CTX key_ctx;
	WHIRLPOOL_init(&key_ctx);
	WHIRLPOOL_add(plaintext, strlen(plaintext), &key_ctx);
	WHIRLPOOL_finalize(&key_ctx, key_block);
	int tmp = VERBOSE_SLOTH;
	VERBOSE_SLOTH = 1;
	print_hex_sloth("Whirlpool Hash", key_block, BLOCK_SIZE_WHIRLPOOL_SLOTH);
	VERBOSE_SLOTH = tmp;
	return 0;
}
int hashfile_sloth() {
	char input_path[ROUTE_LENGTH_SLOTH];
	uint8_t key_block[BLOCK_SIZE_WHIRLPOOL_SLOTH];
	if (get_user_input("Enter input file path: ", input_path, sizeof(input_path)) != 0) {
		return 1;
	}
	FILE* infile = fopen(input_path, "rb");
	if (!infile) {
		fprintf(stderr, "Error opening input file.\n");
		return 1;
	}
	WHIRLPOOL_CTX key_ctx;
	WHIRLPOOL_init(&key_ctx);
	size_t read_len;
	unsigned char buffer[HASH_WHIRLPOOL_BUFFER_SIZE];
	while ((read_len = fread(buffer, 1, HASH_WHIRLPOOL_BUFFER_SIZE, infile)) > 0) {
		WHIRLPOOL_add(buffer, read_len, &key_ctx);
	}
	fclose(infile);
	WHIRLPOOL_finalize(&key_ctx, key_block);
	int tmp = VERBOSE_SLOTH;
	VERBOSE_SLOTH = 1;
	print_hex_sloth("Whirlpool Hash", key_block, BLOCK_SIZE_WHIRLPOOL_SLOTH);
	VERBOSE_SLOTH = tmp;
	return 0;
}