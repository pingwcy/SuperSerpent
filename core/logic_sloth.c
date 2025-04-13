#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "logic_sloth.h"
#include "../params.h"
#include "../vcserpent/SerpentFast.h" 
#include "../pbkdf2/pbkdf2.h"
#include "../rand/rand.h"
#include "utils_sloth.h"
#include "crypto_mode_sloth.h"

int enc_sloth(int mode) {
	uint8_t salt[SALT_SIZE_SLOTH], derived_key[KEY_SIZE_SLOTH];
	char password[PWD_MAX_LENGTH_SLOTH];
	char plaintext[PLAINTEXT_MAX_LENGTH_SLOTH];
	size_t padded_len;

	if (get_user_input("Please enter password: ", password, sizeof(password)) != 0) {
		return 1;
	}
	if (get_user_input("Please enter plaintext: ", plaintext, sizeof(plaintext)) != 0) {
		return 1;
	}
	size_t plaintext_len = strlen(plaintext);

	//printf("Password: %s\n", password);
	//printf("Plaintext: %s\n", plaintext);
	if (secure_random(salt, sizeof(salt)) != 0) {
		fprintf(stderr, "Failed to generate salt.\n");
		return 1;
	}
	print_hex_sloth("Salt",salt,sizeof(salt));

	PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS_SLOTH, sizeof(derived_key), derived_key);
	print_hex_sloth("derived_key", derived_key, sizeof(derived_key));

	if (mode == 0) {
		uint8_t iv[IV_SIZE_SLOTH];
		if (secure_random(iv, sizeof(iv)) != 0) {
			fprintf(stderr, "Failed to generate IV.\n");
			return 1;
		}
		print_hex_sloth("IV", iv, sizeof(iv));

		unsigned char padded_text[PADDEDTEXT_MAX_LENGTH_SLOTH];
		padded_len = pkcs7_pad_sloth((unsigned char*)plaintext, plaintext_len, padded_text);

		if (!padded_len) {
			fprintf(stderr, "Padding error.\n");
			return 1;
		}
		print_hex_sloth("Padded text", padded_text, padded_len);

		uint8_t ks[SERPENT_KSSIZE_SLOTH];
		serpent_set_key(derived_key, ks);

		unsigned char* ciphertext = (unsigned char*)malloc(padded_len);
		if (!ciphertext) {
			//free(padded_text);
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

		size_t total_len = sizeof(salt) + sizeof(iv) + padded_len;
		unsigned char* output = (unsigned char*)malloc(total_len);

		memcpy(output, salt, sizeof(salt));
		memcpy(output + sizeof(salt), iv, sizeof(iv));
		memcpy(output + sizeof(salt) + sizeof(iv), ciphertext, padded_len);

		char* hex_output = uint8_to_hex_string_sloth(output, total_len);

		printf("Encrypted (Salt + IV + Ciphertext) HEX:\n%s\n", hex_output);

		//free(padded_text);
		free(ciphertext);
		free(output);
		free(hex_output);
	}
	else if (mode == 1) {

		uint8_t nonce[NONCE_SIZE_SLOTH], tag[TAG_SIZE_SLOTH];

		if (secure_random(nonce, sizeof(nonce)) != 0) {
			fprintf(stderr, "Failed to generate nonce.\n");
			return 1;
		}
		print_hex_sloth("nonce", nonce, sizeof(nonce));

		unsigned char* encrypted_text = (unsigned char*)malloc(plaintext_len);
		if (!encrypted_text) {
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
		free(output);
		free(hex_output);
		free(encrypted_text);
	}
	return 0;
}
int dec_sloth(int mode) {
	uint8_t salt[SALT_SIZE_SLOTH], derived_key[KEY_SIZE_SLOTH];
	char password[PWD_MAX_LENGTH_SLOTH];
	char hex_input[HEXINPUT_MAX_LENGTH_SLOTH];
	unsigned char* ciphertext;
	size_t ciphertext_len;

	if (get_user_input("Please enter password: ", password, sizeof(password)) != 0) {
		return 1;
	}
	if (get_user_input("Please enter encrypted HEX: ", hex_input, sizeof(hex_input)) != 0) {
		return 1;
	}	

	if (mode == 0) {
		uint8_t iv[IV_SIZE_SLOTH];
		size_t total_len = strlen(hex_input) / 2;
		if (total_len < sizeof(salt) + sizeof(iv)) {
			fprintf(stderr, "Invalid input length.\n");
			return 1;
		}

		hex_to_uint8_sloth(hex_input, salt, sizeof(salt));
		hex_to_uint8_sloth(hex_input + 2 * sizeof(salt), iv, sizeof(iv));

		ciphertext_len = total_len - sizeof(salt) - sizeof(iv);
		ciphertext = (unsigned char*)malloc(ciphertext_len);
		if (!ciphertext) {
			fprintf(stderr, "Memory allocation error.\n");
			return 1;
		}

		hex_to_uint8_sloth(hex_input + 2 * (sizeof(salt) + sizeof(iv)), ciphertext, ciphertext_len);

		print_hex_sloth("Salt", salt, sizeof(salt));
		print_hex_sloth("IV", iv, sizeof(iv));

		PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS_SLOTH, sizeof(derived_key), derived_key);
		print_hex_sloth("Key", derived_key, sizeof(derived_key));

		uint8_t ks[SERPENT_KSSIZE_SLOTH];
		serpent_set_key(derived_key, ks);

		unsigned char* decrypted_text = (unsigned char*)malloc(ciphertext_len);
		if (!decrypted_text) {
			free(ciphertext);
			return 1;
		}

		unsigned char block[BLOCK_SIZE_SLOTH];
		unsigned char prev_cipher[BLOCK_SIZE_SLOTH];
		memcpy(prev_cipher, iv, BLOCK_SIZE_SLOTH);

		for (size_t i = 0; i < ciphertext_len; i += BLOCK_SIZE_SLOTH) {
			memcpy(block, ciphertext + i, BLOCK_SIZE_SLOTH);

			serpent_decrypt(block, block, ks);

			for (size_t j = 0; j < BLOCK_SIZE_SLOTH; j++) {
				decrypted_text[i + j] = block[j] ^ prev_cipher[j];
			}
			memcpy(prev_cipher, ciphertext + i, BLOCK_SIZE_SLOTH);
		}

		size_t plain_len = pkcs7_unpad_sloth(decrypted_text, ciphertext_len);

		printf("Decrypted plaintext: ");
		fwrite(decrypted_text, 1, plain_len, stdout);
		printf("\n");

		free(ciphertext);
		free(decrypted_text);
	}
	else if (mode == 1) {
		uint8_t  tag[TAG_SIZE_SLOTH], nonce[NONCE_SIZE_SLOTH];
		size_t total_len = strlen(hex_input) / 2;
		if (total_len < sizeof(salt) + sizeof(nonce) + sizeof(tag)) {
			fprintf(stderr, "Invalid input length.\n");
			return 1;
		}

		hex_to_uint8_sloth(hex_input, salt, sizeof(salt));
		hex_to_uint8_sloth(hex_input + 2 * sizeof(salt), nonce, sizeof(nonce));
		hex_to_uint8_sloth(hex_input + 2 * (sizeof(salt)+sizeof(nonce)), tag, sizeof(tag));

		ciphertext_len = total_len - sizeof(salt) - sizeof(nonce) -sizeof(tag);
		ciphertext = (unsigned char*)malloc(ciphertext_len);
		if (!ciphertext) {
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
			for (size_t i = 0; i < ciphertext_len; i++) {
				printf("%c", ciphertext[i]);
			}
			printf("\n");
		}
		else {
			printf("Authentication failed!\n");
			return -1;
		}
		free(ciphertext);
		//free(decrypted_text);
	}
	return 0;

}
int enc_file_sloth(int mode) {
	char password[PWD_MAX_LENGTH_SLOTH];
	char input_path[ROUTE_LENGTH_SLOTH], output_path[ROUTE_LENGTH_SLOTH];
	uint8_t salt[SALT_SIZE_SLOTH], derived_key[KEY_SIZE_SLOTH];
	if (get_user_input("Please enter password: ", password, sizeof(password)) != 0) {
		return 1;
	}
	if (get_user_input("Enter input file path: ", input_path, sizeof(input_path)) != 0) {
		return 1;
	}
	if (get_user_input("Enter output file path: ", output_path, sizeof(output_path)) != 0) {
		return 1;
	}
	FILE* infile, * outfile;
	infile = fopen(input_path, "rb");
	if (!infile) {
		fprintf(stderr, "Error opening input file.\n");
		return 1;
	}
	outfile = fopen(output_path, "wb");
	if (!outfile) {
		fprintf(stderr, "Error opening output file.\n");
		fclose(infile);
		return 1;
	}
	if (secure_random(salt, sizeof(salt)) != 0 ) {
		fprintf(stderr, "Failed to generate salt.\n");
		return 1;
	}
	PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS_SLOTH, sizeof(derived_key), derived_key);
	print_hex_sloth("Salt", salt, sizeof(salt));
	print_hex_sloth("Key", derived_key, sizeof(derived_key));

	if (mode == 0) {
		uint8_t iv[IV_SIZE_SLOTH];
		if (secure_random(iv, sizeof(iv)) != 0) {
			fprintf(stderr, "Failed to generate iv.\n");
			return 1;
		}
		uint8_t ks[SERPENT_KSSIZE_SLOTH];
		serpent_set_key(derived_key, ks);

		fwrite(salt, 1, sizeof(salt), outfile);
		fwrite(iv, 1, sizeof(iv), outfile);

		uint8_t buffer[BLOCK_SIZE_SLOTH], padded_block[BLOCK_SIZE_SLOTH];
		size_t read_len;
		uint8_t prev_cipher[BLOCK_SIZE_SLOTH];
		memcpy(prev_cipher, iv, BLOCK_SIZE_SLOTH);  // Initial IV

		while ((read_len = fread(buffer, 1, BLOCK_SIZE_SLOTH, infile)) > 0) {
			memset(padded_block, 0, BLOCK_SIZE_SLOTH);

			if (read_len < BLOCK_SIZE_SLOTH) {
				pkcs7_pad_sloth(buffer, read_len, padded_block);
			}
			else {
				memcpy(padded_block, buffer, BLOCK_SIZE_SLOTH);
			}

			// CBC XOR
			for (size_t i = 0; i < BLOCK_SIZE_SLOTH; i++) {
				padded_block[i] ^= prev_cipher[i];
			}

			serpent_encrypt(padded_block, padded_block, ks);

			memcpy(prev_cipher, padded_block, BLOCK_SIZE_SLOTH);

			fwrite(padded_block, 1, BLOCK_SIZE_SLOTH, outfile);
		}
		fclose(infile);
		fclose(outfile);
	}
	else if (mode == 1) {

		uint8_t nonce[NONCE_SIZE_SLOTH], tag[TAG_SIZE_SLOTH];
		uint8_t* buffer = (uint8_t*)malloc(GCM_BLOCK_SIZE_SLOTH);
		uint8_t* cipher = (uint8_t*)malloc(GCM_BLOCK_SIZE_SLOTH);

		if (!buffer)  
		{
			handle_error_sloth("Memory allocation failed");
			free(buffer);
		}

		fwrite(salt, 1, sizeof(salt), outfile);
		size_t bytes_read;
		while ((bytes_read = fread(buffer, 1, GCM_BLOCK_SIZE_SLOTH, infile)) > 0) {
			if (secure_random(nonce, NONCE_SIZE_SLOTH) != 0) handle_error_sloth("Failed to generate nonce");

			gcm_encrypt_sloth(buffer, bytes_read, derived_key, nonce, tag, cipher);

			fwrite(nonce, 1, NONCE_SIZE_SLOTH, outfile);
			fwrite(tag, 1, TAG_SIZE_SLOTH, outfile);
			fwrite(cipher, 1, bytes_read, outfile);

			print_hex_sloth("Nonce", nonce, sizeof(nonce));
			print_hex_sloth("Tag", tag, sizeof(tag));
		}
		free(buffer);
		free(cipher);
		fclose(outfile);
		fclose(infile);
	}
	return 0;
}

int dec_file_sloth(int mode) {
	char password[PWD_MAX_LENGTH_SLOTH], input_path[ROUTE_LENGTH_SLOTH], output_path[ROUTE_LENGTH_SLOTH];
	uint8_t salt[SALT_SIZE_SLOTH], derived_key[KEY_SIZE_SLOTH];
	if (get_user_input("Please enter password: ", password, sizeof(password)) != 0) {
		return 1;
	}
	if (get_user_input("Enter input file path: ", input_path, sizeof(input_path)) != 0) {
		return 1;
	}
	if (get_user_input("Enter output file path: ", output_path, sizeof(output_path)) != 0) {
		return 1;
	}
	FILE* infile, * outfile;
	infile = fopen(input_path, "rb");
	if (!infile) {
		fprintf(stderr, "Error opening input file.\n");
		return 1;
	}
	outfile = fopen(output_path, "wb");
	if (!outfile) {
		fprintf(stderr, "Error opening output file.\n");
		fclose(infile);
		return 1;
	}
	if (fread(salt, 1, SALT_SIZE_SLOTH, infile) != SALT_SIZE_SLOTH) handle_error_sloth("Failed to read salt");
	PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS_SLOTH, sizeof(derived_key), derived_key);
	print_hex_sloth("Key", derived_key, sizeof(derived_key));
	if (mode == 0) {
		uint8_t iv[IV_SIZE_SLOTH];
		fread(iv, 1, sizeof(iv), infile);
		uint8_t ks[SERPENT_KSSIZE_SLOTH];
		serpent_set_key(derived_key, ks);
		uint8_t buffer[BLOCK_SIZE_SLOTH], decrypted_block[BLOCK_SIZE_SLOTH];
		uint8_t prev_cipher[BLOCK_SIZE_SLOTH];
		memcpy(prev_cipher, iv, BLOCK_SIZE_SLOTH);
		size_t read_len;

		while ((read_len = fread(buffer, 1, BLOCK_SIZE_SLOTH, infile)) > 0) {
			memcpy(decrypted_block, buffer, BLOCK_SIZE_SLOTH);
			serpent_decrypt(decrypted_block, decrypted_block, ks);
			for (size_t i = 0; i < BLOCK_SIZE_SLOTH; i++) {
				decrypted_block[i] ^= prev_cipher[i];
			}
			memcpy(prev_cipher, buffer, BLOCK_SIZE_SLOTH);
			if (feof(infile)) {
				size_t plain_len = pkcs7_unpad_sloth(decrypted_block, BLOCK_SIZE_SLOTH);
				fwrite(decrypted_block, 1, plain_len, outfile);
			}
			else {
				fwrite(decrypted_block, 1, BLOCK_SIZE_SLOTH, outfile);
			}
		}
	}
	else if (mode == 1) {
		uint8_t nonce[NONCE_SIZE_SLOTH], tag[TAG_SIZE_SLOTH];
		uint8_t* ciphertext = (uint8_t*)malloc(GCM_BLOCK_SIZE_SLOTH);
		if (!ciphertext) handle_error_sloth("Memory allocation failed");
		size_t bytes_read;
		while ((bytes_read = fread(nonce, 1, NONCE_SIZE_SLOTH, infile)) == NONCE_SIZE_SLOTH) {
			print_hex_sloth("Nonce", nonce, sizeof(nonce));
			if (fread(tag, 1, TAG_SIZE_SLOTH, infile) != TAG_SIZE_SLOTH) handle_error_sloth("Failed to read tag");
			print_hex_sloth("TAG", tag, sizeof(tag));
			size_t ciphertext_len = fread(ciphertext, 1, GCM_BLOCK_SIZE_SLOTH, infile);
			if (ciphertext_len == 0) handle_error_sloth("Failed to read ciphertext");
			if (gcm_decrypt_sloth(ciphertext, ciphertext_len, derived_key, nonce, tag) != 0) handle_error_sloth("Authentication failed!");
			fwrite(ciphertext, 1, ciphertext_len, outfile);
		}
		free(ciphertext);
	}
	fclose(infile);
	fclose(outfile);
	return 0;
}