#include "vcserpent/SerpentFast.h" 
#include "pbkdf2/pbkdf2.h"
#include "rand/rand.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
//#define _CRTDBG_MAP_ALLOC
//#include <crtdbg.h>

#define BLOCK_SIZE 16    // 128-bit (16 bytes) block size for serpent
#define ITERATIONS 10000 // PBKDF2 迭代次数
#define MAX_INPUT_LEN 1024
#define GCM_BLOCK_SIZE 10*1024*1024
#define SALT_SIZE 16
#define IV_SIZE 16
#define NONCE_SIZE 12
#define TAG_SIZE 16
#define KEY_SIZE 32

//The function to print out error messgae
void handle_error(const char* msg) {
	fprintf(stderr, "%s\n", msg);
	//exit(1);
}
//Wrapper of the Serpent encrypt for GCM mode
void encrypt_block(const uint8_t* input, uint8_t* output, const uint8_t* key) {
	uint8_t ks[140 * 4];  // Serpent 可能使用较大的密钥调度表
	serpent_set_key(key, ks);  // 初始化密钥调度表
	serpent_encrypt(input, output, ks);  // 用密钥调度表加密
}
// GF(2^128) 乘法（Galois 字段乘法）,for GCM MODE
void galois_mult(const uint8_t* X, const uint8_t* Y, uint8_t* result) {
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
void ghash(const uint8_t* H, const uint8_t* data, size_t length, uint8_t* tag) {
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
void gcm_encrypt(const uint8_t* data, size_t length, const uint8_t* key, uint8_t* iv, uint8_t* tag, uint8_t* encrypted_data) {
	uint8_t counter[16] = { 0 };  // 计数器，初始化为 0
	uint8_t keystream[16];
	uint8_t H[16] = { 0 };  // H = E(K, 0)

	// 确保 nonce 仅 12 字节，并正确设置计数器
	memcpy(counter, iv, 12);  // 只复制 12 字节
	counter[15] = 1;  // GCM 规范要求从 1 开始

	// 计算 H
	encrypt_block(H, H, key);

	// 加密数据
	for (size_t i = 0; i < length; i += 16) {
		encrypt_block(counter, keystream, key);

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
	encrypt_block(tag, tag, key);
}

// 修正 GCM 解密函数
int gcm_decrypt(uint8_t* data, size_t length, const uint8_t* key, uint8_t* iv, uint8_t* tag) {
	uint8_t counter[16] = { 0 };
	uint8_t keystream[16];
	uint8_t H[16] = { 0 };
	uint8_t computed_tag[TAG_SIZE];

	memcpy(counter, iv, 12);
	counter[15] = 1;

	encrypt_block(H, H, key);
	ghash(H, data, length, computed_tag);
	encrypt_block(computed_tag, computed_tag, key);

	if (memcmp(computed_tag, tag, TAG_SIZE) != 0) {
		return -1;  // 认证失败
	}

	for (size_t i = 0; i < length; i += 16) {
		encrypt_block(counter, keystream, key);

		for (size_t j = 0; j < 16 && (i + j) < length; j++) {
			data[i + j] ^= keystream[j];
		}

		for (int j = 15; j >= 0; j--) {
			if (++counter[j]) break;
		}
	}

	return 0;
}

//清除掉用户输出的换行符等等
void clear_input_buffer() {
	int c;
	while ((c = getchar()) != '\n' && c != EOF) {
		// 忽略所有剩余的字符直到换行或文件结束
	}
}
//包装一下获取输入
int safe_fgets(char* buffer, size_t buffer_size) {
	if (fgets(buffer, buffer_size, stdin) == NULL) {
		return 0; // 输入失败
	}

	// 去除输入中的换行符（如果有）
	buffer[strcspn(buffer, "\n")] = '\0';

	return 1; // 输入成功
}

// PKCS#7 填充
size_t pkcs7_pad(unsigned char* input, size_t len, unsigned char* output) {
	size_t pad_len = BLOCK_SIZE - (len % BLOCK_SIZE);
	size_t new_len = len + pad_len;

	memcpy(output, input, len);
	memset(output + len, pad_len, pad_len);

	return new_len;
}

// 移除 PKCS#7 填充
size_t pkcs7_unpad(unsigned char* data, size_t len) {
	if (len == 0) return 0;
	uint8_t pad_len = data[len - 1];
	if (pad_len > BLOCK_SIZE || pad_len == 0) return len; // 防止错误填充
	for (size_t i = 0; i < pad_len; i++) {
		if (data[len - 1 - i] != pad_len) return len; // 验证填充
	}
	return len - pad_len; // 返回去除填充后的长度
}

// HEX 转换为 uint8_t 数组
void hex_to_uint8(const char* hex, uint8_t* output, size_t len) {
	for (size_t i = 0; i < len; i++) {
		sscanf(hex + 2 * i, "%2hhx", &output[i]);
	}
}

// 转换 uint8_t 数组为 HEX 字符串
char* uint8_to_hex_string(uint8_t* data, size_t len) {
	char* hex_string = (char*)malloc(len * 2 + 1);
	if (!hex_string) return NULL;

	for (size_t i = 0; i < len; i++) {
		snprintf(hex_string + i * 2, 3, "%02X", data[i]);
	}
	return hex_string;
}
//字符串加密函数
int enc(int mode) {
	uint8_t salt[SALT_SIZE], iv[IV_SIZE], derived_key[KEY_SIZE];
	char password[256];
	char plaintext[1024]; // 用户输入的明文
	size_t padded_len;

	// 获取用户输入的密码
	printf("Please enter password: ");
	fflush(stdout);  // 确保提示先显示
	if (fgets(password, sizeof(password), stdin) == NULL) {
		fprintf(stderr, "Error reading password.\n");
		return 1;
	}
	password[strcspn(password, "\n")] = '\0'; // 去除换行符

	// 获取用户输入的明文
	printf("Please enter plaintext: ");
	fflush(stdout);  // 确保提示先显示
	if (fgets(plaintext, sizeof(plaintext), stdin) == NULL) {
		fprintf(stderr, "Error reading plaintext.\n");
		return 1;
	}
	plaintext[strcspn(plaintext, "\n")] = '\0'; // 去除换行符

	size_t plaintext_len = strlen(plaintext);

	// 打印输入的密码和明文（调试信息）
	//printf("Password: %s\n", password);
	//printf("Plaintext: %s\n", plaintext);

	// 生成 Salt
	if (secure_random(salt, sizeof(salt)) != 0) {
		fprintf(stderr, "Failed to generate salt.\n");
		return 1;
	}

	// 打印 Salt（调试信息）
	printf("Salt: ");
	for (size_t i = 0; i < sizeof(salt); i++) {
		printf("%02x", salt[i]);
	}
	printf("\n");

	// 生成 PBKDF2 密钥
	PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS, sizeof(derived_key), derived_key);

	// 打印 derived_key（调试信息）
	printf("Derived Key: ");
	for (size_t i = 0; i < sizeof(derived_key); i++) {
		printf("%02x", derived_key[i]);
	}
	printf("\n");

	if (mode == 0) {
		// 生成随机 IV
		if (secure_random(iv, sizeof(iv)) != 0) {
			fprintf(stderr, "Failed to generate IV.\n");
			return 1;
		}

		// 打印 IV（调试信息）
		printf("IV: ");
		for (size_t i = 0; i < sizeof(iv); i++) {
			printf("%02x", iv[i]);
		}
		printf("\n");

		unsigned char padded_text[256];  // 定义一个足够大的缓冲区
		padded_len = pkcs7_pad((unsigned char*)plaintext, plaintext_len, padded_text);

		if (!padded_len) {
			fprintf(stderr, "Padding error.\n");
			return 1;
		}


		// 打印填充后的数据（调试信息）
		printf("Padded text: ");
		for (size_t i = 0; i < padded_len; i++) {
			printf("%02x", padded_text[i]);
		}
		printf("\n");

		uint8_t ks[140 * 4];  // Serpent 可能使用较大的密钥调度表
		serpent_set_key(derived_key, ks);

		// 将 derived_key 转换为 HEX 字符串
		char* hex_key = uint8_to_hex_string(derived_key, sizeof(derived_key));

		// CBC 手动 XOR IV 和加密块
		unsigned char* ciphertext = (unsigned char*)malloc(padded_len);
		if (!ciphertext) {
			//free(padded_text);
			//free(hex_key);
			return 1;
		}

		unsigned char block[BLOCK_SIZE];
		unsigned char* prev_cipher = iv; // 初始 CBC IV

		for (size_t i = 0; i < padded_len; i += BLOCK_SIZE) {
			// XOR 明文和前一块密文（或 IV）
			for (size_t j = 0; j < BLOCK_SIZE; j++) {
				block[j] = padded_text[i + j] ^ prev_cipher[j];
			}

			// 打印每一块 XOR 操作后的数据（调试信息）
			//printf("Block after XOR: ");
			//for (size_t j = 0; j < BLOCK_SIZE; j++) {
			//	printf("%02x", block[j]);
			//}
			//printf("\n");

			// 加密
			serpent_encrypt(block, ciphertext + i, ks);

			// 更新 prev_cipher（当前密文作为下一块的 IV）
			prev_cipher = ciphertext + i;
		}

		// 打印加密后的密文（调试信息）
		//printf("Ciphertext: ");
		//for (size_t i = 0; i < padded_len; i++) {
		//	printf("%02x", ciphertext[i]);
		//}
		//printf("\n");

		// 组合输出（Salt + IV + Ciphertext）
		size_t total_len = sizeof(salt) + sizeof(iv) + padded_len;
		unsigned char* output = (unsigned char*)malloc(total_len);

		memcpy(output, salt, sizeof(salt));
		memcpy(output + sizeof(salt), iv, sizeof(iv));
		memcpy(output + sizeof(salt) + sizeof(iv), ciphertext, padded_len);

		// 转换成 HEX 输出
		char* hex_output = uint8_to_hex_string(output, total_len);

		printf("Encrypted (Salt + IV + Ciphertext) HEX:\n%s\n", hex_output);

		// 释放内存
		//free(padded_text);
		free(ciphertext);
		free(output);
		free(hex_output);
		free(hex_key);
	}
	else if (mode == 1) {

		uint_8t nonce[NONCE_SIZE], tag[TAG_SIZE];
		//uint8_t* buffer = (uint8_t*)malloc(GCM_BLOCK_SIZE);

		// 生成随机 nonce
		if (secure_random(nonce, sizeof(nonce)) != 0) {
			fprintf(stderr, "Failed to generate nonce.\n");
			return 1;
		}

		// 打印 nonce（调试信息）
		printf("nonce: ");
		for (size_t i = 0; i < sizeof(nonce); i++) {
			printf("%02x", nonce[i]);
		}
		printf("\n");

		unsigned char* encrypted_text = (unsigned char*)malloc(plaintext_len);
		if (!encrypted_text) {
			fprintf(stderr, "Memory allocation failed for encrypted text.\n");
			return 1;
		}


		gcm_encrypt((unsigned char*)plaintext, plaintext_len, derived_key, nonce, tag, encrypted_text);
		
		printf("Encrypted: ");
		for (size_t i = 0; i < plaintext_len; i++) printf("%02X ", plaintext[i]);
		printf("\nTag: ");
		for (size_t i = 0; i < 16; i++) printf("%02X ", tag[i]);
		printf("\n");
		// 组合输出（Salt + iv + Tag + Ciphertext）
		size_t total_len = sizeof(salt) + sizeof(nonce) + sizeof(tag) + plaintext_len;
		unsigned char* output = (unsigned char*)malloc(total_len);

		memcpy(output, salt, sizeof(salt));
		memcpy(output + sizeof(salt), nonce, sizeof(nonce));
		memcpy(output + sizeof(salt) + sizeof(nonce), tag, sizeof(tag));
		memcpy(output + sizeof(salt) + sizeof(nonce) + sizeof(tag), encrypted_text, plaintext_len);

		// 转换成 HEX 输出
		char* hex_output = uint8_to_hex_string(output, total_len);
		printf("Encrypted (Salt + nonce + Ciphertext) HEX:\n%s\n", hex_output);

	}
	return 0;

}
int dec(int mode) {
	uint8_t salt[SALT_SIZE], iv[IV_SIZE], tag[TAG_SIZE], nonce[NONCE_SIZE], derived_key[KEY_SIZE];
	char password[256];
	char hex_input[4096]; // 用户输入的 HEX 密文
	unsigned char* ciphertext;
	size_t ciphertext_len;

	// 获取用户输入的密码
	printf("Please enter password: ");
	fflush(stdout);  // 确保提示先显示
	if (fgets(password, sizeof(password), stdin) == NULL) {
		fprintf(stderr, "Error reading password.\n");
		return 1;
	}
	password[strcspn(password, "\n")] = '\0'; // 去除换行符

	// 获取用户输入的 HEX 密文
	printf("Please enter encrypted HEX: ");
	fflush(stdout);  // 确保提示先显示
	if (fgets(hex_input, sizeof(hex_input), stdin) == NULL) {
		fprintf(stderr, "Error reading encrypted HEX.\n");
		return 1;
	}
	hex_input[strcspn(hex_input, "\n")] = '\0'; // 去除换行符
	if (mode == 0) {
		// 计算密文长度（HEX 代表的是 16 进制，每 2 个字符 = 1 个字节）
		size_t total_len = strlen(hex_input) / 2;
		if (total_len < sizeof(salt) + sizeof(iv)) {
			fprintf(stderr, "Invalid input length.\n");
			return 1;
		}

		// 解析 Salt, IV, Ciphertext
		hex_to_uint8(hex_input, salt, sizeof(salt));
		hex_to_uint8(hex_input + 2 * sizeof(salt), iv, sizeof(iv));

		ciphertext_len = total_len - sizeof(salt) - sizeof(iv);
		ciphertext = (unsigned char*)malloc(ciphertext_len);
		if (!ciphertext) {
			fprintf(stderr, "Memory allocation error.\n");
			return 1;
		}

		hex_to_uint8(hex_input + 2 * (sizeof(salt) + sizeof(iv)), ciphertext, ciphertext_len);

		// 输出调试信息
		printf("Salt: ");
		for (size_t i = 0; i < sizeof(salt); i++) {
			printf("%02x", salt[i]);
		}
		printf("\n");

		printf("IV: ");
		for (size_t i = 0; i < sizeof(iv); i++) {
			printf("%02x", iv[i]);
		}
		printf("\n");

		// 生成 PBKDF2 密钥
		PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS, sizeof(derived_key), derived_key);

		// 打印 derived_key
		printf("Derived Key: ");
		for (size_t i = 0; i < sizeof(derived_key); i++) {
			printf("%02x", derived_key[i]);
		}
		printf("\n");

		// 将 derived_key 转换为 HEX 字符串
		char* hex_key = uint8_to_hex_string(derived_key, sizeof(derived_key));

		uint8_t ks[140 * 4];  // Serpent 可能使用较大的密钥调度表
		serpent_set_key(derived_key, ks);

		// CBC 手动处理
		unsigned char* decrypted_text = (unsigned char*)malloc(ciphertext_len);
		if (!decrypted_text) {
			free(ciphertext);
			free(hex_key);
			return 1;
		}

		unsigned char block[BLOCK_SIZE];
		unsigned char prev_cipher[BLOCK_SIZE];
		memcpy(prev_cipher, iv, BLOCK_SIZE); // 初始 IV

		for (size_t i = 0; i < ciphertext_len; i += BLOCK_SIZE) {
			// 复制当前密文块
			memcpy(block, ciphertext + i, BLOCK_SIZE);

			// 先解密
			serpent_decrypt(block, block, ks);

			// XOR 还原明文
			for (size_t j = 0; j < BLOCK_SIZE; j++) {
				decrypted_text[i + j] = block[j] ^ prev_cipher[j];
			}

			// 更新 prev_cipher（当前密文块）
			memcpy(prev_cipher, ciphertext + i, BLOCK_SIZE);
		}

		// 移除 PKCS#7 填充
		size_t plain_len = pkcs7_unpad(decrypted_text, ciphertext_len);

		// 输出解密后的明文
		printf("Decrypted plaintext: ");
		fwrite(decrypted_text, 1, plain_len, stdout);
		printf("\n");

		// 释放内存
		free(ciphertext);
		free(decrypted_text);
		free(hex_key);
	}
	else if (mode == 1) {
		// 计算密文长度（HEX 代表的是 16 进制，每 2 个字符 = 1 个字节）
		size_t total_len = strlen(hex_input) / 2;
		if (total_len < sizeof(salt) + sizeof(nonce) + sizeof(tag)) {
			fprintf(stderr, "Invalid input length.\n");
			return 1;
		}

		// 解析 Salt, nonce, Tag, Ciphertext
		hex_to_uint8(hex_input, salt, sizeof(salt));
		hex_to_uint8(hex_input + 2 * sizeof(salt), nonce, sizeof(nonce));
		hex_to_uint8(hex_input + 2 * (sizeof(salt)+sizeof(nonce)), tag, sizeof(tag));

		ciphertext_len = total_len - sizeof(salt) - sizeof(nonce) -sizeof(tag);
		ciphertext = (unsigned char*)malloc(ciphertext_len);
		if (!ciphertext) {
			fprintf(stderr, "Memory allocation error.\n");
			return 1;
		}

		hex_to_uint8(hex_input + 2 * (sizeof(salt) + sizeof(nonce) + sizeof(tag)), ciphertext, ciphertext_len);

		// 输出调试信息
		printf("Salt: ");
		for (size_t i = 0; i < sizeof(salt); i++) {
			printf("%02x", salt[i]);
		}
		printf("\n");

		printf("nonce: ");
		for (size_t i = 0; i < sizeof(nonce); i++) {
			printf("%02x", nonce[i]);
		}
		printf("\n");

		printf("Tag: ");
		for (size_t i = 0; i < sizeof(tag); i++) {
			printf("%02x", tag[i]);
		}
		printf("\n");


		// 生成 PBKDF2 密钥
		PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS, sizeof(derived_key), derived_key);

		// 打印 derived_key
		printf("Derived Key: ");
		for (size_t i = 0; i < sizeof(derived_key); i++) {
			printf("%02x", derived_key[i]);
		}
		printf("\n");

		// 将 derived_key 转换为 HEX 字符串
		//char* hex_key = uint8_to_hex_string(derived_key, sizeof(derived_key));

		// 输出解密后的明文
		if (gcm_decrypt(ciphertext, ciphertext_len, derived_key, nonce, tag) == 0) {
			// 添加 NULL 终止符
			ciphertext[ciphertext_len] = '\0';
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
		// 释放内存
		free(ciphertext);
		//free(decrypted_text);
		//free(hex_key);
	}
	return 0;

}
static int enc_file(int mode) {
	// 获取用户输入的密码
	char password[256];
	char input_path[256], output_path[256];

	printf("Please enter password: ");
	fflush(stdout);
	if (fgets(password, sizeof(password), stdin) == NULL) {
		fprintf(stderr, "Error reading password.\n");
		return 1;
	}
	password[strcspn(password, "\n")] = '\0';

	printf("Enter input file path: ");
	fflush(stdout);
	if (fgets(input_path, sizeof(input_path), stdin) == NULL) {
		fprintf(stderr, "Error reading input_path.\n");
		return 1;
	}
	input_path[strcspn(input_path, "\n")] = '\0';

	printf("Enter output file path: ");
	fflush(stdout);
	if (fgets(output_path, sizeof(output_path), stdin) == NULL) {
		fprintf(stderr, "Error reading output_path.\n");
		return 1;
	}
	output_path[strcspn(output_path, "\n")] = '\0';

	FILE* infile, * outfile;
	// 打开输入和输出文件
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

	if (mode == 0) {
		uint8_t salt[SALT_SIZE], iv[IV_SIZE], derived_key[KEY_SIZE], nonce[NONCE_SIZE];
		// 生成 Salt 和 IV
		if (secure_random(salt, sizeof(salt)) != 0 || secure_random(iv, sizeof(iv)) != 0) {
			fprintf(stderr, "Failed to generate salt or IV.\n");
			return 1;
		}

		// 生成 PBKDF2 密钥
		PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS, sizeof(derived_key), derived_key);

		// Serpent 密钥调度
		uint8_t ks[140 * 4];
		serpent_set_key(derived_key, ks);


		// 写入 Salt 和 IV
		fwrite(salt, 1, sizeof(salt), outfile);
		fwrite(iv, 1, sizeof(iv), outfile);

		uint8_t buffer[BLOCK_SIZE], padded_block[BLOCK_SIZE];
		size_t read_len;
		uint8_t prev_cipher[BLOCK_SIZE];
		memcpy(prev_cipher, iv, BLOCK_SIZE);  // 初始 IV

		while ((read_len = fread(buffer, 1, BLOCK_SIZE, infile)) > 0) {
			memset(padded_block, 0, BLOCK_SIZE);  // 关键修正，防止旧数据影响

			// 仅对最后一块数据进行 PKCS#7 填充
			if (read_len < BLOCK_SIZE) {
				pkcs7_pad(buffer, read_len, padded_block);
			}
			else {
				memcpy(padded_block, buffer, BLOCK_SIZE);
			}

			// CBC XOR
			for (size_t i = 0; i < BLOCK_SIZE; i++) {
				padded_block[i] ^= prev_cipher[i];
			}

			// Serpent 加密
			serpent_encrypt(padded_block, padded_block, ks);

			// **更新 prev_cipher，确保存储的是当前密文**
			memcpy(prev_cipher, padded_block, BLOCK_SIZE);

			// 写入密文
			fwrite(padded_block, 1, BLOCK_SIZE, outfile);
		}

		fclose(infile);
		fclose(outfile);
	}
	else if (mode == 1) {

		uint8_t salt[SALT_SIZE], nonce[NONCE_SIZE], tag[TAG_SIZE], derived_key[KEY_SIZE];
		uint8_t* buffer = (uint8_t*)malloc(GCM_BLOCK_SIZE);
		uint8_t* cipher = (uint8_t*)malloc(GCM_BLOCK_SIZE);

		if (!buffer)  
		{
			// 代码逻辑...
			handle_error("Memory allocation failed");
			free(buffer);
		}


		// 生成随机 Salt
		if (secure_random(salt, SALT_SIZE) != 0) handle_error("Failed to generate salt");

		// 生成 PBKDF2 密钥
		PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, SALT_SIZE, ITERATIONS, KEY_SIZE, derived_key);

		// 先写入 Salt
		fwrite(salt, 1, sizeof(salt), outfile);

		printf("SALT: ");
		for (size_t i = 0; i < sizeof(salt); i++) {
			printf("%02x", salt[i]);
		}
		printf("\n");


		printf("Derived Key: ");
		for (size_t i = 0; i < sizeof(derived_key); i++) {
			printf("%02x", derived_key[i]);
		}
		printf("\n");

		size_t bytes_read;
		while ((bytes_read = fread(buffer, 1, GCM_BLOCK_SIZE, infile)) > 0) {
			// 生成随机 Nonce
			if (secure_random(nonce, NONCE_SIZE) != 0) handle_error("Failed to generate nonce");

			// 加密
			gcm_encrypt(buffer, bytes_read, derived_key, nonce, tag, cipher);

			// 写入 Nonce, Tag, Ciphertext
			fwrite(nonce, 1, 12, outfile);
			fwrite(tag, 1, 16, outfile);
			fwrite(cipher, 1, bytes_read, outfile);

			printf("nonce: ");
			for (size_t i = 0; i < sizeof(nonce); i++) {
				printf("%02x", nonce[i]);
			}
			printf("\n");

			printf("tag: ");
			for (size_t i = 0; i < sizeof(tag); i++) {
				printf("%02x", tag[i]);
			}
			printf("\n");


		}
		free(buffer);
		free(cipher);
		fclose(outfile);
		fclose(infile);

	}
	return 0;
}
int dec_file(int mode) {
	// 获取用户输入的密码
	char password[256];
	printf("Please enter password: ");
	fflush(stdout);
	if (fgets(password, sizeof(password), stdin) == NULL) {
		fprintf(stderr, "Error reading password.\n");
		return 1;
	}
	password[strcspn(password, "\n")] = '\0';


	char input_path[256], output_path[256];

	printf("Enter input file path: ");
	fflush(stdout);
	if (fgets(input_path, sizeof(input_path), stdin) == NULL) {
		fprintf(stderr, "Error reading input_path.\n");
		return 1;
	}
	input_path[strcspn(input_path, "\n")] = '\0';

	printf("Enter output file path: ");
	fflush(stdout);
	if (fgets(output_path, sizeof(output_path), stdin) == NULL) {
		fprintf(stderr, "Error reading output_path.\n");
		return 1;
	}
	output_path[strcspn(output_path, "\n")] = '\0';

	FILE* infile, * outfile;


	// 读取输入文件
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

	if (mode == 0) {
		uint8_t salt[SALT_SIZE], iv[IV_SIZE], derived_key[KEY_SIZE];
		// 读取 Salt 和 IV
		fread(salt, 1, sizeof(salt), infile);
		fread(iv, 1, sizeof(iv), infile);

		// 生成 PBKDF2 密钥
		PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, sizeof(salt), ITERATIONS, sizeof(derived_key), derived_key);

		// Serpent 密钥调度
		uint8_t ks[140 * 4];
		serpent_set_key(derived_key, ks);

		uint8_t buffer[BLOCK_SIZE], decrypted_block[BLOCK_SIZE];
		uint8_t prev_cipher[BLOCK_SIZE];
		memcpy(prev_cipher, iv, BLOCK_SIZE);
		size_t read_len;

		while ((read_len = fread(buffer, 1, BLOCK_SIZE, infile)) > 0) {
			memcpy(decrypted_block, buffer, BLOCK_SIZE);

			// 先解密
			serpent_decrypt(decrypted_block, decrypted_block, ks);

			// XOR 还原明文
			for (size_t i = 0; i < BLOCK_SIZE; i++) {
				decrypted_block[i] ^= prev_cipher[i];
			}

			memcpy(prev_cipher, buffer, BLOCK_SIZE);

			// 移除 PKCS#7 填充（仅处理最后一块）
			if (feof(infile)) {
				size_t plain_len = pkcs7_unpad(decrypted_block, BLOCK_SIZE);
				fwrite(decrypted_block, 1, plain_len, outfile);
			}
			else {
				fwrite(decrypted_block, 1, BLOCK_SIZE, outfile);
			}
		}
	}
	else if (mode == 1) {
		uint8_t salt[SALT_SIZE], nonce[NONCE_SIZE], tag[TAG_SIZE], derived_key[KEY_SIZE];

		// 读取 Salt
		if (fread(salt, 1, 16, infile) != 16) handle_error("Failed to read salt");

		// 生成 PBKDF2 密钥
		PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt, 16, ITERATIONS, 32, derived_key);
		printf("Derived Key: ");
		for (size_t i = 0; i < sizeof(derived_key); i++) {
			printf("%02x", derived_key[i]);
		}
		printf("\n");

		uint8_t* ciphertext = (uint8_t*)malloc(GCM_BLOCK_SIZE);
		if (!ciphertext) handle_error("Memory allocation failed");

		size_t bytes_read;
		while ((bytes_read = fread(nonce, 1, 12, infile)) == 12) {
			printf("NONCE: ");
			for (size_t i = 0; i < sizeof(nonce); i++) {
				printf("%02x", nonce[i]);
			}
			printf("\n");

			// 读取 Tag
			if (fread(tag, 1, 16, infile) != 16) handle_error("Failed to read tag");
			printf("TAG: ");
			for (size_t i = 0; i < sizeof(tag); i++) {
				printf("%02x", tag[i]);
			}
			printf("\n");

			// 读取密文
			size_t ciphertext_len = fread(ciphertext, 1, GCM_BLOCK_SIZE, infile);
			if (ciphertext_len == 0) handle_error("Failed to read ciphertext");

			// 解密
			if (gcm_decrypt(ciphertext, ciphertext_len, derived_key, nonce, tag) != 0) {
				handle_error("Authentication failed!");
			}

			// 写入解密后的数据
			fwrite(ciphertext, 1, ciphertext_len, outfile);
		}

		// 清理资源
		free(ciphertext);

	}

	fclose(infile);
	fclose(outfile);
	return 0;
}
int main() {
	//_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF); // 启用内存泄漏检测

	do {
		printf("SuperSerpent, PBKDF2 with Whirlpool, Iter 10000, salt 16, iv 16, nonce 12, tag 16\n");
		fflush(stdout);
		printf("Select function: \n1.Encryption    2.Decryption\n3.Encrypt File    4.Decrypt File\n5.GCM Encryption    6.GCM Decryption\n7.GCM Encrypt File    8.GCM Decrypt File\nMake selection: ");
		fflush(stdout);
		char input[10];  // 用于存储用户输入
		fgets(input, sizeof(input), stdin);
		if (input[0] == '1') {
			if (enc(0) == 0) {
				printf("Succerss encrypted\n");
			}
		}
		else if (input[0] == '2') {
			if (dec(0) == 0) {
				printf("Succerss decrypted\n");
			}
		}
		else if (input[0] == '3') {
			if (enc_file(0) == 0) {
				printf("Succerss encrypted\n");
			}
		}
		else if (input[0] == '4') {
			if (dec_file(0) == 0) {
				printf("Succerss decrypted\n");
			}
		}
		else if (input[0] == '5') {
			if (enc(1) == 0) {
				printf("Succerss encrypted\n");
			}
		}
		else if (input[0] == '6') {
			if (dec(1) == 0) {
				printf("Succerss decrypted\n");
			}
		}
		else if (input[0] == '7') {
			if (enc_file(1) == 0) {
				printf("Succerss encrypted\n");
			}
		}
		else if (input[0] == '8') {
			if (dec_file(1) == 0) {
				printf("Succerss decrypted\n");
			}
		}

		else {
			break;
		}
	} while (1);
	return 0;
}
