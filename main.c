#include "vcserpent/Serpent.h" 
#include "pbkdf2/pbkdf2.h"
#include "rand/rand.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 16    // 128-bit (16 bytes)
#define ITERATIONS 10000 // PBKDF2 迭代次数
#define MAX_INPUT_LEN 1024

void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
        // 忽略所有剩余的字符直到换行或文件结束
    }
}
int safe_fgets(char *buffer, size_t buffer_size) {
    if (fgets(buffer, buffer_size, stdin) == NULL) {
        return 0; // 输入失败
    }

    // 去除输入中的换行符（如果有）
    buffer[strcspn(buffer, "\n")] = '\0';

    return 1; // 输入成功
}

// PKCS#7 填充
size_t pkcs7_pad(unsigned char* input, size_t len, unsigned char** output) {
    size_t pad_len = BLOCK_SIZE - (len % BLOCK_SIZE);
    size_t new_len = len + pad_len;

    *output = (unsigned char*)malloc(new_len);
    if (!*output) return 0;

    memcpy(*output, input, len);
    memset(*output + len, pad_len, pad_len);

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
int enc() {
    uint8_t salt[16], iv[16], derived_key[32];
    char password[256];
    char plaintext[1024]; // 用户输入的明文
    unsigned char* padded_text;
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
    printf("Password: %s\n", password);
    printf("Plaintext: %s\n", plaintext);

    // 生成 Salt
    if (get_random_bytes(salt, sizeof(salt)) != 0) {
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

    // 生成随机 IV
    if (get_random_bytes(iv, sizeof(iv)) != 0) {
        fprintf(stderr, "Failed to generate IV.\n");
        return 1;
    }

    // 打印 IV（调试信息）
    printf("IV: ");
    for (size_t i = 0; i < sizeof(iv); i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    // PKCS#7 填充
    padded_len = pkcs7_pad((unsigned char*)plaintext, plaintext_len, &padded_text);

    if (!padded_len) {
        fprintf(stderr, "Memory allocation error during padding.\n");
        return 1;
    }

    // 打印填充后的数据（调试信息）
    printf("Padded text: ");
    for (size_t i = 0; i < padded_len; i++) {
        printf("%02x", padded_text[i]);
    }
    printf("\n");

    // 初始化 Serpent 加密（ECB 模式）
    //keyInstance keyI;
    //cipherInstance cipherI;
    //if (cipherInit(&cipherI, MODE_ECB, NULL) <= 0) {
        //free(padded_text);
        //return 1;
    //}
    // 初始化 Serpent 密钥调度
    uint8_t ks[140 * 4];  // Serpent 可能使用较大的密钥调度表
    serpent_set_key(derived_key, ks);

    // 将 derived_key 转换为 HEX 字符串
    char* hex_key = uint8_to_hex_string(derived_key, sizeof(derived_key));
    //if (makeKey(&keyI, DIR_ENCRYPT, 256, hex_key) <= 0) {
        //free(padded_text);
        //free(hex_key);
        //return 1;
    //}

    // CBC 手动 XOR IV 和加密块
    unsigned char* ciphertext = (unsigned char*)malloc(padded_len);
    if (!ciphertext) {
        free(padded_text);
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
        printf("Block after XOR: ");
        for (size_t j = 0; j < BLOCK_SIZE; j++) {
            printf("%02x", block[j]);
        }
        printf("\n");

        // 加密
        serpent_encrypt(block, ciphertext + i, ks);

        // 更新 prev_cipher（当前密文作为下一块的 IV）
        prev_cipher = ciphertext + i;
    }

    // 打印加密后的密文（调试信息）
    printf("Ciphertext: ");
    for (size_t i = 0; i < padded_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

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
    free(padded_text);
    free(ciphertext);
    free(output);
    free(hex_output);
    free(hex_key);

    return 0;

}
int dec() {
    uint8_t salt[16], iv[16], derived_key[32];
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

    return 0;

}
int main() {
    printf("SuperSerpent, PBKDF2 with Whirlpool, Iter 10000, salt 16, iv 16\n");
    printf("Select function: \n1.Encryption\n2.Decryption\n");
    char input[10];  // 用于存储用户输入
    int sel;
    fgets(input, sizeof(input), stdin);
    if (input[0] == '1') {
        if (enc() == 1) {
            printf("Succerss encrypted");
        }
    }
    else if(input[0] == '2'){
        if (dec() == 1) {
            printf("Succerss decrypted");
        }
    }
    return 0;
}
