#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define BLOCK_SIZE 64   // 512-bit = 64 bytes
#define OUTPUT_SIZE 64  // 512-bit Whirlpool 输出
#include "whirlpool/Whirlpool.h"  // 假设 WHIRLPOOL_* API 定义在这个头文件中

void HMAC_Whirlpool(const uint8_t *key, size_t key_len, 
    const uint8_t *message, size_t message_len, 
    uint8_t *output) {
uint8_t key_block[BLOCK_SIZE];  // 关键块
uint8_t o_key_pad[BLOCK_SIZE];  // 外部填充
uint8_t i_key_pad[BLOCK_SIZE];  // 内部填充
uint8_t inner_hash[OUTPUT_SIZE]; // 内部哈希结果
int i;

// 1. 处理密钥
if (key_len > BLOCK_SIZE) {
WHIRLPOOL_CTX key_ctx;
WHIRLPOOL_init(&key_ctx);
WHIRLPOOL_add(key, key_len, &key_ctx);
WHIRLPOOL_finalize(&key_ctx, key_block);
memset(key_block + OUTPUT_SIZE, 0, BLOCK_SIZE - OUTPUT_SIZE);
} else {
memcpy(key_block, key, key_len);
memset(key_block + key_len, 0, BLOCK_SIZE - key_len);
}

// 2. 生成 o_key_pad 和 i_key_pad
for (i = 0; i < BLOCK_SIZE; i++) {
o_key_pad[i] = key_block[i] ^ 0x5c;  // 外部填充
i_key_pad[i] = key_block[i] ^ 0x36;  // 内部填充
}

// 3. 计算内部哈希：hash(i_key_pad + message)
WHIRLPOOL_CTX inner_ctx;
WHIRLPOOL_init(&inner_ctx);
WHIRLPOOL_add(i_key_pad, BLOCK_SIZE, &inner_ctx);
WHIRLPOOL_add(message, message_len, &inner_ctx);
WHIRLPOOL_finalize(&inner_ctx, inner_hash);

// 4. 计算外部哈希：hash(o_key_pad + inner_hash)
WHIRLPOOL_CTX outer_ctx;
WHIRLPOOL_init(&outer_ctx);
WHIRLPOOL_add(o_key_pad, BLOCK_SIZE, &outer_ctx);
WHIRLPOOL_add(inner_hash, OUTPUT_SIZE, &outer_ctx);
WHIRLPOOL_finalize(&outer_ctx, output);
}


void PBKDF2_HMAC_Whirlpool(const uint8_t *password, int password_len, 
    const uint8_t *salt, int salt_len, 
    int iterations, int key_len, 
    uint8_t *output) {
    int hash_len = OUTPUT_SIZE;  
    int block_count = (key_len + hash_len - 1) / hash_len; // 计算需要多少块
    uint8_t U[OUTPUT_SIZE], T[OUTPUT_SIZE];  

for (int i = 1; i <= block_count; i++) {
// 动态分配 salt_block，避免固定大小问题
uint8_t *salt_block = (uint8_t *)malloc(salt_len + 4);
if (!salt_block) return;  // 处理 malloc 失败

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