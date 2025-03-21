#ifndef HMAC_WHIRLPOOL_H
#define HMAC_WHIRLPOOL_H

#include <stdint.h>
#include <stddef.h>

#define BLOCK_SIZE_WHIRLPOOL 64   // 512-bit Whirlpool 使用的块大小
#define OUTPUT_SIZE 64  // 512-bit Whirlpool 哈希输出大小

#include "whirlpool/Whirlpool.h"  // WHIRLPOOL_* API

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 计算 HMAC-Whirlpool 值。
 * @param key 密钥
 * @param key_len 密钥长度（字节）
 * @param message 输入消息
 * @param message_len 消息长度（字节）
 * @param output 输出 HMAC 结果（必须至少为 64 字节）
 */
void HMAC_Whirlpool(const uint8_t *key, size_t key_len, 
                    const uint8_t *message, size_t message_len, 
                    uint8_t *output);

/**
 * @brief 计算 PBKDF2-HMAC-Whirlpool 派生密钥。
 * @param password 输入密码
 * @param password_len 密码长度（字节）
 * @param salt 输入盐值
 * @param salt_len 盐值长度（字节）
 * @param iterations 迭代次数
 * @param key_len 需要派生的密钥长度（字节）
 * @param output 生成的密钥（调用者需要分配足够的空间）
 */
void PBKDF2_HMAC_Whirlpool(const uint8_t *password, int password_len, 
                           const uint8_t *salt, int salt_len, 
                           int iterations, int key_len, 
                           uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif // HMAC_WHIRLPOOL_H
