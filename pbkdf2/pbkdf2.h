#ifndef HMAC_WHIRLPOOL_H
#define HMAC_WHIRLPOOL_H

#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#define STATIC_ASSERT_SLOTH(cond, msg) typedef char static_assertion_##msg[(cond) ? 1 : -1]

#include "../params.h"
#include "whirlpool/Whirlpool.h"  // WHIRLPOOL_* API
typedef struct {
    WHIRLPOOL_CTX inner;
    WHIRLPOOL_CTX outer;
    uint8_t o_key_pad[BLOCK_SIZE_WHIRLPOOL_SLOTH];
} HMAC_Whirlpool_CTX ;

STATIC_ASSERT_SLOTH(sizeof(HMAC_Whirlpool_CTX) ==
    sizeof(WHIRLPOOL_CTX) * 2 + BLOCK_SIZE_WHIRLPOOL_SLOTH, ctx_size_mismatch);

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Compute HMAC-Whirlpool Value
 * @param key The Key
 * @param key_len Bytes Length of Key
 * @param message Input Message
 * @param message_len Bytes Length of Message
 * @param output Output HMAC Result (Must be At Least 64 Bytes)
 */
void HMAC_Whirlpool(const uint8_t *key, size_t key_len, 
                    const uint8_t *message, size_t message_len, 
                    uint8_t *output);

/**
 * @brief Computer PBKDF2-HMAC-Whirlpool Derieved Key
 * @param password Input Password
 * @param password_len Bytes Length of Password
 * @param salt Input Salt
 * @param salt_len Bytes Length of Salt
 * @param iterations Iterations Counts
 * @param key_len Needed Bytes Length of Target Key
 * @param output Output Key (Need Caller Provides Enought Length)
 */
void PBKDF2_HMAC_Whirlpool(const uint8_t *password, int password_len, 
                           const uint8_t *salt, int salt_len, 
                           int iterations, int key_len, 
                           uint8_t *output);

void HMAC_Whirlpool_Init(HMAC_Whirlpool_CTX* ctx, const uint8_t* key, size_t key_len);
void HMAC_Whirlpool_Update(HMAC_Whirlpool_CTX* ctx, const uint8_t* data, size_t len);
void HMAC_Whirlpool_Final(HMAC_Whirlpool_CTX* ctx, uint8_t* output);

#ifdef __cplusplus
}
#endif

#endif // HMAC_WHIRLPOOL_H
