#ifndef SUPERSERPENT_PARAMS_H
#define SUPERSERPENT_PARAMS_H

//The following values can be changed
#define ITERATIONS_SLOTH 10000 // PBKDF2 Iterations, can be set to higher if needed but remember this value when decrypting
#define ROUTE_LENGTH_SLOTH 256 //Already set to 256, but can be changed if needed
#define PWD_MAX_LENGTH_SLOTH 256 //Already large enough, but can be changed if needed


//NEVER CHANGE THE FOLLOWING VALUES
#define BLOCK_SIZE_SLOTH 16    // 128-bit (16 bytes) block size for serpent
#define GCM_BLOCK_SIZE_SLOTH 10*1024*1024
#define SALT_SIZE_SLOTH 16 // 128-bit salt size
#define IV_SIZE_SLOTH 16 // 128-bit IV size
#define NONCE_SIZE_SLOTH 12 //Only support 96-bit nonce
#define TAG_SIZE_SLOTH 16 // Only support 128-bit tag
#define KEY_SIZE_SLOTH 32 // Only support 256-bit keys
#define BLOCK_SIZE_WHIRLPOOL_SLOTH 64   // 512-bit Whirlpool Block size
#define OUTPUT_SIZE_SLOTH 64  // 512-bit Whirlpool digest size
#define PLAINTEXT_MAX_LENGTH_SLOTH 1024
#define MAX_INPUT_LEN_SLOTH 1024
#define PADDEDTEXT_MAX_LENGTH_SLOTH 2048
#define HEXINPUT_MAX_LENGTH_SLOTH 4096
#define SERPENT_KSSIZE_SLOTH 560 //140 * 4
#define HMAC_WHIRLPOOL_KEY_SIZE_SLOTH 32 //HMAC Key size
#define ENTROPY_POOL_SIZE_SLOTH 2048 //Entropy pool size
#define HASH_WHIRLPOOL_BUFFER_SIZE 512 //Buffer size for Whirlpool hash
#endif