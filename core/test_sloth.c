#include <stdio.h>
#include <string.h>
#include "../rand/rand.h"
#include "../pbkdf2/whirlpool/Whirlpool.h"
#include "../pbkdf2/pbkdf2.h"
#include "../vcserpent/SerpentFast.h"
#include "test_sloth.h"
#include "utils_sloth.h"

// ----------- RAND -----------
static int test_rand_sloth() {
    uint8_t content[512] = { 0 };
    if (secure_random(content, 512) != 0) {
        printf("[FAIL] test_rand_sloth: secure_random failed\n");
        return -1;
    }
    return 0;
}
// ----------- WHIRLPOOL -----------
static int test_whirl_sloth() {
    const char* plaintext = "Hello Sloth!";
    uint8_t key_block[BLOCK_SIZE_WHIRLPOOL_SLOTH];
    uint8_t answer[BLOCK_SIZE_WHIRLPOOL_SLOTH] = {
        0x63, 0x51, 0x8E, 0x4B, 0xF5, 0x49, 0xFD, 0x47,
        0x0E, 0x66, 0x74, 0xD8, 0xA6, 0xA4, 0x3F, 0x24,
        0x34, 0x5E, 0xEA, 0xE6, 0x36, 0x2A, 0x19, 0xF2,
        0xBB, 0x4E, 0xD4, 0xE2, 0x30, 0x76, 0x25, 0x9B,
        0x3E, 0x44, 0xCB, 0x30, 0x17, 0x7A, 0x12, 0x95,
        0xCE, 0x15, 0xF1, 0x7B, 0x12, 0x7F, 0xA8, 0x03,
        0xE2, 0x24, 0x38, 0x53, 0x33, 0x23, 0xB1, 0x96,
        0xAB, 0x41, 0x5D, 0xB8, 0xA2, 0x52, 0x4F, 0x87
    };

    WHIRLPOOL_CTX ctx;
    WHIRLPOOL_init(&ctx);
    WHIRLPOOL_add((const uint8_t*)plaintext, strlen(plaintext), &ctx);
    WHIRLPOOL_finalize(&ctx, key_block);

    if (memcmp(key_block, answer, sizeof(answer)) != 0) {
        printf("[FAIL] test_whirl_sloth: hash mismatch\n");
        print_hex_sloth("Expected", answer, sizeof(answer));
        print_hex_sloth("Got     ", key_block, sizeof(key_block));
        return -2;
    }
    return 0;
}
// ----------- SERPENT -----------
static int test_spt_sloth() {
    const uint8_t key[KEY_SIZE_SLOTH] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    uint8_t ks[SERPENT_KSSIZE_SLOTH];
    serpent_set_key(key, ks);

    uint8_t plain[BLOCK_SIZE_SLOTH] = {
        0x22, 0x11, 0xEE, 0xDD, 0xC4, 0xB3, 0xE7, 0xFA,
        0xA0, 0x1B, 0x1E, 0x12, 0x14, 0x1C, 0x56, 0x1B,
    };
    uint8_t cipher[BLOCK_SIZE_SLOTH];
    serpent_encrypt(plain, cipher, ks);

    uint8_t answer[BLOCK_SIZE_SLOTH] = {
        0x99, 0xEA, 0x24, 0xB5, 0x99, 0xAA, 0x21, 0x81,
        0xD9, 0x66, 0x60, 0xFA, 0x4C, 0xDA, 0xC7, 0x64
    };

    if (memcmp(cipher, answer, BLOCK_SIZE_SLOTH) != 0) {
        printf("[FAIL] test_spt_sloth: encryption output mismatch\n");
        print_hex_sloth("Expected", answer, BLOCK_SIZE_SLOTH);
        print_hex_sloth("Got     ", cipher, BLOCK_SIZE_SLOTH);
        return -3;
    }

    uint8_t decpl[BLOCK_SIZE_SLOTH];
    serpent_decrypt(cipher, decpl, ks);
    if (memcmp(plain, decpl, BLOCK_SIZE_SLOTH) != 0) {
        printf("[FAIL] test_spt_sloth: decryption output mismatch\n");
        print_hex_sloth("Plaintext", plain, BLOCK_SIZE_SLOTH);
        print_hex_sloth("Decrypted", decpl, BLOCK_SIZE_SLOTH);
        return -3;
    }
    return 0;
}
// ----------- PBKDF2 -----------
static int test_pbkdf2_sloth() {
    uint8_t salt[SALT_SIZE_SLOTH] = {
        0x08, 0x88, 0xE2, 0x04, 0xE2, 0xB5, 0xAE, 0xD9,
        0x09, 0x18, 0xB4, 0x9A, 0x76, 0xA4, 0xB8, 0xB2
    };
    char password[] = "Lappeenranta, Finland.";
    uint8_t master_key[KEY_SIZE_SLOTH + HMAC_WHIRLPOOL_KEY_SIZE_SLOTH];
    uint8_t answer[KEY_SIZE_SLOTH + HMAC_WHIRLPOOL_KEY_SIZE_SLOTH] = {
        0x8C, 0x37, 0x54, 0x56, 0xA3, 0x80, 0x7F, 0xA4,
        0xF6, 0xF1, 0xC5, 0xDF, 0x2D, 0xF0, 0xB4, 0x78,
        0xF9, 0x49, 0x7F, 0x22, 0xF6, 0x5C, 0x3D, 0xDA,
        0xB7, 0xEE, 0x0E, 0x65, 0x04, 0x1D, 0xE6, 0xB5,
        0x5B, 0x95, 0x49, 0xD1, 0x6F, 0x1C, 0x3E, 0x78,
        0x1E, 0x09, 0xEE, 0x4D, 0x85, 0xCE, 0x58, 0x8D,
        0x5E, 0x21, 0x1A, 0xCB, 0x22, 0x66, 0xC9, 0xBD,
        0x14, 0xDC, 0xEB, 0x8D, 0x12, 0x1B, 0xDE, 0x0D
    };

    PBKDF2_HMAC_Whirlpool((uint8_t*)password, strlen(password), salt,
        sizeof(salt), ITERATIONS_SLOTH, sizeof(master_key), master_key);

    if (memcmp(master_key, answer, sizeof(answer)) != 0) {
        printf("[FAIL] test_pbkdf2_sloth: key mismatch\n");
        print_hex_sloth("Expected", answer, sizeof(answer));
        print_hex_sloth("Got     ", master_key, sizeof(master_key));
        return -4;
    }
    return 0;
}
// ----------- MAIN TEST DRIVER -----------
int test_sloth() {
    int r;

    r = test_rand_sloth();
    if (r != 0) return r;

    r = test_whirl_sloth();
    if (r != 0) return r;

    r = test_spt_sloth();
    if (r != 0) return r;

    r = test_pbkdf2_sloth();
    if (r != 0) return r;

    //printf("[PASS] All tests passed.\n");
    return 0;
}
