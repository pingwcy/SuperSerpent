#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../pbkdf2/pbkdf2.h"
#include "../pbkdf2/whirlpool/Whirlpool.h"
#include "utils_sloth.h"
#include "../vcserpent/SerpentFast.h"

void bench_pbkdf2_sloth() {
    const char *password = "Suomalainen";
    const uint8_t salt[SALT_SIZE_SLOTH] = {
        0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff, 0x11, 0x22, 0x55, 0x66, 0x77, 0x88
    };
    uint8_t derived[KEY_SIZE_SLOTH + HMAC_WHIRLPOOL_KEY_SIZE_SLOTH];

    printf("PBKDF2-HMAC-WHIRLPOOL benchmark (%d iterations, %d rounds per call)\n",
           BENCH_ITERATIONS_SLOTH, ITERATIONS_SLOTH);

    double total = 0.0;
    for (int i = 0; i < BENCH_ITERATIONS_SLOTH; ++i) {
        double start = get_time_ms();

        PBKDF2_HMAC_Whirlpool((const uint8_t *)password, strlen(password),
                              salt, sizeof(salt), ITERATIONS_SLOTH,
                              sizeof(derived), derived);

        double end = get_time_ms();
        double delta = end - start;
        total += delta;
        printf("  [%2d] %.3f ms\n", i + 1, delta);
        print_hex_sloth("Derived key", derived, sizeof(derived));
    }

    double avg = total / BENCH_ITERATIONS_SLOTH;
    printf("Average time: %.3f ms\n", avg);
}

int benchmark_serpent_sloth() {
    // 准备密钥和密钥调度表
    const uint8_t key[KEY_SIZE_SLOTH] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t ks[SERPENT_KSSIZE_SLOTH];
    serpent_set_key(key, ks);

    // 分配缓冲区
    uint8_t *input = (uint8_t *)malloc(TEST_BUFFER_SIZE);
    uint8_t *output = (uint8_t *)malloc(TEST_BUFFER_SIZE);
    if (!input || !output) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    // 用随机数据填充输入缓冲区
    for (size_t i = 0; i < TEST_BUFFER_SIZE; ++i) {
        input[i] = (uint8_t)(rand() % 256);
    }

    size_t blocks = TEST_BUFFER_SIZE / BLOCK_SIZE_SLOTH;

    // 加密 benchmark
    double t_enc_start = get_time_ms();
    for (int r = 0; r < BENCH_ITERATIONS_SLOTH; ++r) {
        for (size_t i = 0; i < blocks; ++i) {
            serpent_encrypt(input + i * BLOCK_SIZE_SLOTH, output + i * BLOCK_SIZE_SLOTH, ks);
        }
    }
    double t_enc_end = get_time_ms();

    // 解密 benchmark
    double t_dec_start = get_time_ms();
    for (int r = 0; r < BENCH_ITERATIONS_SLOTH; ++r) {
        for (size_t i = 0; i < blocks; ++i) {
            serpent_decrypt(output + i * BLOCK_SIZE_SLOTH, input + i * BLOCK_SIZE_SLOTH, ks);
        }
    }
    double t_dec_end = get_time_ms();

    // Output
    double enc_total = t_enc_end - t_enc_start;
    double dec_total = t_dec_end - t_dec_start;
    double total_mb = (double)(TEST_BUFFER_SIZE * BENCH_ITERATIONS_SLOTH) / 1024 / 1024;

    printf("Serpent Benchmark (%d times, %d MB buffer per call):\n", BENCH_ITERATIONS_SLOTH, TEST_BUFFER_SIZE / 1024 / 1024);
    printf("  Encryption: %.2f ms (%.2f MB/s)\n", enc_total, total_mb / (enc_total / 1000.0));
    printf("  Decryption: %.2f ms (%.2f MB/s)\n", dec_total, total_mb / (dec_total / 1000.0));

    // Clean up
    free(input);
    free(output);
    return 0;
}
