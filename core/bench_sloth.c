#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../pbkdf2/pbkdf2.h"
#include "../pbkdf2/whirlpool/Whirlpool.h"
#include "utils_sloth.h"

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
