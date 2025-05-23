#include <stdio.h>
#include <string.h>
#include "whirlpool.h"

void print_hash(const unsigned char *hash, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02X", hash[i]);
    }
    printf("\n");
}

int main() {
    // Test Data
    const char *test_string = "Hello, Whirlpool!";
    unsigned char hash_output[64];
    WHIRLPOOL_CTX ctx;

    // Initial Whirlpool CTX
    WHIRLPOOL_init(&ctx);
    
    // Input Process
    WHIRLPOOL_add((const unsigned char *)test_string, strlen(test_string), &ctx);
    
    // Compute value
    WHIRLPOOL_finalize(&ctx, hash_output);
    
    // Print Hash
    printf("Whirlpool Hash of '%s':\n", test_string);
    print_hash(hash_output, sizeof(hash_output));

    return 0;
}