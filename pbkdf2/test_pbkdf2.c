#include <stdio.h>
#include <stdint.h>
#include "whirlpool/Whirlpool.h"
#include "pbkdf2/pbkdf2.h"

int main() {
    uint8_t password[] = "mypassword";
    uint8_t salt[] = "random_salt";
    uint8_t derived_key[32]; 
    int iterations = 1000;

    PBKDF2_HMAC_Whirlpool(password, strlen((char *)password), 
                          salt, strlen((char *)salt), 
                          iterations, sizeof(derived_key), 
                          derived_key);

    printf("Derived Key: ");
    for (int i = 0; i < sizeof(derived_key); i++) {
        printf("%02x", derived_key[i]);
    }
    printf("\n");

    return 0;
}
