#include <stdio.h>
#include <stdint.h>
#include "whirlpool/Whirlpool.h"
#include "pbkdf2.h"
int VERBOSE_SLOTH = 1;
int main() {
    uint8_t password[] = "test";
    
    uint8_t salt[64] = {
0x9e, 0x69, 0xb0, 0x16, 0xcc, 0xcf, 0x1f, 0xdf, 0x53, 0x33, 0xeb, 0x23, 0x9e, 0xcb, 0x3f, 0x25, 
0xf2, 0xea, 0xca, 0x5c, 0xa3, 0x9b, 0x68, 0x2d, 0xca, 0xa0, 0xd4, 0xe9, 0xb2, 0x0e, 0x8b, 0xaa, 
0xf0, 0xe9, 0x65, 0xad, 0x3c, 0xaa, 0xce, 0x4e, 0x94, 0xec, 0xed, 0xc1, 0x35, 0xfc, 0x50, 0x46, 
0x47, 0x28, 0x49, 0x90, 0x95, 0xca, 0x8c, 0x6d, 0xff, 0x32, 0x09, 0xf6, 0xce, 0x1c, 0xb5, 0xab    };

    uint8_t derived_key1[64]; 
    uint8_t derived_key2[64]; 

    int iterations = 500000;

    PBKDF2_HMAC_Whirlpool(password, strlen((char *)password), salt, sizeof(salt), iterations, sizeof(derived_key1), derived_key1);
    derive_key_whirlpool (password, strlen((char *)password), salt, sizeof(salt), iterations, derived_key2, sizeof(derived_key2));
    if (memcmp(derived_key1, derived_key2, sizeof(derived_key1)) == 0){
        printf("SAME\n");
    }

    printf("Derived Key1: ");
    for (int i = 0; i < sizeof(derived_key1); i++) {
        printf("%02x", derived_key1[i]);
    }
    printf("\n");

    printf("Derived Key2: ");
    for (int i = 0; i < sizeof(derived_key2); i++) {
        printf("%02x", derived_key2[i]);
    }
    printf("\n");

    return 0;
}
