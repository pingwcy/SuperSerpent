#include "serpent.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *serpent_convert_to_string();
void serpent_convert_from_string(int bits, const char *hex, unsigned long *data);

int main()
{
    unsigned long ciphertext[4]; // Ciper Text
    unsigned long plaintext[4];  // Decrypted Text
    char tmpstr[100];

    keyInstance keyI;
    cipherInstance cipherI;

    // Init
    if (cipherInit(&cipherI, MODE_ECB, "") <= 0)
    {
        printf("Cipher initialization failed.\n");
        exit(1);
    }

    // Set key
    if (makeKey(&keyI, DIR_DECRYPT, 128, "00000000000000000000000000000000") <= 0)
    {
        printf("Key setup failed.\n");
        exit(1);
    }

    // Set Cipher text
    serpent_convert_from_string(128, "E2F0D6E455C14D3B7D7FA20F6886A0C7", ciphertext);

    // Output key and cipher text
    printf("KEY=%s\n", serpent_convert_to_string(128, keyI.key, tmpstr));
    printf("CT =%s\n", serpent_convert_to_string(128, ciphertext, tmpstr));

    // Decrypt
    if (blockDecrypt(&cipherI, &keyI, (BYTE *)ciphertext, 128, (BYTE *)plaintext) <= 0)
    {
        printf("Decryption failed.\n");
        exit(1);
    }

    // Output decrypted text
    printf("PT =%s\n", serpent_convert_to_string(128, plaintext, tmpstr));

    return 0;
}
