#include "serpent.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *serpent_convert_to_string();
void serpent_convert_from_string(int bits, const char *hex, unsigned long *data);

int main()
{
    unsigned long ciphertext[4]; // 密文
    unsigned long plaintext[4];  // 解密后的明文
    char tmpstr[100];

    keyInstance keyI;
    cipherInstance cipherI;

    // 初始化加密实例（ECB模式）
    if (cipherInit(&cipherI, MODE_ECB, "") <= 0)
    {
        printf("Cipher initialization failed.\n");
        exit(1);
    }

    // 设定 128-bit 密钥（16字节，全 0）
    if (makeKey(&keyI, DIR_DECRYPT, 128, "00000000000000000000000000000000") <= 0)
    {
        printf("Key setup failed.\n");
        exit(1);
    }

    // 设定 128-bit 密文（16字节，示例值，可替换）
    serpent_convert_from_string(128, "E2F0D6E455C14D3B7D7FA20F6886A0C7", ciphertext);

    // 输出密钥和密文
    printf("KEY=%s\n", serpent_convert_to_string(128, keyI.key, tmpstr));
    printf("CT =%s\n", serpent_convert_to_string(128, ciphertext, tmpstr));

    // 进行一次解密
    if (blockDecrypt(&cipherI, &keyI, (BYTE *)ciphertext, 128, (BYTE *)plaintext) <= 0)
    {
        printf("Decryption failed.\n");
        exit(1);
    }

    // 输出解密后的明文
    printf("PT =%s\n", serpent_convert_to_string(128, plaintext, tmpstr));

    return 0;
}
