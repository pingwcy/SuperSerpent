#include <stdio.h>
#include <string.h>
#include "Serpent.h"

void print_block(const unsigned __int8 *block, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", block[i]);
    }
    printf("\n");
}

int main() {
    // 密钥，32字节长度
    unsigned __int8 userKey[32] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0x7f, 0x35, 0x6d, 0x34, 0xd8, 0x22, 0xa1, 0x5a,
        0x6e, 0x18, 0x3e, 0x4a, 0x2f, 0x77, 0x2b, 0x4d,
        0x6b, 0x52, 0x57, 0x2a, 0x41, 0x39, 0x75, 0x60
    };

    unsigned __int8 ks[256];  // 密钥调度表
    unsigned __int8 inBlock[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                                    0x31, 0x31, 0x98, 0xa2, 0x4e, 0x45, 0x67, 0x9b};  // 明文块
    unsigned __int8 encryptedBlock[16];  // 加密后的密文块
    unsigned __int8 decryptedBlock[16];  // 解密后的明文块

    // 设置密钥
    serpent_set_key(userKey, ks);

    // 输出原始明文
    printf("Original Plaintext:\n");
    print_block(inBlock, sizeof(inBlock));

    // 加密
    serpent_encrypt(inBlock, encryptedBlock, ks);
    printf("Encrypted Ciphertext:\n");
    print_block(encryptedBlock, sizeof(encryptedBlock));

    // 解密
    serpent_decrypt(encryptedBlock, decryptedBlock, ks);
    printf("Decrypted Plaintext:\n");
    print_block(decryptedBlock, sizeof(decryptedBlock));

    // 校验解密后的明文是否与原始明文相同
    if (memcmp(inBlock, decryptedBlock, sizeof(inBlock)) == 0) {
        printf("Decryption successful: Plaintext matches original.\n");
    } else {
        printf("Decryption failed: Plaintext does not match original.\n");
    }

    return 0;
}
