#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "makevcvol_sloth.h"
#include "crypto_mode_sloth.h"
#include "../rand/rand.h"
#include "../pbkdf2/pbkdf2.h"
#include "utils_sloth.h"
#include "../params.h"

static int build_volume_header(uint8_t *out_buf, int volume_size, int sector_size, uint8_t *out_masterkey, int issecond, uint8_t *in_masterkey){
    uint8_t *p = out_buf;
    // 1. Write Salt
    if (secure_random(p, 64) != 0) return -1;
    p += 64;

    // 2. Write VERA
    memcpy(p, "VERA", 4);
    p += 4;

    // 3. Write 00 05 01 0b
    uint8_t fixed1[] = {0x00, 0x05, 0x01, 0x0b};
    memcpy(p, fixed1, 4);
    p += 4;

    // 4. Reserver CRC32 position for Masterkeys
    uint8_t *crc1_pos = p;
    memset(p, 0, 4);
    p += 4;

    // 5. Write 16 bytes 0
    memset(p, 0, 16); p += 16;

    // 6. Write 8 bytes 0
    memset(p, 0, 8); p += 8;

    // 7. Write 8 bytes volume size in big endian
    uint64_t vol_size = volume_size * 1024 * 1024 - 2 * VC_VOLUME_HEADER_SIZE;
    for (int i = 7; i >= 0; --i)
        *p++ = (vol_size >> (i * 8)) & 0xFF;

    // 8. Fixed 00 00 00 00 00 02 00 00
    uint8_t fixed2[] = {0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00};
    memcpy(p, fixed2, 8); p += 8;

    // 9. Re-Write Volume Size
    for (int i = 7; i >= 0; --i)
        *p++ = (vol_size >> (i * 8)) & 0xFF;

    // 10. Write 4 bytes 0
    memset(p, 0, 4); p += 4;

    // 11. Write 00 00 02 00
    //uint8_t fixed3[] = {0x00, 0x00, 0x02, 0x00};
    uint8_t fixed3[4];

    // Big Endian
    fixed3[0] = (sector_size >> 24) & 0xFF;
    fixed3[1] = (sector_size >> 16) & 0xFF;
    fixed3[2] = (sector_size >> 8) & 0xFF;
    fixed3[3] = sector_size & 0xFF;

    memcpy(p, fixed3, 4); p += 4;

    // 12. Write 120 bytes 0
    memset(p, 0, 120); p += 120;

    // 13. Reserver CRC32 position for content before masterkey
    uint8_t *crc2_pos = p;
    memset(p, 0, 4);
    p += 4;

    // 14. Write Master keys
    uint8_t *key64_pos = p;
    if (issecond == 1) {
        if (in_masterkey == NULL) return -1;
        memcpy(p, in_masterkey, 64);
    } else {
        if (secure_random(p, 64) != 0) return -1;
        if (out_masterkey != NULL) {
            memcpy(out_masterkey, p, 64);
        }
    }
    p += 64;

    // 15. Write 192 bytes 0
    memset(p, 0, 192);
    p += 192;

    // 16. Write 65536 random bytes
    if (secure_random(p, 65536) != 0) return -1;
    p += 65536;

    // === Re-Weite CRC32 ===

    // CRC32-1: key64 + 192 zero
    uint32_t crc1 = crc32_calculate_sloth(key64_pos, 256);
    crc1_pos[0] = (crc1 >> 24) & 0xFF;
    crc1_pos[1] = (crc1 >> 16) & 0xFF;
    crc1_pos[2] = (crc1 >> 8) & 0xFF;
    crc1_pos[3] = crc1 & 0xFF;

    // CRC32-2:  From Vera to keys
    uint8_t *vera_start = out_buf + 64;
    uint32_t crc2 = crc32_calculate_sloth(vera_start, 188);
    crc2_pos[0] = (crc2 >> 24) & 0xFF;
    crc2_pos[1] = (crc2 >> 16) & 0xFF;
    crc2_pos[2] = (crc2 >> 8) & 0xFF;
    crc2_pos[3] = crc2 & 0xFF;

    return 0;
}

int encrypt_and_save_header(uint8_t password[], int passwordlength, const char *filename, const uint8_t *plain_header, const int sec_siz) {
    const size_t salt_size = 64;

    uint8_t *ciphertext = (uint8_t *)malloc(VC_VOLUME_HEADER_SIZE);
    uint8_t saltcontent[64], master_key[64], key1[32], key2[32];
    if (ciphertext == NULL) {
        perror("Malloc failed");
        return EXIT_FAILURE;
    }

    // Copy Salt
    memcpy(ciphertext, plain_header, salt_size);
    memcpy(saltcontent, plain_header, salt_size);
    // Make Key
	PBKDF2_HMAC_Whirlpool((uint8_t*)password, passwordlength, saltcontent, sizeof(saltcontent), 500000, sizeof(master_key), master_key);
    // Splite keys
    memcpy(key1, master_key, 32);
    memcpy(key2, master_key + 32, 32);

    // Encryption [64, end)
    xts_enc_sloth(key1, key2, plain_header + 64, VC_VOLUME_HEADER_SIZE - 64, ciphertext + 64, sec_siz);

    // Write Header
    FILE *fp = fopen(filename, "ab");
    if (!fp) {
        perror("fopen");
        return -1;
    }
    fwrite(ciphertext, 1, VC_VOLUME_HEADER_SIZE, fp);
    free(ciphertext);
    fclose(fp);

    return 0;
}

static int append_random_volume(char *filename, int volume_size) {
    FILE *fp = fopen(filename, "ab");  // Append
    if (!fp) {
        perror("fopen");
        return -1;
    }

    // Writing Data Area
    const size_t chunk_size = 4096;
    uint8_t buffer[4096];

    size_t remaining = volume_size * 1024 * 1024 - 2 * VC_VOLUME_HEADER_SIZE;
    while (remaining > 0) {
        size_t this_chunk = (remaining > chunk_size) ? chunk_size : remaining;

        if (secure_random(buffer, this_chunk) != 0) {
            fprintf(stderr, "secure_random failed\n");
            fclose(fp);
            return -1;
        }

        if (fwrite(buffer, 1, this_chunk, fp) != this_chunk) {
            perror("fwrite");
            fclose(fp);
            return -1;
        }

        remaining -= this_chunk;
    }

    fclose(fp);
    return 0;
}

int make_vera_volume_main(){

    char volume_name[256], volume_cap[64], password[PWD_MAX_LENGTH_SLOTH], sector[64];
    int Volume_size, sec_size;
    char extra, extra2;

    if (get_user_input("Provide Route and Name for creating volume: ", volume_name, sizeof(volume_name)) == 0) {
	}
    if (get_user_input("The Size(MB) of the Volume: ", volume_cap, sizeof(volume_cap)) == 0) {
	}
    if (sscanf(volume_cap, "%d%c", &Volume_size, &extra) != 1) {
        printf("Invalid Input.\n");
    }
    if (get_user_input("The Sector Size of the Volume(512/1024/2048/4096): ", sector, sizeof(sector)) == 0) {
	}
    if (sscanf(sector, "%d%c", &sec_size, &extra2) != 1) {
        printf("Invalid Input.\n");
    }

    if (get_user_input("Please Set Password: ", password, sizeof(password)) == 0) {
	}

    uint8_t *buffer1 = (uint8_t *)malloc(VC_VOLUME_HEADER_SIZE);
    uint8_t *buffer2 = (uint8_t *)malloc(VC_VOLUME_HEADER_SIZE);

    if ((buffer1 == NULL) || (buffer2 == NULL)) {
        perror("Malloc failed");
        return EXIT_FAILURE;
    }
    uint8_t in_masterkey[64], out_masterkey[64];
    build_volume_header(buffer1, Volume_size, sec_size, out_masterkey, 0, in_masterkey);
    memcpy(in_masterkey, out_masterkey, 64);
    build_volume_header(buffer2, Volume_size, sec_size, out_masterkey, 1, in_masterkey);

    printf("Building Plain Header 1 and BackUp Header Done.\n");

    // Encrypted and save first header
    encrypt_and_save_header((uint8_t*)password, strlen(password), volume_name, buffer1, sec_size);
    // Write Data Area
    append_random_volume(volume_name, Volume_size);
    // Write Header 2
    encrypt_and_save_header((uint8_t*)password, strlen(password), volume_name, buffer2, sec_size);

    // Clean Up
    free(buffer1);
    free(buffer2);
    printf("Volume successfully created.\n");

    return 0;
}
