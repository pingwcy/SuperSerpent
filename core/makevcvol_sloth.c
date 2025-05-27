#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "makevcvol_sloth.h"
#include "crypto_mode_sloth.h"
#include "../rand/rand.h"
#include "../pbkdf2/pbkdf2.h"
#include "../vcserpent/SerpentFast.h"
#include "utils_sloth.h"
#include "../params.h"

#define TC_MAX_FAT_CLUSTER_SIZE (64 * BYTES_PER_MB)
#define TC_SECTOR_SIZE_LEGACY 512
#define TC_MAX_VOLUME_SECTOR_SIZE 4096

typedef struct {
    char volume_name[11];
    uint32_t num_sectors;     /* total number of sectors */
    uint32_t cluster_count;   /* number of clusters */
    uint32_t size_root_dir;   /* size of the root directory in bytes */
    uint32_t size_fat;        /* size of FAT */
    uint32_t fats;
    uint32_t media;
    uint32_t cluster_size;
    uint32_t fat_length;
    uint16_t dir_entries;
    uint16_t sector_size;
    uint32_t hidden;
    uint16_t reserved;
    uint16_t sectors;
    uint32_t total_sect;

    uint16_t heads;
    uint16_t secs_track;
} fatparams;

static void Endian_Little(uint8_t *data, size_t size) {
    // This function assumes little-endian architecture for simplicity
}

static void RandomNumberGenerator_GetDataFast(void *buffer, size_t length) {
    // Placeholder for random number generation
    for (size_t i = 0; i < length; ++i) {
        ((uint8_t *)buffer)[i] = rand() % 256;
    }
}

static void GetFatParams(fatparams *ft) {
    uint64_t volumeSize = (uint64_t)ft->num_sectors * ft->sector_size;
    unsigned int fatsecs;

    if (ft->cluster_size == 0) { // 'Default' cluster size
        uint32_t clusterSize;

        // Determine optimal cluster size to minimize FAT size (mounting delay), maximize number of files, keep 4 KB alignment, etc.
        if (volumeSize >= 2 * BYTES_PER_TB)
            clusterSize = 256 * BYTES_PER_KB;
        else if (volumeSize >= 512 * BYTES_PER_GB)
            clusterSize = 128 * BYTES_PER_KB;
        else if (volumeSize >= 128 * BYTES_PER_GB)
            clusterSize = 64 * BYTES_PER_KB;
        else if (volumeSize >= 64 * BYTES_PER_GB)
            clusterSize = 32 * BYTES_PER_KB;
        else if (volumeSize >= 32 * BYTES_PER_GB)
            clusterSize = 16 * BYTES_PER_KB;
        else if (volumeSize >= 16 * BYTES_PER_GB)
            clusterSize = 8 * BYTES_PER_KB;
        else if (volumeSize >= 512 * BYTES_PER_MB)
            clusterSize = 4 * BYTES_PER_KB;
        else if (volumeSize >= 256 * BYTES_PER_MB)
            clusterSize = 2 * BYTES_PER_KB;
        else if (volumeSize >= 1 * BYTES_PER_MB)
            clusterSize = 1 * BYTES_PER_KB;
        else
            clusterSize = 512;

        ft->cluster_size = clusterSize / ft->sector_size;

        if (ft->cluster_size == 0)
            ft->cluster_size = 1;

        if (ft->cluster_size * ft->sector_size > TC_MAX_FAT_CLUSTER_SIZE)
            ft->cluster_size = TC_MAX_FAT_CLUSTER_SIZE / ft->sector_size;

        if (ft->cluster_size > 128)
            ft->cluster_size = 128;
    }

    if (volumeSize <= TC_MAX_FAT_CLUSTER_SIZE * 4)
        ft->cluster_size = 1;

    // Geometry always set to SECTORS/1/1
    ft->secs_track = 1;
    ft->heads = 1;

    ft->dir_entries = 512;
    ft->fats = 2;
    ft->media = 0xf8;
    ft->hidden = 0;

    ft->size_root_dir = ft->dir_entries * 32;

    // FAT12
    ft->size_fat = 12;
    ft->reserved = 2;
    fatsecs = ft->num_sectors - (ft->size_root_dir + ft->sector_size - 1) / ft->sector_size - ft->reserved;
    ft->cluster_count = (int)(((int64_t)fatsecs * ft->sector_size) / (ft->cluster_size * ft->sector_size));
    ft->fat_length = (((ft->cluster_count * 3 + 1) >> 1) + ft->sector_size - 1) / ft->sector_size;

    if (ft->cluster_count >= 4085) { // FAT16
        ft->size_fat = 16;
        ft->reserved = 2;
        fatsecs = ft->num_sectors - (ft->size_root_dir + ft->sector_size - 1) / ft->sector_size - ft->reserved;
        ft->cluster_count = (int)(((int64_t)fatsecs * ft->sector_size) / (ft->cluster_size * ft->sector_size));
        ft->fat_length = (ft->cluster_count * 2 + ft->sector_size - 1) / ft->sector_size;
    }

    if (ft->cluster_count >= 65525) { // FAT32
        ft->size_fat = 32;
        ft->reserved = 32 - 1;

        do {
            ft->reserved++;

            fatsecs = ft->num_sectors - ft->reserved;
            ft->size_root_dir = ft->cluster_size * ft->sector_size;
            ft->cluster_count = (int)(((int64_t)fatsecs * ft->sector_size) / (ft->cluster_size * ft->sector_size));
            ft->fat_length = (ft->cluster_count * 4 + ft->sector_size - 1) / ft->sector_size;

            // Align data area on TC_MAX_VOLUME_SECTOR_SIZE

        } while (ft->sector_size == TC_SECTOR_SIZE_LEGACY
                 && (ft->reserved * ft->sector_size + ft->fat_length * ft->fats * ft->sector_size) % TC_MAX_VOLUME_SECTOR_SIZE != 0);
    }

    ft->cluster_count -= ft->fat_length * ft->fats / ft->cluster_size;

    if (ft->num_sectors >= 65536 || ft->size_fat == 32) {
        ft->sectors = 0;
        ft->total_sect = ft->num_sectors;
    } else {
        ft->sectors = (uint16_t)ft->num_sectors;
        ft->total_sect = 0;
    }
}

static void PutBoot(fatparams *ft, uint8_t *boot, uint32_t volumeId) {
    int cnt = 0;

    boot[cnt++] = 0xeb;    /* boot jump */
    boot[cnt++] = (ft->size_fat == 32) ? 0x58 : 0x3c;
    boot[cnt++] = 0x90;
    memcpy(boot + cnt, "MSDOS5.0", 8); /* system id */
    cnt += 8;
    *(uint16_t *)(boot + cnt) = (ft->sector_size); /* bytes per sector */  //THERE NEED CONVERT HOST TO LITTLE ENDIAN!!!!!!
    cnt += 2;
    boot[cnt++] = (uint8_t)ft->cluster_size;          /* sectors per cluster */
    *(uint16_t *)(boot + cnt) = (ft->reserved);       /* reserved sectors */  //THERE NEED CONVERT HOST TO LITTLE ENDIAN!!!!!!
    cnt += 2;
    boot[cnt++] = (uint8_t)ft->fats;                    /* 2 fats */

    if (ft->size_fat == 32) {
        boot[cnt++] = 0x00;
        boot[cnt++] = 0x00;
    } else {
        *(uint16_t *)(boot + cnt) = (ft->dir_entries);  /* 512 root entries */  //THERE NEED CONVERT HOST TO LITTLE ENDIAN!!!!
        cnt += 2;
    }

    *(uint16_t *)(boot + cnt) = (ft->sectors);         /* # sectors */  //THERE NEED CONVERT HOST TO LITTLE ENDIAN!!!!!!!
    cnt += 2;
    boot[cnt++] = (uint8_t)ft->media;                      /* media byte */

    if (ft->size_fat == 32) {
        boot[cnt++] = 0x00;
        boot[cnt++] = 0x00;
    } else {
        *(uint16_t *)(boot + cnt) = ((uint16_t)ft->fat_length); /* fat size */  //THERE NEED CONVERT HOST TO LITTLE ENDIAN!!!!!!!
        cnt += 2;
    }

    *(uint16_t *)(boot + cnt) = (ft->secs_track);      /* # sectors per track */
    cnt += 2;
    *(uint16_t *)(boot + cnt) = (ft->heads);             /* # heads */
    cnt += 2;
    *(uint32_t *)(boot + cnt) = (ft->hidden);          /* # hidden sectors */
    cnt += 4;
    *(uint32_t *)(boot + cnt) = (ft->total_sect);      /* # huge sectors */
    cnt += 4;

    if (ft->size_fat == 32) {
        *(uint32_t *)(boot + cnt) = (ft->fat_length);
        cnt += 4; /* fat size 32 */
        boot[cnt++] = 0x00; /* ExtFlags */
        boot[cnt++] = 0x00;
        boot[cnt++] = 0x00; /* FSVer */
        boot[cnt++] = 0x00;
        boot[cnt++] = 0x02; /* RootClus */
        boot[cnt++] = 0x00;
        boot[cnt++] = 0x00;
        boot[cnt++] = 0x00;
        boot[cnt++] = 0x01; /* FSInfo */
        boot[cnt++] = 0x00;
        boot[cnt++] = 0x06; /* BkBootSec */
        boot[cnt++] = 0x00;
        memset(boot + cnt, 0, 12);
        cnt += 12; /* Reserved */
    }

    boot[cnt++] = 0x00; /* drive number */   // FIXED 80 > 00
    boot[cnt++] = 0x00; /* reserved */
    boot[cnt++] = 0x29; /* boot sig */

    *(uint32_t *)(boot + cnt) = (volumeId);
    cnt += 4;

    memcpy(boot + cnt, ft->volume_name, 11); /* vol title */
    cnt += 11;

    switch (ft->size_fat) { /* filesystem type */
        case 12:
            memcpy(boot + cnt, "FAT12   ", 8);
            break;
        case 16:
            memcpy(boot + cnt, "FAT16   ", 8);
            break;
        case 32:
            memcpy(boot + cnt, "FAT32   ", 8);
            break;
    }
    cnt += 8;

    memset(boot + cnt, 0, ft->size_fat == 32 ? 420 : 448); /* boot code */
    cnt += ft->size_fat == 32 ? 420 : 448;
    boot[cnt++] = 0x55;
    boot[cnt++] = 0xaa; /* boot sig */
}

/* FAT32 FSInfo */
static void PutFSInfo(uint8_t *sector, fatparams *ft) {
    memset(sector, 0, ft->sector_size);
    sector[3] = 0x41; /* LeadSig */
    sector[2] = 0x61;
    sector[1] = 0x52;
    sector[0] = 0x52;
    sector[484 + 3] = 0x61; /* StrucSig */
    sector[484 + 2] = 0x41;
    sector[484 + 1] = 0x72;
    sector[484 + 0] = 0x72;

    // Free cluster count
    *(uint32_t *)(sector + 488) = (ft->cluster_count - ft->size_root_dir / ft->sector_size / ft->cluster_size);

    // Next free cluster
    *(uint32_t *)(sector + 492) = ((uint32_t)2);

    sector[508 + 3] = 0xaa; /* TrailSig */
    sector[508 + 2] = 0x55;
    sector[508 + 1] = 0x00;
    sector[508 + 0] = 0x00;
}

static int writeSector(uint8_t *sector, XTS_CTX *ctx, uint32_t sectorNumber, FILE *file, fatparams *ft) {
    // Move file pointer to the correct position
    // fseek(file, (sectorNumber * ft->sector_size) + VC_VOLUME_HEADER_SIZE, SEEK_SET);
    // Encrypt Sector
    uint8_t cipher_sector[4096];
    xts_encrypt(ctx, sector, cipher_sector, ft->sector_size, (sectorNumber + VC_VOLUME_HEADER_SIZE / (ft->sector_size)), ft->sector_size);
    // Write the sector to the file
    return fwrite(cipher_sector, ft->sector_size, 1, file) == 1;
}

static void Format(int (*writeSector)(uint8_t*, XTS_CTX*, uint32_t, FILE*, fatparams*), uint64_t deviceSize, uint32_t clusterSize, uint32_t sectorSize, const char *filename, uint8_t *key1, uint8_t *key2) {
    XTS_CTX ctx;
    uint8_t ks1[SERPENT_KSSIZE_SLOTH];
    uint8_t ks2[SERPENT_KSSIZE_SLOTH];

    serpent_set_key(key1, ks1);
    serpent_set_key(key2, ks2);
	// print_hex_sloth("Key1: ", key1, KEY_SIZE_SLOTH);
	// print_hex_sloth("Key2: ", key2, KEY_SIZE_SLOTH);
    ctx.block_encrypt = serpent_encrypt_fn;
    ctx.block_decrypt = serpent_decrypt_fn;
    memcpy(ctx.ks1, ks1, SERPENT_KSSIZE_SLOTH);
    memcpy(ctx.ks2, ks2, SERPENT_KSSIZE_SLOTH);
    ctx.key_length = SERPENT_KSSIZE_SLOTH;


    fatparams fatParams;

#if TC_MAX_VOLUME_SECTOR_SIZE > 0xFFFF
#error TC_MAX_VOLUME_SECTOR_SIZE > 0xFFFF
#endif
    fatParams.sector_size = (uint16_t)sectorSize;

    if (deviceSize / fatParams.sector_size > 0xffffFFFF)
        return; // throw ParameterIncorrect (SRC_POS);

    fatParams.num_sectors = (uint32_t)(deviceSize / fatParams.sector_size);
    fatParams.cluster_size = clusterSize / fatParams.sector_size;
    memcpy(fatParams.volume_name, "NO NAME    ", 11);
    GetFatParams(&fatParams);
    fatparams *ft = &fatParams;

    uint8_t *sector = (uint8_t *)malloc(ft->sector_size);
    if (!sector) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    uint32_t sectorNumber = 0;

    // Open the output file
    FILE *file = fopen(filename, "ab");
    if (!file) {
        fprintf(stderr, "Failed to open file %s\n", filename);
        free(sector);
        return;
    }

    /* Write the data area */

    memset(sector, 0, ft->sector_size);

    uint32_t volumeId;
    RandomNumberGenerator_GetDataFast(&volumeId, sizeof(volumeId));

    PutBoot(ft, sector, volumeId);
    if (!writeSector(sector, &ctx, sectorNumber, file, ft)) {
        fclose(file);
        free(sector);
        return;
    }
    Endian_Little(sector, ft->sector_size);
    sectorNumber++;

    /* fat32 boot area */
    if (ft->size_fat == 32) {
        /* fsinfo */
        PutFSInfo(sector, ft);
        if (!writeSector(sector, &ctx, sectorNumber, file, ft)) {
            fclose(file);
            free(sector);
            return;
        }
        Endian_Little(sector, ft->sector_size);
        sectorNumber++;

        /* reserved */
        while (sectorNumber < 6) {
            memset(sector, 0, ft->sector_size);
            sector[508 + 3] = 0xaa; /* TrailSig */
            sector[508 + 2] = 0x55;
            if (!writeSector(sector, &ctx, sectorNumber, file, ft)) {
                fclose(file);
                free(sector);
                return;
            }
            Endian_Little(sector, ft->sector_size);
            sectorNumber++;
        }

        /* bootsector backup */
        memset(sector, 0, ft->sector_size);
        PutBoot(ft, sector, volumeId);
        if (!writeSector(sector, &ctx, sectorNumber, file, ft)) {
            fclose(file);
            free(sector);
            return;
        }
        Endian_Little(sector, ft->sector_size);
        sectorNumber++;

        PutFSInfo(sector, ft);
        if (!writeSector(sector, &ctx, sectorNumber, file, ft)) {
            fclose(file);
            free(sector);
            return;
        }
        Endian_Little(sector, ft->sector_size);
        sectorNumber++;
    }

    /* reserved */
    while (sectorNumber < (uint32_t)ft->reserved) {
        memset(sector, 0, ft->sector_size);
        if (!writeSector(sector, &ctx, sectorNumber, file, ft)) {
            fclose(file);
            free(sector);
            return;
        }
        Endian_Little(sector, ft->sector_size);
        sectorNumber++;
    }

    /* write fat */
    for (uint32_t x = 1; x <= ft->fats; x++) {
        for (uint32_t n = 0; n < ft->fat_length; n++) {
            memset(sector, 0, ft->sector_size);

            if (n == 0) {
                uint8_t fat_sig[12];
                if (ft->size_fat == 32) {
                    fat_sig[0] = (uint8_t)ft->media;
                    fat_sig[1] = fat_sig[2] = 0xff;
                    fat_sig[3] = 0x0f;
                    fat_sig[4] = fat_sig[5] = fat_sig[6] = 0xff;
                    fat_sig[7] = 0x0f;
                    fat_sig[8] = fat_sig[9] = fat_sig[10] = 0xff;
                    fat_sig[11] = 0x0f;
                    memcpy(sector, fat_sig, 12);
                } else if (ft->size_fat == 16) {
                    fat_sig[0] = (uint8_t)ft->media;
                    fat_sig[1] = 0xff;
                    fat_sig[2] = 0xff;
                    fat_sig[3] = 0xff;
                    memcpy(sector, fat_sig, 4);
                } else if (ft->size_fat == 12) {
                    fat_sig[0] = (uint8_t)ft->media;
                    fat_sig[1] = 0xff;
                    fat_sig[2] = 0xff;
                    fat_sig[3] = 0x00;
                    memcpy(sector, fat_sig, 4);
                }
            }

            if (!writeSector(sector, &ctx, sectorNumber, file, ft)) {
                fclose(file);
                free(sector);
                return;
            }
            Endian_Little(sector, ft->sector_size);
            sectorNumber++;
        }
    }

    /* write rootdir */
    for (uint32_t x = 0; x < ft->size_root_dir / ft->sector_size; x++) {
        memset(sector, 0, ft->sector_size);
        if (!writeSector(sector, &ctx, sectorNumber, file, ft)) {
            fclose(file);
            free(sector);
            return;
        }
        Endian_Little(sector, ft->sector_size);
        sectorNumber++;
    }
    // Fill the rest of the volume with random data to avoid residue
    uint64_t writtenBytes = (uint64_t)sectorNumber * ft->sector_size;
    uint64_t totalVolumeBytes = deviceSize - 2 * VC_VOLUME_HEADER_SIZE;
    if (writtenBytes < totalVolumeBytes) {
        uint8_t* fillBuffer = malloc(ft->sector_size);
        if (!fillBuffer) {
            fprintf(stderr, "Memory allocation failed during tail padding.\n");
            fclose(file);
            return;
        }
        for (uint64_t i = writtenBytes; i < totalVolumeBytes; i += ft->sector_size, sectorNumber++) {
            RandomNumberGenerator_GetDataFast(fillBuffer, ft->sector_size);
            if (!writeSector(fillBuffer, &ctx, sectorNumber, file, ft)) {
                fprintf(stderr, "Failed writing tail padding.\n");
                free(fillBuffer);
                fclose(file);
                return;
            }
        }
        free(fillBuffer);
    }

    free(sector);
    fclose(file);
}

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

    // 16. Write 65024 random bytes
    if (secure_random(p, 65024) != 0) return -1;
    p += 65024;

    // 17. Write 65536 random bytes
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

static int encrypt_and_save_header(uint8_t password[], int passwordlength, const char *filename, const uint8_t *plain_header, const int sec_siz) {
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
    xts_enc_sloth(key1, key2, plain_header + 64, VC_VOLUME_HEADER_SIZE - 64, ciphertext + 64, sec_siz, 0);

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

static int build_volume_content(char *filename, int volume_size, int sectorSize, int clusterSize, uint8_t *master_key) {
    uint8_t key1[KEY_SIZE_SLOTH], key2[KEY_SIZE_SLOTH];
    memcpy(key1, master_key, KEY_SIZE_SLOTH);
    memcpy(key2, master_key + KEY_SIZE_SLOTH, KEY_SIZE_SLOTH);
    Format(writeSector, volume_size * 1024 * 1024, clusterSize, sectorSize, filename, key1, key2);
    return 0;
}

static int build_random_volume(char *filename, int volume_size){
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
    char extra, extra2, need_fs[3];
    sec_size = 512; // 512 bytes Sector for FAT32
    if (get_user_input("Provide Route and Name for creating volume: ", volume_name, sizeof(volume_name)) == 0) {
	}
    if (get_user_input("The Size(MB) of the Volume: ", volume_cap, sizeof(volume_cap)) == 0) {
	}
    if (sscanf(volume_cap, "%d%c", &Volume_size, &extra) != 1) {
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
    // Encrypted and save first header
    encrypt_and_save_header((uint8_t*)password, strlen(password), volume_name, buffer1, sec_size);

    printf("Building Plain Header 1 and BackUp Header Done.\n");

    if (get_user_input("Do you need format volume as FAT?(y/n) ", need_fs, sizeof(need_fs)) == 0) {
        if (need_fs[0] == 'y') {
            //Write Data Area
            build_volume_content(volume_name, Volume_size, sec_size, 4096, out_masterkey);
	        }
        else{
            //if (get_user_input("The Sector Size of the Volume(512/1024/2048/4096): ", sector, sizeof(sector)) == 0) {
                //if (sscanf(sector, "%d%c", &sec_size, &extra2) != 1) {
                //printf("Invalid Input.\n");
                //}
            build_random_volume(volume_name, Volume_size);
        }
	}

    // Write Header 2
    encrypt_and_save_header((uint8_t*)password, strlen(password), volume_name, buffer2, sec_size);

    // Clean Up
    free(buffer1);
    free(buffer2);
    printf("Volume successfully created.\n");

    return 0;
}
