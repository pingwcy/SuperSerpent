#define FUSE_USE_VERSION 31
#include "../params.h"
#include "../fuse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include "crypto_mode_sloth.h"
#include "utils_sloth.h"
#include "../vcserpent/SerpentFast.h"
#include "../pbkdf2/pbkdf2.h"
#include "../rand/rand.h"
#include "makevcvol_sloth.h"
#define FILE_NAME_TMP "/vcfile"

static const char* backing_file = NULL;
static char user_password[256] = {0};
 
static uint8_t header_key[64], header_raw[VC_VOLUME_HEADER_SIZE], header_decryped[VC_VOLUME_HEADER_SIZE - 64], master_key[64];
static XTS_CTX global_xts;

static int init_encryption() {

    FILE *file = fopen(backing_file, "rb");
    if (file == NULL) {
        perror("Can't Open File");
        return 1;
    }
    uint8_t buffer[64];
    size_t saltlen = fread(buffer, sizeof(uint8_t), 64, file);

    if (saltlen < 64) {
        if (feof(file)) {
            printf("Container is too small!");
        } else if (ferror(file)) {
            perror("Error in reading file!");
            fclose(file);
            return 1;
        }
    }

    PBKDF2_HMAC_Whirlpool((uint8_t*)user_password, strlen(user_password), buffer, sizeof(buffer), 500000, 64, header_key);
    fclose(file);


    uint8_t key1[KEY_SIZE_SLOTH], key2[KEY_SIZE_SLOTH];
    memcpy(key1, header_key, KEY_SIZE_SLOTH);
    memcpy(key2, header_key + KEY_SIZE_SLOTH, KEY_SIZE_SLOTH);
    if (return_volume_header(backing_file, header_raw) !=0){
        handle_error_sloth("Error in reading header");
        return -2;
    }

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
    xts_decrypt(&ctx, header_raw + 64, header_decryped, VC_VOLUME_HEADER_SIZE - 64 , 0, 512);

    uint64_t vol_size = parse_volume_header(header_decryped, master_key);
    if (vol_size <= 0){
        return -3;
    }

	uint8_t keya[KEY_SIZE_SLOTH], keyb[KEY_SIZE_SLOTH];
    memcpy(keya, master_key, KEY_SIZE_SLOTH);
    memcpy(keyb, master_key + KEY_SIZE_SLOTH, KEY_SIZE_SLOTH);

	uint8_t ksa[SERPENT_KSSIZE_SLOTH];
    uint8_t ksb[SERPENT_KSSIZE_SLOTH];
    serpent_set_key(keya, ksa);
    serpent_set_key(keyb, ksb);
	global_xts.block_encrypt = serpent_encrypt_fn;
	global_xts.block_decrypt = serpent_decrypt_fn;
	memcpy(global_xts.ks1, ksa, SERPENT_KSSIZE_SLOTH);
    memcpy(global_xts.ks2, ksb, SERPENT_KSSIZE_SLOTH);
    global_xts.key_length = SERPENT_KSSIZE_SLOTH;

    return 0;
}

static int vcfs_getattr(const char* path, struct stat* stbuf) {
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else if (strcmp(path, FILE_NAME_TMP) == 0) {
        struct stat st;
        if (stat(backing_file, &st) == -1)
            return -errno;
        stbuf->st_mode = S_IFREG | 0644;
        stbuf->st_nlink = 1;
        stbuf->st_size = (st.st_size >= 2 * HEADER_SIZE_VCFUSE) ? st.st_size - 2 * HEADER_SIZE_VCFUSE : 0;
    } else {
        return -ENOENT;
    }

    return 0;
}

static int vcfs_open(const char* path, struct fuse_file_info* fi) {
    if (strcmp(path, FILE_NAME_TMP) != 0)
        return -ENOENT;

    int fd = open(backing_file, O_RDWR);
    if (fd < 0) return -errno;

    unsigned char header[HEADER_SIZE_VCFUSE];
    if (pread(fd, header, HEADER_SIZE_VCFUSE, 0) != HEADER_SIZE_VCFUSE) {
        close(fd);
        return -EIO;
    }


    fi->fh = fd;
    return 0;
}

static int vcfs_read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
    if (strcmp(path, FILE_NAME_TMP) != 0)
        return -ENOENT;

    int fd = fi->fh;
    off_t aligned_offset = offset & ~(BLOCK_SIZE_SLOTH - 1);
    off_t end_offset = (offset + size + BLOCK_SIZE_SLOTH - 1) & ~(BLOCK_SIZE_SLOTH - 1);
    size_t aligned_size = end_offset - aligned_offset;
    char *aligned_buf = malloc(aligned_size);
    if (!aligned_buf)
        return -ENOMEM;

    off_t enc_offset = aligned_offset + HEADER_SIZE_VCFUSE;
    ssize_t r = pread(fd, aligned_buf, aligned_size, enc_offset);
    if (r <= 0) {
        free(aligned_buf);
        return r;
    }

    size_t total = 0;
    const size_t sector_size = 512;

    while (total < r) {
        size_t chunk = (r - total > (sector_size)) ? (sector_size) : (r - total);
        size_t logical_offset = aligned_offset + total;
        uint64_t sector_number = logical_offset / sector_size + 256;

        xts_decrypt(&global_xts, (uint8_t*)(aligned_buf + total), (uint8_t*)(aligned_buf + total), chunk, sector_number, sector_size);
        total += chunk;
    }

    size_t start_padding = offset - aligned_offset;
    size_t end_padding = aligned_size - (start_padding + size);
    memcpy(buf, aligned_buf + start_padding, size);

    free(aligned_buf);
    return size;
}

static int vcfs_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
    if (strcmp(path, FILE_NAME_TMP) != 0)
        return -ENOENT;

    int fd = fi->fh;
    off_t aligned_offset = offset & ~(BLOCK_SIZE_SLOTH - 1);
    off_t end_offset = (offset + size + BLOCK_SIZE_SLOTH - 1) & ~(BLOCK_SIZE_SLOTH - 1);
    size_t aligned_size = end_offset - aligned_offset;
    char *aligned_buf = malloc(aligned_size);
    if (!aligned_buf)
        return -ENOMEM;

    off_t enc_offset = aligned_offset + HEADER_SIZE_VCFUSE;

    // Read existing data into aligned buffer
    ssize_t r = pread(fd, aligned_buf, aligned_size, enc_offset);
    if (r < 0) {
        free(aligned_buf);
        return r;
    }

    // Fill in new data
    size_t start_padding = offset - aligned_offset;
    memcpy(aligned_buf + start_padding, buf, size);

    size_t total = 0;
    const size_t sector_size = 512;

    while (total < aligned_size) {
        size_t chunk = (aligned_size - total > sector_size) ? sector_size : (aligned_size - total);
        size_t logical_offset = aligned_offset + total;
        uint64_t sector_number = logical_offset / sector_size + 256;

        xts_encrypt(&global_xts, (uint8_t*)(aligned_buf + total), (uint8_t*)(aligned_buf + total), chunk, sector_number, sector_size);
        total += chunk;
    }

    ssize_t w = pwrite(fd, aligned_buf, aligned_size, enc_offset);
    if (w != aligned_size) {
        free(aligned_buf);
        return -EIO;
    }

    free(aligned_buf);
    return size;
}
static int vcfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
    if (strcmp(path, FILE_NAME_TMP) != 0)
        return -ENOENT;

    int fd = open(backing_file, O_CREAT | O_RDWR | O_TRUNC, mode);
    if (fd < 0) return -errno;

    unsigned char header[HEADER_SIZE_VCFUSE];
    if (secure_random(header, HEADER_SIZE_VCFUSE) != 0)
        memset(header, 0, HEADER_SIZE_VCFUSE);

    if (write(fd, header, HEADER_SIZE_VCFUSE) != HEADER_SIZE_VCFUSE) {
        close(fd);
        return -EIO;
    }

    //init_encryption(header);
    fi->fh = fd;
    return 0;
}

static int vcfs_truncate(const char* path, off_t size) {
    if (strcmp(path, FILE_NAME_TMP) != 0)
        return -ENOENT;

    return truncate(backing_file, size + HEADER_SIZE_VCFUSE);
}

static int vcfs_release(const char* path, struct fuse_file_info* fi) {
    if (fi->fh >= 0) close(fi->fh);
    return 0;
}
static int vcfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi) {
    (void) offset;
    (void) fi;

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, FILE_NAME_TMP + 1, NULL, 0);  // +1 去掉前面的'/'

    return 0;
}

static struct fuse_operations vcfs_oper = {
    .getattr = vcfs_getattr,
    .open    = vcfs_open,
    .read    = vcfs_read,
    .write   = vcfs_write,
    .create  = vcfs_create,
    .truncate = vcfs_truncate,
    .release = vcfs_release,
    .readdir = vcfs_readdir,
};

int vcfuse_main(int argc, char* argv[]) {
    char file_path[512];
    char* fuse_argv[20];
    int fuse_argc = 0;

    // Get backing file
    if (get_user_input("Enter the Volume Name: ", file_path, sizeof(file_path)) != 0) {
        fprintf(stderr, "Read Volume Failed.\n");
        return 1;
    }
    backing_file = strdup(file_path);  // backing_file

    // Get Password
    if (get_user_input("Enter Password: ", user_password, sizeof(user_password)) != 0) {
        fprintf(stderr, "Fail to Read Password.\n");
        return 1;
    }

    // 构造 FUSE 参数
    fuse_argv[fuse_argc++] = argv[0];
    fuse_argv[fuse_argc++] = "/tmp/slothvc";
    fuse_argv[fuse_argc++] = "-f";          // 前台运行
    fuse_argv[fuse_argc++] = "-o";          // 挂载选项开始
    fuse_argv[fuse_argc++] = "allow_other"; // 允许其他用户访问
    fuse_argv[fuse_argc++] = "-o";          // 添加更多选项
    fuse_argv[fuse_argc++] = "nonempty";    // 允许挂载到非空目录
    init_encryption();
    return fuse_main(fuse_argc, fuse_argv, &vcfs_oper, NULL);
}
