// #define FUSE_USE_VERSION 31
#include "../params.h"
#include "../fuse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include "crypto_mode_sloth.h"
#include "utils_sloth.h"
#include "../vcserpent/SerpentFast.h"
#include "../pbkdf2/pbkdf2.h"
#include "../rand/rand.h"
#include "makevcvol_sloth.h"
#include <sys/mount.h>

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

#ifdef USING_LIBFUSE_V3
static int vcfs_getattr(const char* path, struct stat* stbuf, struct fuse_file_info *fi) {
#else
static int vcfs_getattr(const char* path, struct stat* stbuf) {
#endif
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
    off_t enc_offset = offset + HEADER_SIZE_VCFUSE;
    char tmp[512];
    size_t total = 0;
    const size_t sector_size = 512;

    while (total < size) {
        size_t chunk = (size - total > sizeof(tmp)) ? sizeof(tmp) : (size - total);
        ssize_t r = pread(fd, tmp, chunk, enc_offset + total);
        if (r <= 0) break;

        // 计算扇区号（相对于数据区域）
        uint64_t logical_offset = offset + total;
        uint64_t sector_number = logical_offset / sector_size + 256;

        // 解密到 buf
        xts_decrypt(&global_xts, (uint8_t*)tmp, (uint8_t*)(buf + total), r, sector_number, sector_size);
        total += r;
    }

    return total;
}

static int vcfs_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
    if (strcmp(path, FILE_NAME_TMP) != 0)
        return -ENOENT;

    int fd = fi->fh;
    off_t enc_offset = offset + HEADER_SIZE_VCFUSE;
    char tmp[512];
    size_t total = 0;
    const size_t sector_size = 512;

    while (total < size) {
        size_t chunk = (size - total > sizeof(tmp)) ? sizeof(tmp) : (size - total);
        memcpy(tmp, buf + total, chunk);

        uint64_t logical_offset = offset + total;
        uint64_t sector_number = logical_offset / sector_size + 256;

        xts_encrypt(&global_xts, (uint8_t*)tmp, (uint8_t*)tmp, chunk, sector_number, sector_size);

        ssize_t w = pwrite(fd, tmp, chunk, enc_offset + total);
        if (w != chunk) return -EIO;
        total += chunk;
    }

    return total;
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

#ifdef USING_LIBFUSE_V3
static int vcfs_truncate(const char* path, off_t size, struct fuse_file_info *fi) {
#else
static int vcfs_truncate(const char* path, off_t size) {
#endif
    if (strcmp(path, FILE_NAME_TMP) != 0)
        return -ENOENT;

    return truncate(backing_file, size + HEADER_SIZE_VCFUSE);
}

static int vcfs_release(const char* path, struct fuse_file_info* fi) {
    if (fi->fh >= 0) close(fi->fh);
    return 0;
}
#ifdef USING_LIBFUSE_V3
static int vcfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
#else
static int vcfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi) {
#endif
    (void) offset;
    (void) fi;

    if (strcmp(path, "/") != 0)
        return -ENOENT;
#ifdef USING_LIBFUSE_V3
	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);
    filler(buf, FILE_NAME_TMP + 1, NULL, 0, 0);  // +1 去掉前面的'/'
#else
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, FILE_NAME_TMP + 1, NULL, 0);  // +1 去掉前面的'/'
#endif

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

void safe_unmount_vcfuse(const char *loopdev) {
    // 1. Unmount Loop Device
    if (access(loopdev, F_OK) == 0) {
        printf("[*] Attempting to detach loop device %s\n", loopdev);

        char *losetup_argv[] = {"losetup", "-d", (char *)loopdev, NULL};
        run_cmd("losetup", losetup_argv);
    } else {
        printf("[*] Loop device %s does not exist, skipping losetup -d.\n", loopdev);
    }

    // 2. Unmount Fuse
    umount("/tmp/slothvc");
    
    printf("[*] Unmount complete.\n");
}

struct fuse_thread_args {
    int argc;
    char **argv;
};

static void* run_fuse(void* arg) {
    struct fuse_thread_args *args = (struct fuse_thread_args*)arg;
    int ret = fuse_main(args->argc, args->argv, &vcfs_oper, NULL);
    
    // 清理资源
    for (int i = 0; i < args->argc; i++) {
        free(args->argv[i]);
    }
    free(args->argv);
    free(args);
    
    return NULL;
}

int vcfuse_main(int argc, char* argv[]) {
    char file_path[512];
    char mount_point[] = "/tmp/slothvc";
    
    // 获取用户输入
    get_user_input("Enter the Volume Name: ", file_path, 512);

    
    if ((backing_file = strdup(file_path)) == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        return 1;
    }
    
    get_user_input("Enter Password: ", user_password, sizeof(user_password));

    
    // 初始化加密
    if (init_encryption() != 0) {
        fprintf(stderr, "Encryption initialization failed.\n");
        free(backing_file);
        return 1;
    }
    
    // 准备FUSE参数
    const char *fuse_options[] = {
        "-f",
        "-o", "allow_other",
#ifndef USING_LIBFUSE_V3
        "-o", "nonempty",
#endif
        NULL
    };
    
    // 计算参数数量
    int fuse_argc = 0;
    while (fuse_options[fuse_argc] != NULL) fuse_argc++;
    
    // 分配参数内存
    struct fuse_thread_args *args = malloc(sizeof(struct fuse_thread_args));
    if (!args) {
        fprintf(stderr, "Memory allocation failed.\n");
        free(backing_file);
        return 1;
    }
    
    args->argc = fuse_argc + 2; // 程序名 + 挂载点 + 选项
    args->argv = malloc((args->argc + 1) * sizeof(char*));
    if (!args->argv) {
        fprintf(stderr, "Memory allocation failed.\n");
        free(args);
        free(backing_file);
        return 1;
    }
    
    // 填充参数
    args->argv[0] = strdup(argv[0]); // 程序名
    args->argv[1] = strdup(mount_point); // 挂载点
    
    for (int i = 0; i < fuse_argc; i++) {
        args->argv[i+2] = strdup(fuse_options[i]);
    }
    args->argv[args->argc] = NULL; // 终止NULL
    mkdir("/tmp/slothvc", 0755);
    // 创建FUSE线程
    pthread_t fuse_thread;
    if (pthread_create(&fuse_thread, NULL, run_fuse, args) != 0) {
        fprintf(stderr, "Failed to create FUSE thread.\n");
        for (int i = 0; i < args->argc; i++) free(args->argv[i]);
        free(args->argv);
        free(args);
        free(backing_file);
        return 1;
    }
    pthread_detach(fuse_thread);
    // 设置loop设备
    const char *loopdev = find_unused_loopdev();
    if (!loopdev) {
        fprintf(stderr, "No available loop device found.\n");
        return 1;
    }
    printf("Using loop device: %s\n", loopdev);

    run_losetup(loopdev, "/tmp/slothvc/vcfile");

    return 0;
}
