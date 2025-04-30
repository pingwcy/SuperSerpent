#define FUSE_USE_VERSION 31
#define _FILE_OFFSET_BITS 64

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <utime.h>
#include <sys/time.h>
#include <sys/statvfs.h>
#include "./rand/rand.h"
#include "params.h"
#include "./vcserpent/SerpentFast.h"
#include "./pbkdf2/pbkdf2.h"
#include "./core/utils_sloth.h"
#define MAX_FILES 128
#define BUFFER_SIZE 4096
//#define PATH_MAX 256
#define MAX_FILE_SIZE 4096000
#define HEADER_SIZE 28 // 16字节SALT + 12字节NONCE
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static char user_password[256]; // 全局密码缓存
typedef struct {
    char filename[256];
    unsigned char key[KEY_SIZE_SLOTH];
    uint8_t ks[SERPENT_KSSIZE_SLOTH];
    unsigned char salt[16];   // 保存原始salt用于判断
    int valid;
} FileKeyCache;

static FileKeyCache key_cache[MAX_FILES];

typedef struct {
    char name[256];
    size_t size;
} MyFile;

static MyFile files[MAX_FILES];
static int file_count = 0;
static char mount_point[PATH_MAX];

typedef struct {
    unsigned char key[KEY_SIZE_SLOTH];
    uint8_t ks[SERPENT_KSSIZE_SLOTH];
    uint8_t nonce[NONCE_SIZE_SLOTH];
} Keyinfo;

///////////////////// 加密相关 ///////////////////////
void sloth_kdf(const char *password, const unsigned char *salt, unsigned char *out_key) {
    const int iterations = ITERATIONS_SLOTH; // 建议的迭代次数，可根据安全需求调整
    PBKDF2_HMAC_Whirlpool(
        (const uint8_t *)password, strlen(password),
        salt, 16, // 假设盐值长度是16字节(128位)
        iterations,
        KEY_SIZE_SLOTH,
        out_key
    );
}

Keyinfo get_file_key(const char *filename, const unsigned char *header, const char *password) {
    // 加锁（阻塞式）
    pthread_mutex_lock(&cache_mutex);

    const unsigned char *salt = header; // header 前16字节是 salt
    Keyinfo result = {0};

    for (int i = 0; i < MAX_FILES; i++) {
        if (key_cache[i].valid &&
            strcmp(key_cache[i].filename, filename) == 0 &&
            memcmp(key_cache[i].salt, salt, 16) == 0) {

            memcpy(result.key, key_cache[i].key, KEY_SIZE_SLOTH);
            memcpy(result.ks, key_cache[i].ks, SERPENT_KSSIZE_SLOTH);
            memcpy(result.nonce, header + 16, NONCE_SIZE_SLOTH);
            fprintf(stderr, "[get file key] Match at %d: filename=%s, salt=%02x%02x...\n",i,key_cache[i].filename, key_cache[i].salt[0], key_cache[i].salt[1]);
            pthread_mutex_unlock(&cache_mutex); // 成功命中缓存，先解锁再返回
            return result;
        }
    }

    for (int i = 0; i < MAX_FILES; i++) {
        if (!key_cache[i].valid) {
            strncpy(key_cache[i].filename, filename, sizeof(key_cache[i].filename) - 1);
            key_cache[i].filename[sizeof(key_cache[i].filename) - 1] = '\0';
            memcpy(key_cache[i].salt, salt, 16);

            sloth_kdf(password, salt, key_cache[i].key);
            serpent_set_key(key_cache[i].key, key_cache[i].ks);
            key_cache[i].valid = 1;

            memcpy(result.key, key_cache[i].key, KEY_SIZE_SLOTH);
            memcpy(result.ks, key_cache[i].ks, SERPENT_KSSIZE_SLOTH);
            memcpy(result.nonce, header + 16, NONCE_SIZE_SLOTH);

            pthread_mutex_unlock(&cache_mutex); // 插入新缓存后解锁
            return result;
        }
    }

    // 如果没有找到空位
    pthread_mutex_unlock(&cache_mutex); // 返回前必须解锁
    return (Keyinfo){0}; // 返回无效结果
}
void ctr_encrypt_sloth(const uint8_t* data, size_t length, const uint8_t* key, uint64_t offset_bytes, uint8_t* encrypted_data, const uint8_t* ks, const uint8_t* nonce) {
    if (!data || !key || !encrypted_data || !ks || !nonce) return;
    fprintf(stderr, "[ctr_encrypt_sloth] key=%02x%02x%02x...\n",key[0],key[1],key[2]);
    printf(user_password);
    printf("\n");

    uint8_t counter[BLOCK_SIZE_SLOTH];
    uint8_t keystream[BLOCK_SIZE_SLOTH];
    size_t i = 0;

    while (i < length) {
        uint64_t block_index = (offset_bytes + i) / BLOCK_SIZE_SLOTH;
        size_t block_offset = (offset_bytes + i) % BLOCK_SIZE_SLOTH;

        // 构造 counter
        memcpy(counter, nonce, NONCE_SIZE_SLOTH);
        counter[12] = (block_index >> 24) & 0xFF;
        counter[13] = (block_index >> 16) & 0xFF;
        counter[14] = (block_index >> 8) & 0xFF;
        counter[15] = (block_index >> 0) & 0xFF;

        serpent_encrypt(counter, keystream, ks);

        size_t chunk = BLOCK_SIZE_SLOTH - block_offset;
        if (chunk > length - i) chunk = length - i;

        for (size_t j = 0; j < chunk; j++) {
            encrypted_data[i] = data[i] ^ keystream[block_offset + j];
            i++;
        }
    }
}

void ctr_decrypt_sloth(uint8_t* data, size_t length, const uint8_t* key, uint64_t block_offset, const uint8_t* ks, const uint8_t* nonce) {
    ctr_encrypt_sloth(data, length, key, block_offset, data, ks, nonce);
}


// 填充SALT和NONCE
void initialize_header(FILE *fp) {
    unsigned char header[HEADER_SIZE];
    if (secure_random(header, HEADER_SIZE) != 0) {
        memset(header, 0, HEADER_SIZE);
        return;
    }
    fseek(fp, 0, SEEK_SET);
    fwrite(header, 1, HEADER_SIZE, fp);
}

int read_header(FILE *fp, unsigned char *header) {
    fseek(fp, 0, SEEK_SET);
    size_t read_bytes = fread(header, 1, HEADER_SIZE, fp);
    return (read_bytes == HEADER_SIZE) ? 0 : -1;
}
//////////////////////////////////////////////////////

static void update_file_size(MyFile *f) {
    char full_path[PATH_MAX];
    snprintf(full_path, sizeof(full_path), "%s/%s", mount_point, f->name);

    struct stat st;
    if (stat(full_path, &st) == 0) {
        f->size = (st.st_size >= HEADER_SIZE) ? (st.st_size - HEADER_SIZE) : 0;
    } else {
        f->size = 0;
    }
}
static void load_files() {
    char full_path[PATH_MAX];
    snprintf(full_path, sizeof(full_path), "%s/%s", mount_point, ".");

    DIR *dir;
    struct dirent *ent;
    dir = opendir(full_path);
    if (dir != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_type == DT_REG && strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
                strncpy(files[file_count].name, ent->d_name, 255);
                files[file_count].name[255] = '\0';

                snprintf(full_path, sizeof(full_path), "%s/%s", mount_point, ent->d_name);
                struct stat st;
                update_file_size(&files[file_count]);

                file_count++;
            }
        }
        closedir(dir);
    }
}
static void rescan_files() {
    file_count = 0;
    memset(files, 0, sizeof(files));
    load_files();  // 重用已有函数
}



static MyFile* find_file(const char *path) {
    for (int i = 0; i < file_count; i++) {
        if (strcmp(path + 1, files[i].name) == 0) {
            return &files[i];
        }
    }
    return NULL;
}


static int myfs_getattr(const char *path, struct stat *stbuf) {
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }

    MyFile *f = find_file(path);
    if (!f)
        return -ENOENT;

    stbuf->st_mode = S_IFREG | 0644;
    stbuf->st_nlink = 1;
    stbuf->st_size = f->size;
    return 0;
}

static int myfs_open(const char *path, struct fuse_file_info *fi) {
    MyFile *f = find_file(path);
    if (!f)
        return -ENOENT;
    char full_path[PATH_MAX];
    snprintf(full_path, sizeof(full_path), "%s/%s", mount_point, f->name);

    FILE *file = fopen(full_path, "r+b");
    if (!file)
        return -EIO;

    fi->fh = (uint64_t)file;  // 保存 FILE* 指针

    return 0;
}

static int myfs_read(const char *path, char *buf, size_t size, off_t offset,
    struct fuse_file_info *fi) {
    MyFile *f = find_file(path);
    if (!f)
        return -ENOENT;

    if (offset >= f->size)
        return 0;

    size_t total_bytes_read = 0;
    char buffer[BUFFER_SIZE];

    FILE *file = (FILE *)fi->fh;
    if (!file)
        return -EIO;

    unsigned char header[HEADER_SIZE];
    if (read_header(file, header) != 0) {
        return -EIO;
    }

    while (total_bytes_read < size) {
        size_t current_offset = offset + total_bytes_read;
        size_t remaining_size = size - total_bytes_read;
        size_t read_size = remaining_size > BUFFER_SIZE ? BUFFER_SIZE : remaining_size;

        fseek(file, HEADER_SIZE + current_offset, SEEK_SET);
        ssize_t bytes_read = fread(buffer, 1, read_size, file);
        if (bytes_read <= 0)
            break;

        Keyinfo rst_sloth = get_file_key(f->name, header, user_password);
        ctr_decrypt_sloth((uint8_t*)buffer, bytes_read, rst_sloth.key, current_offset, rst_sloth.ks, rst_sloth.nonce);

        memcpy(buf + total_bytes_read, buffer, bytes_read);
        total_bytes_read += bytes_read;
    }

    return total_bytes_read;
}

static int myfs_write(const char *path, const char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    (void) fi;
    MyFile *f = find_file(path);
    if (!f)
        return -ENOENT;

    size_t total_bytes_written = 0;
    char buffer[BUFFER_SIZE];

    char full_path[PATH_MAX];
    snprintf(full_path, sizeof(full_path), "%s/%s", mount_point, f->name);

    FILE *file = fopen(full_path, "r+b");
    if (!file) {
        file = fopen(full_path, "wb");
        if (!file)
            return -EIO;
        initialize_header(file); // 新建时写入SALT和NONCE
    }

    unsigned char header[HEADER_SIZE];
    if (read_header(file, header) != 0) {
        fclose(file);
        return -EIO;
    }

    while (total_bytes_written < size) {
        size_t current_offset = offset + total_bytes_written;
        size_t remaining_size = size - total_bytes_written;
        size_t write_size = remaining_size > BUFFER_SIZE ? BUFFER_SIZE : remaining_size;

        memcpy(buffer, buf + total_bytes_written, write_size);

        Keyinfo rst_sloth = get_file_key(f->name, header, user_password);
        if (1==2){
            fclose(file);
            return -EIO;
        }
        ctr_encrypt_sloth((const uint8_t*)buffer, write_size, rst_sloth.key, current_offset, (uint8_t*)buffer, rst_sloth.ks, rst_sloth.nonce);

        fseek(file, HEADER_SIZE + current_offset, SEEK_SET);
        fwrite(buffer, 1, write_size, file);

        total_bytes_written += write_size;
    }

    fflush(file);  // 刷入 libc 缓冲
    int fd = fileno(file);
    if (fsync(fd) != 0) {
        fclose(file);
        return -EIO;
    }

    fclose(file);

    update_file_size(f);

    return size;
}

static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void) mode; (void) fi;

    if (file_count >= MAX_FILES)
        return -ENOSPC;

    strncpy(files[file_count].name, path + 1, 255);
    files[file_count].name[255] = '\0';
    files[file_count].size = 0;
    file_count++;

    char full_path[PATH_MAX];
    snprintf(full_path, sizeof(full_path), "%s/%s", mount_point, files[file_count - 1].name);

    FILE *file = fopen(full_path, "wb");
    if (file) {
        initialize_header(file);
        fclose(file);
        rescan_files(); 
    }
    return 0;
}

static int myfs_truncate(const char *path, off_t size) {
    MyFile *f = find_file(path);
    if (!f)
        return -ENOENT;

    if (size > MAX_FILE_SIZE)
        return -EFBIG;

    char full_path[PATH_MAX];
    snprintf(full_path, sizeof(full_path), "%s/%s", mount_point, f->name);

    FILE *file = fopen(full_path, "r+b");
    if (!file)
        return -EIO;

    int fd = fileno(file);
    if (fd == -1) {
        fclose(file);
        return -EIO;
    }

    // 调整实际文件大小
    if (ftruncate(fd, HEADER_SIZE + size) != 0) {
        fclose(file);
        return -EIO;
    }

    fflush(file);
    fsync(fd);

    fclose(file);
    rescan_files(); 
    update_file_size(f);  // 确保 MyFile.size 与实际文件一致

    return 0;
}

static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi) {
    (void) offset; (void) fi;
    if (strcmp(path, "/") != 0)
        return -ENOENT;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    for (int i = 0; i < file_count; i++) {
        filler(buf, files[i].name, NULL, 0);
    }

    return 0;
}

static int myfs_unlink(const char *path) {
    char full_path[PATH_MAX];
    snprintf(full_path, sizeof(full_path), "%s/%s", mount_point, path + 1);

    // 尝试物理删除
    if (unlink(full_path) != 0) {
        return -errno; // 保证返回具体错误
    }

    // 更新内存记录
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].name, path + 1) == 0) {
            for (int j = i; j < file_count - 1; j++) {
                files[j] = files[j + 1];
            }
            file_count--;
            break;
        }
    }
    // 更新 files[] 缓存
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].name, path + 1) == 0) {
            for (int j = i; j < file_count - 1; j++) {
                files[j] = files[j + 1];
            }
            file_count--;
            break;
        }
    }

    // 清理缓存
    for (int i = 0; i < MAX_FILES; i++) {
        if (key_cache[i].valid && strcmp(key_cache[i].filename, path + 1) == 0) {
            key_cache[i].valid = 0;
        }
    }
    rescan_files();
    return 0;
}

static int myfs_rename(const char *from, const char *to) {
    char from_path[PATH_MAX], to_path[PATH_MAX];
    snprintf(from_path, sizeof(from_path), "%s/%s", mount_point, from + 1);
    snprintf(to_path, sizeof(to_path), "%s/%s", mount_point, to + 1);

    // 尝试重命名磁盘文件
    if (rename(from_path, to_path) != 0) {
        return -errno;
    }

    // 重命名成功后，刷新内存文件表
    rescan_files();

    return 0;
}
static int myfs_release(const char *path, struct fuse_file_info *fi) {
    FILE *file = (FILE *)fi->fh;
    if (file) {
        fclose(file);
    }
        // 如果文件名不是 files[] 中的内容，有可能是 LibreOffice 的临时文件
    const char *fname = path + 1;
    if (!find_file(path)) {
        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", mount_point, fname);
    
        // 临时文件可能需要被删除
        if (strstr(fname, "~") || strstr(fname, "#") || strstr(fname, "lock")) {
            unlink(full_path);  // 🧹 自动清理
        }
    }
    
    return 0;
}
static int myfs_flush(const char *path, struct fuse_file_info *fi) {
    // 对于简单实现，这里通常什么都不做，只要返回0即可
    return 0;
}

static int myfs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
    MyFile *f = find_file(path);
    if (!f)
        return -ENOENT;

    char full_path[PATH_MAX];
    snprintf(full_path, sizeof(full_path), "%s/%s", mount_point, f->name);

    FILE *file = fopen(full_path, "r+b");
    if (!file)
        return -EIO;

    int fd = fileno(file);
    int ret = fsync(fd);  // 强制写入磁盘
    fclose(file);
    return (ret == 0) ? 0 : -EIO;
}

static int myfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void) fi;
    char fullpath[512];
    get_full_path(fullpath, path);

    int res = chmod(fullpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int myfs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
    (void) fi;
    char fullpath[512];
    get_full_path(fullpath, path);

    int res = chown(fullpath, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int myfs_mkdir(const char *path, mode_t mode) {
    char fullpath[512];
    get_full_path(fullpath, path);

    int res = mkdir(fullpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int myfs_rmdir(const char *path) {
    char fullpath[512];
    get_full_path(fullpath, path);

    int res = rmdir(fullpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int myfs_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi) {
    return 0;
}
static int myfs_access(const char *path, int mask) {
    return 0;
}
static int myfs_statfs(const char *path, struct statvfs *stbuf) {
    return 0;
}

static struct fuse_operations myfs_oper = {
    .getattr = myfs_getattr,
    .open = myfs_open,
    .read = myfs_read,
    .write = myfs_write,
    .readdir = myfs_readdir,
    .create = myfs_create,
    .truncate = myfs_truncate,
    .rename = myfs_rename,
    .unlink = myfs_unlink,
    .release = myfs_release,
    .flush = myfs_flush,
    .fsync = myfs_fsync,
    .chmod = myfs_chmod,   
    .chown = myfs_chown, 
    .mkdir = myfs_mkdir,
    .rmdir = myfs_rmdir,
    .utimens = myfs_utimens,
    .access = myfs_access,
    .statfs = myfs_statfs,

};

int main(int argc, char *argv[]) {
    secure_memzero_sloth(key_cache, sizeof(key_cache));
    secure_memzero_sloth(files, sizeof(files));
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <mount-point> <directory>\n", argv[0]);
        exit(1);
    }
    printf("Please Enter Password: ");
    if (!fgets(user_password, sizeof(user_password), stdin)) {
        fprintf(stderr, "Cannot Read Password\n");
        exit(1);
    }
    user_password[strcspn(user_password, "\n")] = 0; // 去除换行

    strcpy(mount_point, argv[2]);
    char *new_argv[] = {argv[0], argv[1], "-f", "-o", "nonempty"};
    int new_argc = 5;

    srand(time(NULL));
    load_files();
    return fuse_main(new_argc, new_argv, &myfs_oper, NULL);
}
