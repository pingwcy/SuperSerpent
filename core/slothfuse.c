#include "../params.h"
#include "slothfuse.h"
#include <libgen.h>
#include "../fuse.h"
#include <ftw.h>
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
#include "../rand/rand.h"
#include "../vcserpent/SerpentFast.h"
#include "../pbkdf2/pbkdf2.h"
#include "utils_sloth.h"
#include "crypto_mode_sloth.h"
#include "../uthash.h"

static char user_password[256]; // 全局密码缓存
static char mount_point[PATH_MAX];

typedef struct {
    char path[PATH_MAX];                     // 文件路径
    unsigned char salt[16];                  // 盐
    unsigned char key[KEY_SIZE_SLOTH];       // 加密密钥
    uint8_t ks[SERPENT_KSSIZE_SLOTH];        // 密钥调度结果
    UT_hash_handle hh;
} KeyCacheEntry;

static KeyCacheEntry* key_cache = NULL;
static pthread_mutex_t key_cache_mutex = PTHREAD_MUTEX_INITIALIZER;


typedef struct {
    pthread_rwlock_t lock;
} FileLock;

typedef struct {
    char path[PATH_MAX];
    FileLock fl;
    UT_hash_handle hh;
} LockEntry;

static LockEntry* lock_table = NULL;
static pthread_mutex_t lock_table_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
	unsigned char key[KEY_SIZE_SLOTH];
	uint8_t ks[SERPENT_KSSIZE_SLOTH];
	uint8_t nonce[NONCE_SIZE_SLOTH];
} Keyinfo;
///
void remove_file_lock(const char* path) {
    pthread_mutex_lock(&lock_table_mutex);

    LockEntry* entry;
    HASH_FIND_STR(lock_table, path, entry);
    if (entry) {
        pthread_rwlock_destroy(&entry->fl.lock);
        HASH_DEL(lock_table, entry);
        free(entry);
    }

    pthread_mutex_unlock(&lock_table_mutex);
}
void remove_cached_key(const char* path) {
    pthread_mutex_lock(&key_cache_mutex);

    KeyCacheEntry* entry;
    HASH_FIND_STR(key_cache, path, entry);
    if (entry) {
        HASH_DEL(key_cache, entry);
        free(entry);
    }

    pthread_mutex_unlock(&key_cache_mutex);
}
void rename_file_lock(const char* old_path, const char* new_path) {
	if (!old_path || !new_path || strlen(new_path) >= PATH_MAX) return;
    pthread_mutex_lock(&lock_table_mutex);

    LockEntry* entry;
    HASH_FIND_STR(lock_table, old_path, entry);
    if (entry) {
        // 从哈希表中移除旧路径
        HASH_DEL(lock_table, entry);

        // 更新路径
        strncpy(entry->path, new_path, PATH_MAX - 1);
        entry->path[PATH_MAX - 1] = '\0';

        // 重新添加到哈希表
        HASH_ADD_STR(lock_table, path, entry);
    }
    pthread_mutex_unlock(&lock_table_mutex);
}
void rename_cached_key(const char* old_path, const char* new_path) {
	if (!old_path || !new_path || strlen(new_path) >= PATH_MAX) return;
    pthread_mutex_lock(&key_cache_mutex);

    KeyCacheEntry* entry;
    HASH_FIND_STR(key_cache, old_path, entry);
    if (entry) {
        // 从哈希表中移除旧路径
        HASH_DEL(key_cache, entry);

        // 更新路径
        strncpy(entry->path, new_path, PATH_MAX - 1);
        entry->path[PATH_MAX - 1] = '\0';

        // 重新添加到哈希表
        HASH_ADD_STR(key_cache, path, entry);
    }
    pthread_mutex_unlock(&key_cache_mutex);
}

///////////////////// 加密相关 ///////////////////////

Keyinfo get_file_key(const char* path, const unsigned char* header, const char* password) {
    KeyCacheEntry* entry;
    Keyinfo result = {0};

    pthread_mutex_lock(&key_cache_mutex);
    HASH_FIND_STR(key_cache, path, entry);
    if (entry && memcmp(entry->salt, header, 16) == 0) {
        memcpy(result.key, entry->key, KEY_SIZE_SLOTH);
        memcpy(result.ks, entry->ks, SERPENT_KSSIZE_SLOTH);
        memcpy(result.nonce, header + 16, NONCE_SIZE_SLOTH);
        pthread_mutex_unlock(&key_cache_mutex);
        return result;
    }

    // Cache miss: 创建新 entry
	entry = malloc(sizeof(KeyCacheEntry));
	if (!entry) {
    	pthread_mutex_unlock(&key_cache_mutex);
    	printf("===MEM ALLOC ERROR===");
    return result; // result is zeroed earlier
	}
    strncpy(entry->path, path, PATH_MAX - 1);
    memcpy(entry->salt, header, 16);
    sloth_kdf(password, header, entry->key);
    serpent_set_key(entry->key, entry->ks);

    memcpy(result.key, entry->key, KEY_SIZE_SLOTH);
    memcpy(result.ks, entry->ks, SERPENT_KSSIZE_SLOTH);
    memcpy(result.nonce, header + 16, NONCE_SIZE_SLOTH);

    HASH_ADD_STR(key_cache, path, entry);
    pthread_mutex_unlock(&key_cache_mutex);
    return result;
}

FileLock* get_or_create_lock(const char* path) {
    LockEntry* entry;

    pthread_mutex_lock(&lock_table_mutex);
    HASH_FIND_STR(lock_table, path, entry);
    if (!entry) {
        entry = malloc(sizeof(LockEntry));
        strncpy(entry->path, path, PATH_MAX - 1);
        pthread_rwlock_init(&entry->fl.lock, NULL);
        HASH_ADD_STR(lock_table, path, entry);
    }
    pthread_mutex_unlock(&lock_table_mutex);

    return &entry->fl;
}

// 填充SALT和NONCE
void initialize_header(FILE* fp) {
	unsigned char header[HEADER_SIZE];
	if (secure_random(header, HEADER_SIZE) != 0) {
		memset(header, 0, HEADER_SIZE);
		return;
	}
	fseek(fp, 0, SEEK_SET);
	fwrite(header, 1, HEADER_SIZE, fp);
}

int read_header(FILE* fp, unsigned char* header) {
	fseek(fp, 0, SEEK_SET);
	size_t read_bytes = fread(header, 1, HEADER_SIZE, fp);
	return (read_bytes == HEADER_SIZE) ? 0 : -1;
}
//////////////////////////////////////////////////////
static void get_full_path(char* fullpath, const char* path) {
	snprintf(fullpath, PATH_MAX, "%s%s", mount_point, path);
}

static int myfs_getattr(const char* path, struct stat* stbuf) {
	memset(stbuf, 0, sizeof(struct stat));

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
	}

	char full_path[PATH_MAX];
	get_full_path(full_path, path);

	struct stat st;
	if (stat(full_path, &st) == -1)
		return -errno;

	if (S_ISDIR(st.st_mode)) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else {
		stbuf->st_mode = S_IFREG | 0644;
		stbuf->st_nlink = 1;
		stbuf->st_size = (st.st_size >= HEADER_SIZE) ? (st.st_size - HEADER_SIZE) : 0;
	}
	return 0;
}


static int myfs_open(const char* path, struct fuse_file_info* fi) {
	char full_path[PATH_MAX];
	get_full_path(full_path, path);

	int fd = open(full_path, O_RDWR);
	if (fd == -1)
		return -errno;

	fi->fh = fd; // 将文件描述符保存在 fi->fh 中
	return 0;
}

static int myfs_read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
	if (offset < 0) return -EINVAL;

	char full_path[PATH_MAX];
	get_full_path(full_path, path);

	FileLock* file_lock = get_or_create_lock(path);
	if (!file_lock) return -EIO;
	pthread_rwlock_wrlock(&file_lock->lock);

	int fd = fi->fh;
	if (fd < 0) {
		pthread_rwlock_unlock(&file_lock->lock);
		return -EIO;
	}

	unsigned char header[HEADER_SIZE];
	if (pread(fd, header, HEADER_SIZE, 0) != HEADER_SIZE) {
		pthread_rwlock_unlock(&file_lock->lock);
		return -EIO;
	}

	Keyinfo kinfo = get_file_key(path, header, user_password);

	size_t total_read = 0;
	char* buffer = malloc(BUFFER_SIZE);
	if (!buffer) {
		pthread_rwlock_unlock(&file_lock->lock);
		return -ENOMEM;
	}

	while (total_read < size) {
		size_t current_offset = offset + total_read;
		size_t chunk = (size - total_read > BUFFER_SIZE) ? BUFFER_SIZE : (size - total_read);

		ssize_t bytes = pread(fd, buffer, chunk, HEADER_SIZE + current_offset);
		if (bytes <= 0) break;

		ctr_decrypt_sloth((uint8_t*)buffer, bytes, kinfo.key, current_offset, kinfo.ks, kinfo.nonce);
		memcpy(buf + total_read, buffer, bytes);
		total_read += bytes;
	}

	free(buffer);
	pthread_rwlock_unlock(&file_lock->lock);
	return total_read;
}

static int myfs_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
	if (offset < 0) return -EINVAL;

	char full_path[PATH_MAX];
	get_full_path(full_path, path);

	FileLock* file_lock = get_or_create_lock(path);
	if (!file_lock) return -EIO;
	pthread_rwlock_wrlock(&file_lock->lock);

	int fd = fi->fh;
	if (fd < 0) {
		pthread_rwlock_unlock(&file_lock->lock);
		return -EIO;
	}

	unsigned char header[HEADER_SIZE];
	if (pread(fd, header, HEADER_SIZE, 0) != HEADER_SIZE) {
		pthread_rwlock_unlock(&file_lock->lock);
		return -EIO;
	}

	Keyinfo kinfo = get_file_key(path, header, user_password);

	size_t total_written = 0;
	char* buffer = malloc(BUFFER_SIZE);
	if (!buffer) {
		pthread_rwlock_unlock(&file_lock->lock);
		return -ENOMEM;
	}

	while (total_written < size) {
		size_t current_offset = offset + total_written;
		size_t chunk = (size - total_written > BUFFER_SIZE) ? BUFFER_SIZE : (size - total_written);

		memcpy(buffer, buf + total_written, chunk);
		ctr_encrypt_sloth((uint8_t*)buffer, chunk, kinfo.key, current_offset, (uint8_t*)buffer, kinfo.ks, kinfo.nonce);

		if (pwrite(fd, buffer, chunk, HEADER_SIZE + current_offset) != chunk) {
			free(buffer);
			pthread_rwlock_unlock(&file_lock->lock);
			return -EIO;
		}

		total_written += chunk;
	}

	free(buffer);
	pthread_rwlock_unlock(&file_lock->lock);
	return total_written;
}

static int myfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
	char full_path[PATH_MAX];
	get_full_path(full_path, path);

	int fd = open(full_path, O_CREAT | O_RDWR, mode);
	if (fd < 0)
		return -errno;

	unsigned char header[HEADER_SIZE];
	if (secure_random(header, HEADER_SIZE) == 0)
		write(fd, header, HEADER_SIZE);
	else
		write(fd, (unsigned char[HEADER_SIZE]) { 0 }, HEADER_SIZE);

	fi->fh = fd;

	get_or_create_lock(path);  // 初始化该文件的锁
	return 0;
}

static int myfs_truncate(const char* path, off_t size) {
	if (size < 0) return -EINVAL;

	char full_path[PATH_MAX];
	get_full_path(full_path, path);

	FileLock* file_lock = get_or_create_lock(path);
	if (!file_lock) return -EIO;
	pthread_rwlock_wrlock(&file_lock->lock);

	// 临界区
	int res = truncate(full_path, size + HEADER_SIZE);

	pthread_rwlock_unlock(&file_lock->lock);

	if (res == -1) return -errno;
	return 0;
}

static int myfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi) {
	(void)offset;
	(void)fi;

	DIR* dp;
	struct dirent* de;
	char full_path[PATH_MAX];

	get_full_path(full_path, path);
	dp = opendir(full_path);
	if (!dp) return -errno;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);

	while ((de = readdir(dp)) != NULL) {
		// 忽略隐藏的元数据（如 .DS_Store）
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;
		filler(buf, de->d_name, NULL, 0);
	}
	closedir(dp);
	return 0;
}

static int myfs_unlink(const char* path) {
	char full_path[PATH_MAX];
	get_full_path(full_path, path);

	int res = unlink(full_path);
	if (res == -1) return -errno;

	remove_file_lock(path);       // 移除锁
	remove_cached_key(path);      // 移除缓存密钥（如有）
	return 0;
}

static int myfs_rename(const char* from, const char* to) {
	char full_from[PATH_MAX], full_to[PATH_MAX];
	get_full_path(full_from, from);
	get_full_path(full_to, to);

	if (rename(full_from, full_to) != 0)
		return -errno;

	// 更新锁映射表
	rename_file_lock(from, to);

	// 更新密钥缓存
	rename_cached_key(from, to);

	return 0;
}

static int myfs_release(const char* path, struct fuse_file_info* fi) {
	int fd = fi->fh;
	if (fd >= 0) fsync(fd);
	if (fd >= 0) close(fd);

	// 清理临时文件（如 LibreOffice 临时文件）
	if (strstr(path, "~") || strstr(path, "#") || strstr(path, "lock")) {
		char full_path[PATH_MAX];
		get_full_path(full_path, path);
		unlink(full_path);
	}
	return 0;
}

static int myfs_flush(const char* path, struct fuse_file_info* fi) {
	// 对于简单实现，这里通常什么都不做，只要返回0即可
	return 0;
}

static int myfs_fsync(const char* path, int isdatasync, struct fuse_file_info* fi) {
	(void)path;
	int fd = fi->fh;
	if (fd < 0) return -EIO;
	return (fsync(fd) == 0) ? 0 : -errno;
}

static int myfs_chmod(const char* path, mode_t mode, struct fuse_file_info* fi) {
	(void)fi;
	char fullpath[PATH_MAX];
	get_full_path(fullpath, path);
	return (chmod(fullpath, mode) == 0) ? 0 : -errno;
}

static int myfs_chown(const char* path, uid_t uid, gid_t gid, struct fuse_file_info* fi) {
	(void)fi;
	char fullpath[PATH_MAX];
	get_full_path(fullpath, path);
	return (chown(fullpath, uid, gid) == 0) ? 0 : -errno;
}

static int myfs_mkdir(const char* path, mode_t mode) {
	char fullpath[PATH_MAX];
	get_full_path(fullpath, path);
	return (mkdir(fullpath, mode) == 0) ? 0 : -errno;
}

static int myfs_rmdir(const char* path) {
	char fullpath[PATH_MAX];
	get_full_path(fullpath, path);
	return (rmdir(fullpath) == 0) ? 0 : -errno;
}

static int myfs_utimens(const char* path, const struct timespec tv[2], struct fuse_file_info* fi) {
	return 0;
}
static int myfs_access(const char* path, int mask) {
	return 0;
}
static int myfs_statfs(const char* path, struct statvfs* stbuf) {
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
	//.chmod = myfs_chmod,
	//.chown = myfs_chown,
	.mkdir = myfs_mkdir,
	.rmdir = myfs_rmdir,
#ifdef HAVE_UTIMENSAT
	.utimens = myfs_utimens,
#endif
	.access = myfs_access,
	.statfs = myfs_statfs,

};

int main_fuse_sloth(int argc, char* argv[]) {
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <mount-point> <directory>\n", argv[0]);
		exit(1);
	}
	else{
		if (get_user_input("Please Enter Password: ", user_password, sizeof(user_password)) != 0) {
			//continue;
		}
		strcpy(mount_point, argv[2]);
		char* new_argv[] = { argv[0], argv[1], "-f", "-o", "nonempty,allow_other" };
		int new_argc = 5;

		srand(time(NULL));
		return fuse_main(new_argc, new_argv, &myfs_oper, NULL);
	}
}
