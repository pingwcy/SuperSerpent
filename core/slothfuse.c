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

///////////////////// 加密相关 ///////////////////////

Keyinfo get_file_key(const char* path, const unsigned char* header, const char* password) {
    pthread_mutex_lock(&key_cache_mutex);
	
    KeyCacheEntry* entry;
    Keyinfo result = {0};

    // 查找缓存
    HASH_FIND_STR(key_cache, path, entry);
    if (entry && memcmp(entry->salt, header, 16) == 0) {
        // 缓存命中，直接返回
        memcpy(result.key, entry->key, KEY_SIZE_SLOTH);
        memcpy(result.ks, entry->ks, SERPENT_KSSIZE_SLOTH);
        memcpy(result.nonce, header + 16, NONCE_SIZE_SLOTH);
        pthread_mutex_unlock(&key_cache_mutex);
        return result;
    }

    // 构造新 entry
    KeyCacheEntry* new_entry = malloc(sizeof(KeyCacheEntry));
    if (!new_entry) {
        printf("===MEM ALLOC ERROR===\n");
        pthread_mutex_unlock(&key_cache_mutex);
        return result;
    }
	if (entry) {
        HASH_DEL(key_cache, entry);
        free(entry);
    }

    strncpy(new_entry->path, path, PATH_MAX - 1);
    new_entry->path[PATH_MAX - 1] = '\0';
    memcpy(new_entry->salt, header, 16);
    sloth_kdf(password, header, new_entry->key);
    serpent_set_key(new_entry->key, new_entry->ks);

    HASH_ADD_STR(key_cache, path, new_entry);
    memcpy(result.key, new_entry->key, KEY_SIZE_SLOTH);
    memcpy(result.ks, new_entry->ks, SERPENT_KSSIZE_SLOTH);
    memcpy(result.nonce, header + 16, NONCE_SIZE_SLOTH);

    pthread_mutex_unlock(&key_cache_mutex);
    return result;
}


FileLock* get_or_create_lock(const char* path) {
    pthread_mutex_lock(&lock_table_mutex);
	LockEntry* entry;
    HASH_FIND_STR(lock_table, path, entry);
    if (!entry) {
        // 先创建新 entry，避免在锁内长时间运行
        LockEntry* new_entry = malloc(sizeof(LockEntry));
        if (new_entry) {
            strncpy(new_entry->path, path, PATH_MAX - 1);
            new_entry->path[PATH_MAX - 1] = '\0';
            pthread_rwlock_init(&new_entry->fl.lock, NULL);

            // 再次检查哈希表中是否已插入（另一个线程可能已完成）
            HASH_FIND_STR(lock_table, path, entry);
            if (!entry) {
                HASH_ADD_STR(lock_table, path, new_entry);
                entry = new_entry;
            } else {
                // 已存在，释放我们刚创建的 entry
                pthread_rwlock_destroy(&new_entry->fl.lock);
                free(new_entry);
            }
        }
    }
    pthread_mutex_unlock(&lock_table_mutex);
    return entry ? &entry->fl : NULL;
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

	//remove_file_lock(path);       // 移除锁
	//remove_cached_key(path);      // 移除缓存密钥（如有）
	return 0;
}

static int myfs_rename(const char* from, const char* to) {
	char full_from[PATH_MAX], full_to[PATH_MAX];
	get_full_path(full_from, from);
	get_full_path(full_to, to);

	if (rename(full_from, full_to) != 0)
		return -errno;

	// 更新锁映射表
	//rename_file_lock(from, to);

	// 更新密钥缓存
	//rename_cached_key(from, to);

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

static int myfs_chmod(const char* path, mode_t mode) {
	//(void)fi;
	char fullpath[PATH_MAX];
	get_full_path(fullpath, path);
	return (chmod(fullpath, mode) == 0) ? 0 : -errno;
}

static int myfs_chown(const char* path, uid_t uid, gid_t gid) {
	//(void)fi;
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
	(void) fi;
	int res;
	char fullpath[PATH_MAX];
	get_full_path(fullpath, path);

	/* don't use utime/utimes since they follow symlinks */
	res = utimensat(0, fullpath, tv, AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return -errno;

	return 0;
}
static int myfs_access(const char* path, int mask) {
	int res;
	char fullpath[PATH_MAX];
	get_full_path(fullpath, path);

	res = access(fullpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}
static int myfs_statfs(const char* path, struct statvfs* stbuf) {
	int res;
	char fullpath[PATH_MAX];
	get_full_path(fullpath, path);

	res = statvfs(fullpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}
#ifdef HAVE_POSIX_FALLOCATE
static int myfs_fallocate(const char *path, int mode,
			off_t offset, off_t length, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;

	if (mode)
		return -EOPNOTSUPP;

	if(fi == NULL)
		fd = open(path, O_WRONLY);
	else
		fd = fi->fh;
	
	if (fd == -1)
		return -errno;

	res = -posix_fallocate(fd, offset, length);

	if(fi == NULL)
		close(fd);
	return res;
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int myfs_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char fullpath[PATH_MAX];
	get_full_path(fullpath, path);

	int res = lsetxattr(fullpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int myfs_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char fullpath[PATH_MAX];
	get_full_path(fullpath, path);

	int res = lgetxattr(fullpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int myfs_listxattr(const char *path, char *list, size_t size)
{
	char fullpath[PATH_MAX];
	get_full_path(fullpath, path);

	int res = llistxattr(fullpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int myfs_removexattr(const char *path, const char *name)
{
	char fullpath[PATH_MAX];
	get_full_path(fullpath, path);

	int res = lremovexattr(fullpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

#ifdef HAVE_COPY_FILE_RANGE
static ssize_t myfs_copy_file_range(const char *path_in,
				   struct fuse_file_info *fi_in,
				   off_t offset_in, const char *path_out,
				   struct fuse_file_info *fi_out,
				   off_t offset_out, size_t len, int flags)
{
	int fd_in, fd_out;
	ssize_t res;

	if(fi_in == NULL)
		fd_in = open(path_in, O_RDONLY);
	else
		fd_in = fi_in->fh;

	if (fd_in == -1)
		return -errno;

	if(fi_out == NULL)
		fd_out = open(path_out, O_WRONLY);
	else
		fd_out = fi_out->fh;

	if (fd_out == -1) {
		close(fd_in);
		return -errno;
	}

	res = copy_file_range(fd_in, &offset_in, fd_out, &offset_out, len,
			      flags);
	if (res == -1)
		res = -errno;

	if (fi_out == NULL)
		close(fd_out);
	if (fi_in == NULL)
		close(fd_in);

	return res;
}
#endif

static off_t myfs_lseek(const char *path, off_t off, int whence, struct fuse_file_info *fi)
{
	int fd;
	off_t res;

	if (fi == NULL)
		fd = open(path, O_RDONLY);
	else
		fd = fi->fh;

	if (fd == -1)
		return -errno;

	res = lseek(fd, off, whence);
	if (res == -1)
		res = -errno;

	if (fi == NULL)
		close(fd);
	return res;
}

static int myfs_link(const char *from, const char *to)
{
	int res;
	char fullpath1[PATH_MAX];
	get_full_path(fullpath1, from);
	char fullpath2[PATH_MAX];
	get_full_path(fullpath2, to);

	res = link(fullpath1, fullpath2);
	if (res == -1)
		return -errno;

	return 0;
}
static int myfs_symlink(const char *from, const char *to)
{
	int res;
	char fullpath1[PATH_MAX];
	get_full_path(fullpath1, from);
	char fullpath2[PATH_MAX];
	get_full_path(fullpath2, to);

	res = symlink(fullpath1, fullpath2);
	if (res == -1)
		return -errno;

	return 0;
}
static int myfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char fullpath[PATH_MAX];
	get_full_path(fullpath, path);

	res = mknod(fullpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}
static int myfs_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char fullpath[PATH_MAX];
	get_full_path(fullpath, path);

	res = readlink(fullpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
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
	.readlink = myfs_readlink,
	.mknod = myfs_mknod,
	.symlink = myfs_symlink,
	.link = myfs_link,
#ifdef HAVE_UTIMENSAT
	.utimens = myfs_utimens,
#endif
	.access = myfs_access,
	.statfs = myfs_statfs,
#ifdef HAVE_POSIX_FALLOCATE
	//.fallocate	= myfs_fallocate, //Not Implemented
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= myfs_setxattr,
	.getxattr	= myfs_getxattr,
	.listxattr	= myfs_listxattr,
	.removexattr	= myfs_removexattr,
#endif
#ifdef HAVE_COPY_FILE_RANGE
	//.copy_file_range = myfs_copy_file_range, //Not Implemented
#endif
	//.lseek		= myfs_lseek, //Not Implemented

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
		char* new_argv[] = { argv[0], argv[1], "-f", "-o", "nonempty,allow_other,exec" };
		int new_argc = 5;

		srand(time(NULL));
		return fuse_main(new_argc, new_argv, &myfs_oper, NULL);
	}
}


/*
// NOTE: We do not free lock_table or key_cache entries on unlink/rename.
// This avoids use-after-free without reference counting in a lightweight single-user context.

void remove_file_lock(const char* path) {
	if (!path) return;
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
	if (!path) return;
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

    // 检查是否冲突
    LockEntry* existing;
    HASH_FIND_STR(lock_table, new_path, existing);
    if (existing) {
        pthread_mutex_unlock(&lock_table_mutex);
        return; // 已存在新路径，避免冲突
    }

    LockEntry* entry;
    HASH_FIND_STR(lock_table, old_path, entry);
    if (entry) {
        HASH_DEL(lock_table, entry);
        strncpy(entry->path, new_path, PATH_MAX - 1);
        entry->path[PATH_MAX - 1] = '\0';
        HASH_ADD_STR(lock_table, path, entry);
    }

    pthread_mutex_unlock(&lock_table_mutex);
}

void rename_cached_key(const char* old_path, const char* new_path) {
    if (!old_path || !new_path || strlen(new_path) >= PATH_MAX) return;

    pthread_mutex_lock(&key_cache_mutex);

    // 检查是否已存在新路径，避免覆盖
    KeyCacheEntry* existing;
    HASH_FIND_STR(key_cache, new_path, existing);
    if (existing) {
        pthread_mutex_unlock(&key_cache_mutex);
        return;
    }

    KeyCacheEntry* entry;
    HASH_FIND_STR(key_cache, old_path, entry);
    if (entry) {
        HASH_DEL(key_cache, entry);
        strncpy(entry->path, new_path, PATH_MAX - 1);
        entry->path[PATH_MAX - 1] = '\0';
        HASH_ADD_STR(key_cache, path, entry);
    }

    pthread_mutex_unlock(&key_cache_mutex);
}

//Unused functions
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
*/