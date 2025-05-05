#define FUSE_USE_VERSION 31
#define _FILE_OFFSET_BITS 64
#include <libgen.h>
#include <fuse.h>
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
#include "./rand/rand.h"
#include "params.h"
#include "./vcserpent/SerpentFast.h"
#include "./pbkdf2/pbkdf2.h"
#include "./core/utils_sloth.h"
#define MAX_FILES 12800

#define BUFFER_SIZE 4096
//#define PATH_MAX 256
#define MAX_FILE_SIZE 4096000
#define HEADER_SIZE 28 // 16字节SALT + 12字节NONCE
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t files_mutex = PTHREAD_MUTEX_INITIALIZER;

static char user_password[256]; // 全局密码缓存
typedef struct {
	char path[PATH_MAX];
	unsigned char key[KEY_SIZE_SLOTH];
	uint8_t ks[SERPENT_KSSIZE_SLOTH];
	unsigned char salt[16];   // 保存原始salt用于判断
	int valid;
} FileKeyCache;

static FileKeyCache key_cache[MAX_FILES];

typedef struct {
	char path[PATH_MAX];
	size_t size;
	int is_dir;//0file 1dir
	pthread_mutex_t lock; // 每个文件一个锁
	int lock_initialized;
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
void sloth_kdf(const char* password, const unsigned char* salt, unsigned char* out_key) {
	const int iterations = ITERATIONS_SLOTH; // 建议的迭代次数，可根据安全需求调整
	PBKDF2_HMAC_Whirlpool(
		(const uint8_t*)password, strlen(password),
		salt, 16, // 假设盐值长度是16字节(128位)
		iterations,
		KEY_SIZE_SLOTH,
		out_key
	);
}

Keyinfo get_file_key(const char* filename, const unsigned char* header, const char* password) {
	// 加锁（阻塞式）
	pthread_mutex_lock(&cache_mutex);

	const unsigned char* salt = header; // header 前16字节是 salt
	Keyinfo result = { 0 };

	for (int i = 0; i < MAX_FILES; i++) {
		if (key_cache[i].valid &&
			strcmp(key_cache[i].path, filename) == 0 &&
			memcmp(key_cache[i].salt, salt, 16) == 0) {

			memcpy(result.key, key_cache[i].key, KEY_SIZE_SLOTH);
			memcpy(result.ks, key_cache[i].ks, SERPENT_KSSIZE_SLOTH);
			memcpy(result.nonce, header + 16, NONCE_SIZE_SLOTH);
			//fprintf(stderr, "[get file key] Match at %d: filename=%s, salt=%02x%02x...\n",i,key_cache[i].filename, key_cache[i].salt[0], key_cache[i].salt[1]);
			pthread_mutex_unlock(&cache_mutex); // 成功命中缓存，先解锁再返回
			return result;
		}
	}

	for (int i = 0; i < MAX_FILES; i++) {
		if (!key_cache[i].valid) {
			strncpy(key_cache[i].path, filename, sizeof(key_cache[i].path) - 1);
			key_cache[i].path[sizeof(key_cache[i].path) - 1] = '\0';
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
	return (Keyinfo) { 0 }; // 返回无效结果
}
void ctr_encrypt_sloth(const uint8_t* data, size_t length, const uint8_t* key, uint64_t offset_bytes, uint8_t* encrypted_data, const uint8_t* ks, const uint8_t* nonce) {
	if (!data || !key || !encrypted_data || !ks || !nonce) return;
	//fprintf(stderr, "[ctr_encrypt_sloth] key=%02x%02x%02x...\n",key[0],key[1],key[2]);
	//printf(user_password);
	//printf("\n");

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

static void update_file_size(MyFile* f) {
	char full_path[PATH_MAX];
	snprintf(full_path, sizeof(full_path), "%s/%s", mount_point, f->path);

	struct stat st;
	if (stat(full_path, &st) == 0) {
		f->size = (st.st_size >= HEADER_SIZE) ? (st.st_size - HEADER_SIZE) : 0;
	}
	else {
		f->size = 0;
	}
}

void scan_dir_recursive(const char* base_path, const char* relative_path) {

	char full_path[PATH_MAX];
	snprintf(full_path, sizeof(full_path), "%s/%s", base_path, relative_path);

	DIR* dir = opendir(full_path);
	if (!dir) return;

	struct dirent* ent;
	while ((ent = readdir(dir)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
			continue;

		char rel_child[PATH_MAX];
		snprintf(rel_child, sizeof(rel_child), "%s/%s", relative_path, ent->d_name);

		if (ent->d_type == DT_DIR) {
			// 保存目录
			if (file_count < MAX_FILES) {
				strncpy(files[file_count].path, rel_child, PATH_MAX - 1);
				files[file_count].size = 0; // 目录没有 size
				files[file_count].is_dir = 1;
				pthread_mutex_init(&files[file_count].lock, NULL);
				files[file_count].lock_initialized = 1;			
				file_count++;
			}
			scan_dir_recursive(base_path, rel_child);  // 继续递归
		}
		else if (ent->d_type == DT_REG) {
			strncpy(files[file_count].path, rel_child, PATH_MAX - 1);
			update_file_size(&files[file_count]);
			files[file_count].is_dir = 0;
			pthread_mutex_init(&files[file_count].lock, NULL);
			files[file_count].lock_initialized = 1;		
			file_count++;
		}
	}

	closedir(dir);
}

static void load_files() {
	file_count = 0;
	scan_dir_recursive(mount_point, ""); // 从根目录开始
}


static void rescan_files() {
	pthread_mutex_lock(&files_mutex);
	for (int i = 0; i < file_count; i++) {
		if (files[i].lock_initialized) {
			pthread_mutex_destroy(&files[i].lock);
			files[i].lock_initialized = 0;
		}
	}
	file_count = 0;
	memset(files, 0, sizeof(files));
	load_files();
	pthread_mutex_unlock(&files_mutex);
}

static MyFile* find_file(const char* path) {
	pthread_mutex_lock(&files_mutex);
	for (int i = 0; i < file_count; i++) {
		if (strcmp(path, files[i].path) == 0) {
			pthread_mutex_unlock(&files_mutex);
			return &files[i];
		}
	}
	pthread_mutex_unlock(&files_mutex);
	return NULL;
}


static int myfs_getattr(const char* path, struct stat* stbuf) {
	memset(stbuf, 0, sizeof(struct stat));

	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
	}

	MyFile* f = find_file(path);
	if (!f)
		return -ENOENT;

	if (f->is_dir) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else {
		stbuf->st_mode = S_IFREG | 0644;
		stbuf->st_nlink = 1;
		stbuf->st_size = f->size;
	}
	return 0;
}


static int myfs_open(const char* path, struct fuse_file_info* fi) {
	MyFile* f = find_file(path);
	if (!f)
		return -ENOENT;

	char full_path[PATH_MAX];
	snprintf(full_path, sizeof(full_path), "%s/%s", mount_point, f->path);

	int fd = open(full_path, O_RDWR);
	if (fd == -1)
		return -errno;

	fi->fh = fd;  // 保存文件描述符
	return 0;
}

static int myfs_read(const char* path, char* buf, size_t size, off_t offset,
	struct fuse_file_info* fi) {
	MyFile* f = find_file(path);
	if (!f) return -ENOENT;
	if (offset >= f->size) return 0;
	pthread_mutex_lock(&f->lock);  // 加锁

	int fd = fi->fh;
	if (fd < 0) {
		pthread_mutex_unlock(&f->lock); // 解锁
		return -EIO;
	}
	unsigned char header[HEADER_SIZE];
	if (pread(fd, header, HEADER_SIZE, 0) != HEADER_SIZE){
		pthread_mutex_unlock(&f->lock); // 解锁
		return -EIO;
	}

	Keyinfo rst_sloth = get_file_key(f->path, header, user_password);
	size_t total_bytes_read = 0;
	char buffer[BUFFER_SIZE];

	while (total_bytes_read < size) {
		size_t current_offset = offset + total_bytes_read;
		size_t chunk = (size - total_bytes_read > BUFFER_SIZE) ? BUFFER_SIZE : size - total_bytes_read;

		ssize_t bytes_read = pread(fd, buffer, chunk, HEADER_SIZE + current_offset);
		if (bytes_read <= 0) break;

		ctr_decrypt_sloth((uint8_t*)buffer, bytes_read, rst_sloth.key, current_offset, rst_sloth.ks, rst_sloth.nonce);
		memcpy(buf + total_bytes_read, buffer, bytes_read);
		total_bytes_read += bytes_read;
	}
	pthread_mutex_unlock(&f->lock); // 解锁

	return total_bytes_read;
}

static int myfs_write(const char* path, const char* buf, size_t size, off_t offset,
	struct fuse_file_info* fi) {
	MyFile* f = find_file(path);
	if (!f) return -ENOENT;

	pthread_mutex_lock(&f->lock);
	int fd = fi->fh;
	if (fd < 0){
		pthread_mutex_unlock(&f->lock);
		return -EIO;
	}
	unsigned char header[HEADER_SIZE];
	if (pread(fd, header, HEADER_SIZE, 0) != HEADER_SIZE){
		pthread_mutex_unlock(&f->lock);
		return -EIO;
	}
	Keyinfo rst_sloth = get_file_key(f->path, header, user_password);
	size_t total_bytes_written = 0;
	char buffer[BUFFER_SIZE];

	while (total_bytes_written < size) {
		size_t current_offset = offset + total_bytes_written;
		size_t chunk = (size - total_bytes_written > BUFFER_SIZE) ? BUFFER_SIZE : size - total_bytes_written;

		memcpy(buffer, buf + total_bytes_written, chunk);
		ctr_encrypt_sloth((const uint8_t*)buffer, chunk, rst_sloth.key, current_offset, (uint8_t*)buffer, rst_sloth.ks, rst_sloth.nonce);

		if (pwrite(fd, buffer, chunk, HEADER_SIZE + current_offset) != chunk){
			pthread_mutex_unlock(&f->lock);
			return -EIO;
		}
		total_bytes_written += chunk;
	}

	fsync(fd);
	update_file_size(f);
	pthread_mutex_unlock(&f->lock);
	return size;
}

static int myfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
	pthread_mutex_lock(&files_mutex);

	if (file_count >= MAX_FILES) {
		pthread_mutex_unlock(&files_mutex);
		return -ENOSPC;
	}

	char full_path[PATH_MAX];
	snprintf(full_path, sizeof(full_path), "%s/%s", mount_point, path);

	int fd = open(full_path, O_CREAT | O_RDWR, 0644);
	if (fd < 0) {
		pthread_mutex_unlock(&files_mutex);
		return -errno;
	}

	unsigned char header[HEADER_SIZE];
	if (secure_random(header, HEADER_SIZE) == 0)
		write(fd, header, HEADER_SIZE);
	else
		write(fd, (unsigned char[HEADER_SIZE]) { 0 }, HEADER_SIZE);

	fi->fh = fd;

	strncpy(files[file_count].path, path, PATH_MAX - 1);
	files[file_count].path[PATH_MAX - 1] = '\0';
	files[file_count].is_dir = 0;
	files[file_count].size = 0;
	pthread_mutex_init(&files[file_count].lock, NULL);
	files[file_count].lock_initialized = 1;
	file_count++;

	pthread_mutex_unlock(&files_mutex);

	return 0;
}

static int myfs_truncate(const char* path, off_t size) {
    MyFile* f = find_file(path);
    if (!f) return -ENOENT;

    char fullpath[PATH_MAX];
    get_full_path(fullpath, path);

    // 实际文件大小 = 数据 + header
    int res = truncate(fullpath, size + HEADER_SIZE);
    if (res == -1) return -errno;

    f->size = size;
    update_file_size(f); // 再次确认逻辑大小
    return 0;
}

static int myfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
    off_t offset, struct fuse_file_info* fi) {
    (void)offset;
    (void)fi;
    
    rescan_files();

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    size_t path_len = strlen(path);
    if (path_len > 1 && path[path_len-1] == '/')
        path_len--; // 去掉末尾的/

    for (int i = 0; i < file_count; i++) {
        const char* file_path = files[i].path;

        // 检查是否以当前路径开头
        if (strncmp(file_path, path, path_len) != 0)
            continue;

        // 获取剩余部分
        const char* remaining = file_path + path_len;
        if (*remaining == '/') remaining++;

        // 只取第一级目录/文件名
        const char* slash = strchr(remaining, '/');
        if (slash != NULL) {
            // 如果是更深层的路径，跳过
            continue;
        }

        // 确保不是空字符串
        if (*remaining == '\0')
            continue;

        // 添加条目
        filler(buf, remaining, NULL, 0);
    }
    return 0;
}

static int myfs_unlink(const char* path) { 
	char full_path[PATH_MAX];
	get_full_path(full_path, path);

	if (unlink(full_path) != 0) return -errno;

	pthread_mutex_lock(&files_mutex);
	for (int i = 0; i < file_count; i++) {
		if (strcmp(files[i].path, path) == 0) {
			if (files[i].lock_initialized) {
				pthread_mutex_destroy(&files[i].lock);
				files[i].lock_initialized = 0;
			}
			for (int j = i; j < file_count - 1; j++) {
				files[j] = files[j + 1];
			}
			file_count--;
			break;
		}
	}
	pthread_mutex_unlock(&files_mutex);

	pthread_mutex_lock(&cache_mutex);
	for (int i = 0; i < MAX_FILES; i++) {
		if (key_cache[i].valid && strcmp(key_cache[i].path, path) == 0) {
			key_cache[i].valid = 0;
		}
	}
	pthread_mutex_unlock(&cache_mutex);

	return 0;
}

static int myfs_rename(const char* from, const char* to) {
	char full_from[PATH_MAX], full_to[PATH_MAX];
	get_full_path(full_from, from);
	get_full_path(full_to, to);

	int res = rename(full_from, full_to);
	if (res == -1) return -errno;

	pthread_mutex_lock(&files_mutex);
	for (int i = 0; i < file_count; i++) {
		if (strcmp(files[i].path, from) == 0) {
			strncpy(files[i].path, to, PATH_MAX - 1);
			files[i].path[PATH_MAX - 1] = '\0';
			break;
		}
	}
	pthread_mutex_unlock(&files_mutex);

	pthread_mutex_lock(&cache_mutex);
	for (int i = 0; i < MAX_FILES; i++) {
		if (key_cache[i].valid && strcmp(key_cache[i].path, from) == 0) {
			strncpy(key_cache[i].path, to, PATH_MAX - 1);
			key_cache[i].path[PATH_MAX - 1] = '\0';
		}
	}
	pthread_mutex_unlock(&cache_mutex);
	rescan_files();
	return 0;
}

static int myfs_release(const char* path, struct fuse_file_info* fi) {
	int fd = fi->fh;
	if (fd >= 0) {
		close(fd);
	}
	// 如果文件名不是 files[] 中的内容，有可能是 LibreOffice 的临时文件
	const char* fname = path;
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
static int myfs_flush(const char* path, struct fuse_file_info* fi) {
	// 对于简单实现，这里通常什么都不做，只要返回0即可
	return 0;
}

static int myfs_fsync(const char* path, int isdatasync, struct fuse_file_info* fi) {
	int fd = fi->fh;
	if (fd < 0) return -EIO;

	return (fsync(fd) == 0) ? 0 : -EIO;
}

static int myfs_chmod(const char* path, mode_t mode, struct fuse_file_info* fi) {
	(void)fi;
	char fullpath[512];
	get_full_path(fullpath, path);

	int res = chmod(fullpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int myfs_chown(const char* path, uid_t uid, gid_t gid, struct fuse_file_info* fi) {
	(void)fi;
	char fullpath[512];
	get_full_path(fullpath, path);

	int res = chown(fullpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int myfs_mkdir(const char* path, mode_t mode) {
	char fullpath[512];
	get_full_path(fullpath, path);

	int res = mkdir(fullpath, mode);
	if (res == -1)
		return -errno;
	
	rescan_files();  // 重新扫描，更新所有文件状态
	return 0;
}

static int myfs_rmdir(const char* path) {
	char fullpath[512];
	get_full_path(fullpath, path);

	int res = rmdir(fullpath);
	if (res == -1)
		return -errno;

	return 0;
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
	.chmod = myfs_chmod,
	.chown = myfs_chown,
	.mkdir = myfs_mkdir,
	.rmdir = myfs_rmdir,
	.utimens = myfs_utimens,
	.access = myfs_access,
	.statfs = myfs_statfs,

};

int main(int argc, char* argv[]) {
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
	char* new_argv[] = { argv[0], argv[1], "-f", "-o", "nonempty" };
	int new_argc = 5;

	srand(time(NULL));
	load_files();
	return fuse_main(new_argc, new_argv, &myfs_oper, NULL);
}
