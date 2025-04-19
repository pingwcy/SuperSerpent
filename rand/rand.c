#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/time.h>
#endif

#include "../params.h"
#include "../core/utils_sloth.h"
#include "rand.h"
#include "../pbkdf2/pbkdf2.h"
#ifdef __x86_64__
#include <x86intrin.h>
#elif defined(__aarch64__) || defined(__arm__)
#include <sys/auxv.h>
#endif

// 获取随机字节（主要熵源）
static int get_random_bytes(void *buf, size_t len) {
#ifdef _WIN32
    HCRYPTPROV hProvider = 0;
    if (!CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptGenRandom(hProvider, (DWORD)len, (BYTE*)buf)) {
        CryptReleaseContext(hProvider, 0);
        return -1;
    }
    CryptReleaseContext(hProvider, 0);
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) return -1;
    ssize_t result = read(fd, buf, len);
    close(fd);
    if (result != len) return -1;
#endif
    return 0;
}
int secure_random(void* buf, size_t len) {
    if (len == 0) return 0;

    unsigned char entropy_pool[ENTROPY_POOL_SIZE_SLOTH];
    unsigned char hmac_key[HMAC_WHIRLPOOL_KEY_SIZE_SLOTH];

    // 收集系统熵：HMAC key + 输入缓冲区
    if (get_random_bytes(hmac_key, HMAC_WHIRLPOOL_KEY_SIZE_SLOTH) != 0) return -1;
    if (get_random_bytes(entropy_pool, ENTROPY_POOL_SIZE_SLOTH) != 0) return -1;

    size_t generated = 0;
    uint64_t counter = 0;
    unsigned char round_input[ENTROPY_POOL_SIZE_SLOTH + sizeof(counter)];
    unsigned char round_output[OUTPUT_SIZE_SLOTH];

    while (generated < len) {
        // 构造输入：entropy_pool || counter
        memcpy(round_input, entropy_pool, ENTROPY_POOL_SIZE_SLOTH);
        memcpy(round_input + ENTROPY_POOL_SIZE_SLOTH, &counter, sizeof(counter));

        HMAC_Whirlpool(hmac_key, HMAC_WHIRLPOOL_KEY_SIZE_SLOTH, round_input,
            sizeof(round_input), round_output);

        size_t to_copy = (len - generated < OUTPUT_SIZE_SLOTH) ? (len - generated) : OUTPUT_SIZE_SLOTH;
        memcpy((unsigned char*)buf + generated, round_output, to_copy);

        generated += to_copy;
        counter++;
    }

    // 安全清除敏感数据
    secure_memzero_sloth(entropy_pool, sizeof(entropy_pool));
    secure_memzero_sloth(hmac_key, sizeof(hmac_key));
    secure_memzero_sloth(round_input, sizeof(round_input));
    secure_memzero_sloth(round_output, sizeof(round_output));

    return 0;
}

/*
// 增加时间熵
static void mix_time_entropy(unsigned char *buf, size_t len) {
    uint64_t t = 0;

#ifdef _WIN32  // Windows 平台
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);  // 获取高精度计时器的当前值
    t = counter.QuadPart;               // 使用计时器的当前值
#else  // 类 Unix 系统（Linux, macOS 等）
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);  // 获取单调时钟的时间
    t = ts.tv_sec ^ ts.tv_nsec;           // 计算时间戳
#endif

    // 混合时间戳到缓冲区
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= (t >> (i % sizeof(t))) & 0xFF;
    }
}

// 增加 CPU 时间戳熵
static void mix_cpu_entropy(unsigned char *buf, size_t len) {
#if defined(__x86_64__) || defined(__i386__)
    uint64_t tsc = __rdtsc();
#elif defined(__aarch64__) || defined(__arm__)
    uint64_t tsc = (uint64_t)getauxval(AT_RANDOM);
#else
    uint64_t tsc = (uint64_t)clock();
#endif
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= (tsc >> (i % sizeof(tsc))) & 0xFF;
    }
}

// 增加进程 ID 和线程 ID 熵
static void mix_pid_entropy(unsigned char *buf, size_t len) {
    #ifdef _WIN32  // Windows 平台
        DWORD pid = GetCurrentProcessId();  // 获取进程 ID
        DWORD tid = GetCurrentThreadId();   // 获取线程 ID
    #else  // 类 Unix 系统（Linux, macOS 等）
        pid_t pid = getpid();  // 获取进程 ID
        pid_t tid = 0;  // 默认初始化为 0

        #ifdef __linux__
        tid = syscall(SYS_gettid);  // Linux 使用 syscall 获取线程 ID
        #elif defined(__FreeBSD__)
        tid = (pid_t)thr_self();  // FreeBSD 使用 thr_self 获取线程 ID
        #elif defined(__APPLE__)
        tid = (pid_t)pthread_self();  // macOS 使用 pthread_self 获取线程 ID
        #endif
    #endif
    
    uint64_t id_mix = (uint64_t)pid ^ (uint64_t)tid;  // 混合进程 ID 和线程 ID
    
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= (id_mix >> (i % sizeof(id_mix))) & 0xFF;  // 混合 ID 到缓冲区
    }
}

// 组合多种熵源
static void enhance_entropy(unsigned char *buf, size_t len) {
    mix_time_entropy(buf, len);
    mix_cpu_entropy(buf, len);
    mix_pid_entropy(buf, len);
}
*/



/*
int main() {
    unsigned char rand_buf[16];
    if (secure_random(rand_buf, sizeof(rand_buf)) == 0) {
        printf("Generated random bytes: ");
        for (size_t i = 0; i < sizeof(rand_buf); i++) {
            printf("%02x ", rand_buf[i]);
        }
        printf("\n");
    } else {
        printf("Failed to generate random bytes\n");
    }
    return 0;
}
*/