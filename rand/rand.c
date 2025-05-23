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

// Get Random Bytes (Main Entroy Source)
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

    // Collect Entroy fro System: HMAC key + Buffer
    if (get_random_bytes(hmac_key, HMAC_WHIRLPOOL_KEY_SIZE_SLOTH) != 0) return -1;
    if (get_random_bytes(entropy_pool, ENTROPY_POOL_SIZE_SLOTH) != 0) return -1;

    size_t generated = 0;
    uint64_t counter = 0;
    unsigned char round_input[ENTROPY_POOL_SIZE_SLOTH + sizeof(counter)];
    unsigned char round_output[OUTPUT_SIZE_SLOTH];

    while (generated < len) {
        // Make: entropy_pool || counter
        memcpy(round_input, entropy_pool, ENTROPY_POOL_SIZE_SLOTH);
        memcpy(round_input + ENTROPY_POOL_SIZE_SLOTH, &counter, sizeof(counter));

        HMAC_Whirlpool(hmac_key, HMAC_WHIRLPOOL_KEY_SIZE_SLOTH, round_input,
            sizeof(round_input), round_output);

        size_t to_copy = (len - generated < OUTPUT_SIZE_SLOTH) ? (len - generated) : OUTPUT_SIZE_SLOTH;
        memcpy((unsigned char*)buf + generated, round_output, to_copy);

        generated += to_copy;
        counter++;
    }

    // Zero Memmory
    secure_memzero_sloth(entropy_pool, sizeof(entropy_pool));
    secure_memzero_sloth(hmac_key, sizeof(hmac_key));
    secure_memzero_sloth(round_input, sizeof(round_input));
    secure_memzero_sloth(round_output, sizeof(round_output));

    return 0;
}

/*
Following functions are abandaned.
// Add time entropy
static void mix_time_entropy(unsigned char *buf, size_t len) {
    uint64_t t = 0;

#ifdef _WIN32  // Windows 
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);  // Accirate time
    t = counter.QuadPart;               // Current time
#else  // Unix (Linux, macOS)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);  // Get clock
    t = ts.tv_sec ^ ts.tv_nsec;           // Calc time stamp
#endif

    // Mix time to buffer
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= (t >> (i % sizeof(t))) & 0xFF;
    }
}

// Add CPU Time Entropy
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

// Add process ID and thread ID entropy
static void mix_pid_entropy(unsigned char *buf, size_t len) {
    #ifdef _WIN32  // Windows
        DWORD pid = GetCurrentProcessId();  // Get process ID
        DWORD tid = GetCurrentThreadId();   // Get thread ID
    #else  // Unix (Linux, macOS)
        pid_t pid = getpid();  // Get process ID
        pid_t tid = 0;  // Initial to 0

        #ifdef __linux__
        tid = syscall(SYS_gettid);  // Linux use syscall to get thread ID
        #elif defined(__FreeBSD__)
        tid = (pid_t)thr_self();  // FreeBSD use thr_self to get thread ID
        #elif defined(__APPLE__)
        tid = (pid_t)pthread_self();  // macOS use pthread_self to get thread ID
        #endif
    #endif
    
    uint64_t id_mix = (uint64_t)pid ^ (uint64_t)tid;  // Mix process ID and thread ID
    
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= (id_mix >> (i % sizeof(id_mix))) & 0xFF;  // Mix ID to buffer
    }
}

// Mix multi entropy
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