#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>  // 包含CryptGenRandom的头文件
#else
#include <fcntl.h>
#include <unistd.h>
#endif

int get_random_bytes(void *buf, size_t len) {
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
    return 0;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) return -1;
    ssize_t result = read(fd, buf, len);
    close(fd);
    return (result == len) ? 0 : -1;
#endif
}