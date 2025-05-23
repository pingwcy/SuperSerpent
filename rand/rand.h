#ifndef RANDOM_UTILS_H
#define RANDOM_UTILS_H

#include <stddef.h> // For size_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fill Buffer with Secure Randoms Bytes
 * 
 * @param buf Buffer to Store Random Bytes[]
 * @param len Required Random Bytes Length
 * @return int Success for 0，Fail for -1
 */
//int get_random_bytes(void *buf, size_t len);

int secure_random(void *buf, size_t len);
#ifdef __cplusplus
}
#endif

#endif // RANDOM_UTILS_H