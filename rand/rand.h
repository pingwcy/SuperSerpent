#ifndef RANDOM_UTILS_H
#define RANDOM_UTILS_H

#include <stddef.h> // 用于 size_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 生成随机字节并填充到缓冲区
 * 
 * @param buf 用于存储随机字节的缓冲区
 * @param len 需要生成的随机字节数
 * @return int 成功返回 0，失败返回 -1
 */
//int get_random_bytes(void *buf, size_t len);

int secure_random(void *buf, size_t len);
#ifdef __cplusplus
}
#endif

#endif // RANDOM_UTILS_H