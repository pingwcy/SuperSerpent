#ifndef UTILS_SLOTH_H
#define UTILS_SLOTH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int VERBOSE_SLOTH;
void ct_xor_sloth(uint8_t* out, const uint8_t* in, uint8_t val, size_t len);
void ct_memcpy_sloth(uint8_t* dst, const uint8_t* src, size_t len);
void secure_memzero_sloth(void* ptr, size_t len);
int constant_time_compare_sloth(const uint8_t* a, const uint8_t* b, size_t len);
void strtolower(const char* src, char* dest);
int get_user_input(const char* label, char* buffer, size_t buffer_size);
void handle_error_sloth(const char* msg);
void clear_input_buffer_sloth();
int safe_fgets_sloth(char* buffer, size_t buffer_size);
void print_hex_sloth(const char* label, const uint8_t* data, size_t length);
size_t pkcs7_pad_sloth(unsigned char* input, size_t len, unsigned char* output);
size_t pkcs7_unpad_sloth(unsigned char* data, size_t len);
void hex_to_uint8_sloth(const char* hex, uint8_t* output, size_t len);
char* uint8_to_hex_string_sloth(uint8_t* data, size_t len);
double get_time_ms();
uint32_t crc32_calculate_sloth(const uint8_t *data, size_t length);

#ifdef __cplusplus
}
#endif

#endif