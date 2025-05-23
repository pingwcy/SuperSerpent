#include "utils_sloth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>
#include "../params.h"
#if defined(_WIN32)
#include <windows.h>
#endif

// Constant-time XOR
void ct_xor_sloth(uint8_t* out, const uint8_t* in, uint8_t val, size_t len) {
	for (size_t i = 0; i < len; ++i) {
		out[i] = in[i] ^ val;
	}
}

// Constant-time copy
void ct_memcpy_sloth(uint8_t* dst, const uint8_t* src, size_t len) {
	volatile uint8_t dummy = 0;
	for (size_t i = 0; i < len; ++i) {
		dst[i] = src[i];
		dummy |= dst[i]; // Dummy
	}
	(void)dummy;
}

void secure_memzero_sloth(void* ptr, size_t len) {
if (ptr == NULL || len == 0) return;

#if defined(_WIN32)
	SecureZeroMemory(ptr, len); // For Windows
#else
	// Check if memset_s avaiable
#if defined(__STDC_LIB_EXT1__) && (__STDC_WANT_LIB_EXT1__ == 1)
	if (memset_s(ptr, len, 0, len) == 0) {
		return;
	}
#endif

	// fallback solution + memory barrier to avoid optimizition
	volatile unsigned char* p = (volatile unsigned char*)ptr;
	while (len--) {
		*p++ = 0;
	}

	// Memory Barrier
	__asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}


int constant_time_compare_sloth(const uint8_t* a, const uint8_t* b, size_t len) {
	uint8_t result = 0;
	for (size_t i = 0; i < len; i++) {
		result |= a[i] ^ b[i];
	}
	return result == 0;
}

void strtolower(const char* src, char* dest) {
	for (; *src; ++src, ++dest)
		*dest = tolower(*src);
	*dest = '\0';
}

int get_user_input(const char* label, char* buffer, size_t buffer_size) {
	// Safely get user input
	if (buffer == NULL || buffer_size == 0) {
		fprintf(stderr, "[ERROR] Invalid parameters: buffer=%p, size=%zu\n",
			(void*)buffer, buffer_size);
		return EINVAL;  // Parameters invalid
	}

	// End with 0
	buffer[0] = '\0';

	// Check stdin and eof
	if (feof(stdin) || ferror(stdin)) {
		fprintf(stderr, "[ERROR] stdin is in error state or at EOF\n");
		clearerr(stdin);  // Clear error
		return EIO;
	}

	// Flush stdout
	if (label != NULL) {
		printf("%s", label);
		if (fflush(stdout) != 0) {
			fprintf(stderr, "[ERROR] Failed to flush stdout\n");
			return EIO;
		}
	}

	// Get user input
	if (fgets(buffer, buffer_size, stdin) == NULL) {
		if (feof(stdin)) {
			fprintf(stderr, "[WARNING] EOF reached while reading input\n");
			return EOF;
		}
		else {
			fprintf(stderr, "[ERROR] Input read failure: %s\n", strerror(errno));
			return EIO;
		}
	}

	// newline
	char* newline = strchr(buffer, '\n');
	if (newline != NULL) {
		*newline = '\0';
	}
	else {
		// Check length
		int c;
		while ((c = getchar()) != '\n' && c != EOF) {
			// Using up of input
		}

		// Check byffer length
		if (buffer_size > 1) {
			buffer[buffer_size - 1] = '\0';
		}
		else {
			buffer[0] = '\0';  // buffer_size=1 is the least
		}

		fprintf(stderr, "[WARNING] Input truncated (max %zu characters)\n",
			buffer_size - 1);
		return EOVERFLOW;  // Too long
	}

	// Check if No Input
	if (buffer[0] == '\0') {
		fprintf(stderr, "[WARNING] Empty input received\n");
		return ENODATA;  // No input
	}

	return 0;
}

void handle_error_sloth(const char* msg) {
	fprintf(stderr, "%s\n", msg);
	//exit(1);
}

void clear_input_buffer_sloth() {
	int c;
	while ((c = getchar()) != '\n' && c != EOF) {
	}
}
int safe_fgets_sloth(char* buffer, size_t buffer_size) {
	if (fgets(buffer, buffer_size, stdin) == NULL) {
		return 0; 
	}

	buffer[strcspn(buffer, "\n")] = '\0';

	return 1; 
}
void print_hex_sloth(const char* label, const uint8_t* data, size_t length) {
	if (!label || !data || VERBOSE_SLOTH == 0) return;
	printf("%s: ", label);
	for (size_t i = 0; i < length; i++) {
		printf("%02X", data[i]); 
	}
	printf("\n");
}
size_t pkcs7_pad_sloth(unsigned char* input, size_t len, unsigned char* output) {
	size_t pad_len = BLOCK_SIZE_SLOTH - (len % BLOCK_SIZE_SLOTH);
	size_t new_len = len + pad_len;

	memcpy(output, input, len);
	memset(output + len, pad_len, pad_len);

	return new_len;
}

size_t pkcs7_unpad_sloth(unsigned char* data, size_t len) {
	if (len == 0) {
		handle_error_sloth("Padding error: empty input");
		return len;
	}

	uint8_t pad_len = data[len - 1];

	// Check padding length
	if (pad_len == 0 || pad_len > BLOCK_SIZE_SLOTH || pad_len > len) {
		handle_error_sloth("Padding error: invalid padding length");
		return len;
	}

	uint8_t bad = 0;

	// Check padding format
	for (size_t i = 0; i < pad_len; i++) {
		bad |= data[len - 1 - i] ^ pad_len;
	}

	if (bad != 0) {
		handle_error_sloth("Padding error: incorrect padding bytes");
		return len;
	}

	return len - pad_len;
}

void hex_to_uint8_sloth(const char* hex, uint8_t* output, size_t len) {
	if (strlen(hex) < len * 2) {
		handle_error_sloth("Hex input too short");
		return;
	}

	unsigned int byte;
	for (size_t i = 0; i < len; i++) {
		sscanf(hex + 2 * i, "%2x", &byte);
		output[i] = (uint8_t)byte;
	}
}

char* uint8_to_hex_string_sloth(uint8_t* data, size_t len) {
	char* hex_string = (char*)malloc(len * 2 + 1);
	if (!hex_string) return NULL;

	for (size_t i = 0; i < len; i++) {
		snprintf(hex_string + i * 2, 3, "%02x", data[i]);
	}
	return hex_string;
}

#ifdef _WIN32
#include <windows.h>
double get_time_ms() {
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000.0 / freq.QuadPart;
}
#else
#include <time.h>
double get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}
#endif
