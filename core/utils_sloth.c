#include "utils_sloth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../params.h"

int get_user_input(const char* label, char* buffer, size_t buffer_size) {
	printf("%s", label);
	fflush(stdout);  
	if (fgets(buffer, buffer_size, stdin) == NULL) {
		fprintf(stderr, "Error reading input.\n");
		return 1;
	}
	buffer[strcspn(buffer, "\n")] = '\0'; 
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
	if (!label || !data) return; 
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
	if (len == 0) return 0;
	uint8_t pad_len = data[len - 1];
	if (pad_len > BLOCK_SIZE_SLOTH || pad_len == 0) return len; 
	for (size_t i = 0; i < pad_len; i++) {
		if (data[len - 1 - i] != pad_len) return len; 
	}
	return len - pad_len;
}

void hex_to_uint8_sloth(const char* hex, uint8_t* output, size_t len) {
	for (size_t i = 0; i < len; i++) {
		sscanf(hex + 2 * i, "%2hhx", &output[i]);
	}
}

char* uint8_to_hex_string_sloth(uint8_t* data, size_t len) {
	char* hex_string = (char*)malloc(len * 2 + 1);
	if (!hex_string) return NULL;

	for (size_t i = 0; i < len; i++) {
		snprintf(hex_string + i * 2, 3, "%02X", data[i]);
	}
	return hex_string;
}