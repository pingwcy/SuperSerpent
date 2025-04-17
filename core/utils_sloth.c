#include "utils_sloth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include "../params.h"

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
	// �����Լ��1����֤����������Ч��
	if (buffer == NULL || buffer_size == 0) {
		fprintf(stderr, "[ERROR] Invalid parameters: buffer=%p, size=%zu\n",
			(void*)buffer, buffer_size);
		return EINVAL;  // ���ر�׼������
	}

	// �����Լ��2��ȷ����������д
	buffer[0] = '\0';

	// �����Լ��3����֤��׼�����Ƿ����
	if (feof(stdin) || ferror(stdin)) {
		fprintf(stderr, "[ERROR] stdin is in error state or at EOF\n");
		clearerr(stdin);  // �������״̬
		return EIO;
	}

	// ��ʾ��ʾ��Ϣ��ȷ�����
	if (label != NULL) {
		printf("%s", label);
		if (fflush(stdout) != 0) {
			fprintf(stderr, "[ERROR] Failed to flush stdout\n");
			return EIO;
		}
	}

	// ��ȫ��ȡ����
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

	// �����з��ͻ���������
	char* newline = strchr(buffer, '\n');
	if (newline != NULL) {
		*newline = '\0';
	}
	else {
		// ���볬����������С�����
		int c;
		while ((c = getchar()) != '\n' && c != EOF) {
			// ��ȫ����ʣ������
		}

		// ȷ���ַ�����ȷ��ֹ
		if (buffer_size > 1) {
			buffer[buffer_size - 1] = '\0';
		}
		else {
			buffer[0] = '\0';  // ����buffer_size=1���������
		}

		fprintf(stderr, "[WARNING] Input truncated (max %zu characters)\n",
			buffer_size - 1);
		return EOVERFLOW;  // �������������
	}

	// �����Լ��4����֤����ַ�����Ч��
	if (buffer[0] == '\0') {
		fprintf(stderr, "[WARNING] Empty input received\n");
		return ENODATA;  // ���������ݴ�����
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

	// ��� padding �����Ƿ�Ϸ�
	if (pad_len == 0 || pad_len > BLOCK_SIZE_SLOTH || pad_len > len) {
		handle_error_sloth("Padding error: invalid padding length");
		return len;
	}

	uint8_t bad = 0;

	// ��֤����Ƿ�һ��
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