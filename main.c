#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "params.h"
#include "core/logic_sloth.h"
#include "core/utils_sloth.h"
//#define _CRTDBG_MAP_ALLOC
//#include <crtdbg.h>
int VERBOSE_SLOTH = 0;

int main(int argc, char* argv[]) {
	//_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF); // 启用内存泄漏检测
	for (int i = 1; i < argc; i++) {
		char lowerArg[256];
		strtolower(argv[i], lowerArg);

		if (strcmp(lowerArg, "-verbose") == 0) {
			VERBOSE_SLOTH = 1;
			printf("Verbose mode enabled\n");
		}
	}

	do {
		printf("SuperSerpent, PBKDF2 with Whirlpool, Iter %d, salt %d, iv %d, nonce %d, tag %d\n", ITERATIONS_SLOTH, SALT_SIZE_SLOTH, IV_SIZE_SLOTH, NONCE_SIZE_SLOTH, TAG_SIZE_SLOTH);
		fflush(stdout);
		printf("Select function: \n1.CBC Encryption    2.CBC Decryption    3.CBC Encrypt File    4.CBC Decrypt File\n5.GCM Encryption    6.GCM Decryption    7.GCM Encrypt File    8.GCM Decrypt File\n");
		fflush(stdout);
		char input[10];  // 用于存储用户输入
		if (get_user_input("Make selection: ", input, sizeof(input)) != 0) {
			continue;
		}
		if (input[0] == '1') {
			if (enc_sloth(0) == 0) {
				printf("Success encrypted\n");
			}
		}
		else if (input[0] == '2') {
			if (dec_sloth(0) == 0) {
				printf("Success decrypted\n");
			}
		}
		else if (input[0] == '3') {
			if (enc_file_sloth(0) == 0) {
				printf("Success encrypted\n");
			}
		}
		else if (input[0] == '4') {
			if (dec_file_sloth(0) == 0) {
				printf("Success decrypted\n");
			}
		}
		else if (input[0] == '5') {
			if (enc_sloth(1) == 0) {
				printf("Success encrypted\n");
			}
		}
		else if (input[0] == '6') {
			if (dec_sloth(1) == 0) {
				printf("Success decrypted\n");
			}
		}
		else if (input[0] == '7') {
			if (enc_file_sloth(1) == 0) {
				printf("Success encrypted\n");
			}
		}
		else if (input[0] == '8') {
			if (dec_file_sloth(1) == 0) {
				printf("Success decrypted\n");
			}
		}
		else if (input[0] == 'a') {
			hashstr_sloth();
		}
		else if (input[0] == 'b') {
			hashfile_sloth();
		}
		else {
			break;
		}
	} while (1);
	return 0;
}
