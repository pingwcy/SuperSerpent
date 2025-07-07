#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "params.h"
#include "core/logic_sloth.h"
#include "core/utils_sloth.h"
#include "core/test_sloth.h"
#include "core/bench_sloth.h"
#include "core/makevcvol_sloth.h"
#if defined(_WIN32)
//#define _CRTDBG_MAP_ALLOC
//#include <crtdbg.h>
#else
#ifndef ENC_ONLY_MODE
#include "core/slothfuse.h"
#include "core/slothfuse_vc.h"
#endif
#endif
int VERBOSE_SLOTH = 0;

int main(int argc, char* argv[]) {
	//_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF); // Enable Memory Leak Detection for Windows
	if (test_sloth() != 0){
		handle_error_sloth("SELF TEST ERROR!");
		return -1;
	}
	if (argc < 3) {
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
			printf("1.CBC Encryption    2.CBC Decryption    3.CBC Encrypt File    4.CBC Decrypt File\n5.GCM Encryption    6.GCM Decryption    7.GCM Encrypt File    8.GCM Decrypt File\na.Create VeraCrypt File Container       b.Mount VeraCrypt Vol c.Dismount Volume\n0.Benchmark         y.String Hash       z.File Hash\n");
			fflush(stdout);
			char input[10];  // Selection
			if (get_user_input("Make selection: ", input, sizeof(input)) != 0) {
				continue;
			}
			if (input[0] == '0') {
				bench_pbkdf2_sloth();
				benchmark_serpent_sloth();
			}
			else if (input[0] == '1') {
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
				make_vera_volume_main();
			}
#if !defined(_WIN32) && !defined(ENC_ONLY_MODE)

			else if (input[0] == 'b') {
				mount_volume_entrance();

			}
			else if (input[0] == 'c') {
				char loopname[64];
				get_user_input("Enter Loop Device Name: ", loopname, 64);
				safe_unmount("slothcrypt", loopname);
			}
			else if (input[0] == 'd') {
				vcfuse_main(argc, argv);
			}
			else if (input[0] == 'e') {
				char loopname2[64];
				get_user_input("Enter Loop Device Name: ", loopname2, 64);
				safe_unmount_vcfuse(loopname2);
			}
#endif
			else if (input[0] == 'y') {
				hashstr_sloth();
			}
			else if (input[0] == 'z') {
				hashfile_sloth();
			}
			else {
				break;
			}
		} while (1);
		return 0;
	}
	else {
#if defined(_WIN32) || defined(ENC_ONLY_MODE)
		printf("Fuse Not Supported By Windows Or Turned off for this Linux build.\n");
#else
		main_fuse_sloth(argc, argv);
#endif
	}
}
