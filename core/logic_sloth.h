#ifndef  LOGIC_SLOTH_H
#define LOGIC_SLOTH_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int enc_sloth(int mode);
int dec_sloth(int mode);
int enc_file_sloth(int mode);
int dec_file_sloth(int mode);
int hashstr_sloth();
int hashfile_sloth();

#ifdef __cplusplus
}
#endif

#endif // ! LOGIC_SLOTH_H