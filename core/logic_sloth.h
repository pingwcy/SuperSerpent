#ifndef  LOGIC_SLOTH_H
#define LOGIC_SLOTH_H
#include <stdint.h>
int enc_sloth(int mode);
int dec_sloth(int mode);
int enc_file_sloth(int mode);
int dec_file_sloth(int mode);
int hashstr_sloth();
int hashfile_sloth();
#endif // ! LOGIC_SLOTH_H