#ifndef MAKE_VC_H
#define MAKE_VC_H
#ifdef __cplusplus
extern "C" {
#endif

int make_vera_volume_main();

#ifndef _WIN32
int mount_volume_entrance();
void safe_unmount(const char *mapper_name, const char *loopdev);
uint64_t parse_volume_header(uint8_t *in_buf, uint8_t *OutMasterKey);
int return_volume_header(const char* filename, uint8_t *outbuffer);
int get_key_volume(const char* filename, uint8_t *outHeaderkey);
char *find_unused_loopdev();
void run_losetup(const char *loopdev, const char *imagefile);
#endif

#ifdef __cplusplus
}
#endif

#endif