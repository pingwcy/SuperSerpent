#ifndef SLOTH_FUSE_HEADER
#define SLOTH_FUSE_HEADER
#ifdef __cplusplus
extern "C" {
#endif

int vcfuse_main(int argc, char* argv[]);
void safe_unmount_vcfuse(const char *loopdev);

#ifdef __cplusplus
}
#endif

#endif
