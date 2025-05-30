#ifndef MAKE_VC_H
#define MAKE_VC_H
#ifdef __cplusplus
extern "C" {
#endif

int make_vera_volume_main();

#ifndef _WIN32
int mount_volume_entrance();
#endif

#ifdef __cplusplus
}
#endif

#endif