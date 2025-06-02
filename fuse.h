/*
   This header is for compatibility with older software using FUSE.

   Please use 'pkg-config --cflags fuse' to set include path.  The
   correct usage is still '#include <fuse.h>', not '#include
   <fuse/fuse.h>'.
*/
#include "params.h"
#ifdef USING_LIBFUSE_V3
#include "fuse/fuse37/fuse.h"
#else
#include "fuse/fuse29/fuse.h"
#endif
