LIBEXT = dylib
LIBFLAGS = -dynamiclib -Wl,-compatibility_version,$(LIB_MAJOR) -Wl,-current_version,$(LIB_VERSION)

LIBMAJOREXT = $(LIB_MAJOR).$(LIBEXT)
LIBMINOREXT = $(LIB_VERSION).$(LIBEXT)
