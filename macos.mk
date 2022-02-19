LIBEXT = dylib
LIBFLAGS = -dynamiclib -Wl,-install_name,"$(PREFIX)/lib/libkeccak.$(LIBMAJOREXT)" \
		   -Wl,-compatibility_version,$(LIB_MAJOR) -Wl,-current_version,$(LIB_VERSION)

LIBMAJOREXT = $(LIB_MAJOR).$(LIBEXT)
LIBMINOREXT = $(LIB_VERSION).$(LIBEXT)
