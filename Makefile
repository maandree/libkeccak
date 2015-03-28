# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.


# The package path prefix, if you want to install to another root, set DESTDIR to that root.
PREFIX = /usr
# The library path excluding prefix.
LIB = /lib
# The library header path excluding prefix.
INCLUDE = /include
# The resource path excluding prefix.
DATA = /share
# The library path including prefix.
LIBDIR = $(PREFIX)$(LIB)
# The library header including prefix.
INCLUDEDIR = $(PREFIX)$(INCLUDE)
# The resource path including prefix.
DATADIR = $(PREFIX)$(DATA)
# The generic documentation path including prefix.
DOCDIR = $(DATADIR)/doc
# The info manual documentation path including prefix.
INFODIR = $(DATADIR)/info
# The license base path including prefix.
LICENSEDIR = $(DATADIR)/licenses

# The name of the package as it should be installed.
PKGNAME = libkeccak



# The version of the library.
LIB_MAJOR = 0
LIB_MINOR = 1
LIB_VERSION = $(LIB_MAJOR).$(LIB_MINOR)



WARN = -Wall -Wextra -pedantic -Wdouble-promotion -Wformat=2 -Winit-self -Wmissing-include-dirs  \
       -Wtrampolines -Wfloat-equal -Wshadow -Wmissing-prototypes -Wmissing-declarations          \
       -Wredundant-decls -Wnested-externs -Winline -Wno-variadic-macros -Wswitch-default         \
       -Wpadded -Wsync-nand -Wunsafe-loop-optimizations -Wcast-align -Wstrict-overflow           \
       -Wdeclaration-after-statement -Wundef -Wbad-function-cast -Wcast-qual -Wwrite-strings     \
       -Wlogical-op -Waggregate-return -Wstrict-prototypes -Wold-style-definition -Wpacked       \
       -Wvector-operation-performance -Wunsuffixed-float-constants -Wsuggest-attribute=const     \
       -Wsuggest-attribute=noreturn -Wsuggest-attribute=pure -Wsuggest-attribute=format          \
       -Wnormalized=nfkc

# These have not been extensively tested but appear to:
#     * Produce produce false warnings
#     * Slowdown the library's performance
#   -flto -flto-compression-level -flto-partition={1to1,balanced,mix,none} -flto-report -flto-report-wpa -fwpa
COPTIMISE = -falign-functions=0 -fkeep-inline-functions -fmerge-all-constants -Ofast
LDOPTIMISE =

FLAGS = -std=gnu99 $(WARN)


LIB_OBJ = digest files generalised-spec hex state


.PHONY: default
default: lib test

.PHONY: all
all: lib test benchmark


.PHONY: lib
lib: so a


.PHONY: so
so: bin/libkeccak.so.$(LIB_VERSION) bin/libkeccak.so.$(LIB_MAJOR) bin/libkeccak.so

obj/libkeccak/%.o: src/libkeccak/%.c src/libkeccak.h src/libkeccak/*.h
	@mkdir -p obj/libkeccak
	$(CC) $(FLAGS) $(COPTIMISE) -fPIC -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

bin/libkeccak.so.$(LIB_VERSION): $(foreach O,$(LIB_OBJ),obj/libkeccak/$(O).o)
	@mkdir -p bin
	$(CC) $(FLAGS) $(LDOPTIMISE) -shared -Wl,-soname,libkeccak.so.$(LIB_MAJOR) -o $@ $^ $(LDFLAGS)

bin/libkeccak.so.$(LIB_MAJOR):
	@mkdir -p bin
	ln -sf libkeccak.so.$(LIB_VERSION) $@

bin/libkeccak.so:
	@mkdir -p bin
	ln -sf libkeccak.so.$(LIB_VERSION) $@


.PHONY: a
a: bin/libkeccak.a

bin/libkeccak.a: $(foreach O,$(LIB_OBJ),obj/libkeccak/$(O).o)
	@mkdir -p bin
	ar rcs $@ $^


.PHONY: test
test: bin/test

bin/test: obj/test.o bin/libkeccak.so bin/libkeccak.so.$(LIB_MAJOR) bin/libkeccak.so.$(LIB_VERSION)
	$(CC) $(FLAGS) -o $@ $< -Lbin -lkeccak $(LDFLAGS)

obj/test.o: src/test.c src/libkeccak/*.h src/libkeccak.h
	@mkdir -p obj
	$(CC) $(FLAGS) -Isrc -O3 -c -o $@ $< $(CFLAGS) $(CPPFLAGS)


.PHONY: benchmark
benchmark: bin/benchmark

bin/benchmark: obj/benchmark.o bin/libkeccak.so bin/libkeccak.so.$(LIB_MAJOR) bin/libkeccak.so.$(LIB_VERSION)
	$(CC) $(FLAGS) -o $@ $< -Lbin -lkeccak $(LDFLAGS)

obj/benchmark.o: src/benchmark.c src/libkeccak/*.h src/libkeccak.h
	@mkdir -p obj
	$(CC) $(FLAGS) -Isrc -O3 -c -o $@ $< $(CFLAGS) $(CPPFLAGS)



.PHONY: check
check: bin/test bin/libkeccak.so bin/libkeccak.so.$(LIB_MAJOR) bin/libkeccak.so.$(LIB_VERSION)
	@test $$(sha256sum LICENSE | cut -d ' ' -f 1) = \
	      57c8ff33c9c0cfc3ef00e650a1cc910d7ee479a8bc509f6c9209a7c2a11399d6 || \
	      ( echo 'The file LICENSE is incorrect, test will fail!' ; false )
	env LD_LIBRARY_PATH=bin valgrind --leak-check=full bin/test
	test $$(env LD_LIBRARY_PATH=bin valgrind bin/test 2>&1 >/dev/null | wc -l) = 14
# Using valgrind 3.10.0, its output to standard error should consist of 14 lines,
# the test itself never prints to standard error.


.PHONY: run-benchmark
run-benchmark: bin/benchmark bin/libkeccak.so bin/libkeccak.so.$(LIB_MAJOR) bin/libkeccak.so.$(LIB_VERSION)
	for i in $$(seq 7) ; do env LD_LIBRARY_PATH=bin bin/benchmark ; done | median



.PHONY: install
install: install-base

.PHONY: install-all
install-all: install-base

.PHONY: install-base
install-base: install-lib install-copyright

.PHONY: install-lib
install-lib: install-headers install-dynamic-lib install-static-lib

.PHONY: install-headers
install-headers:
	install -dm755 -- "$(DESTDIR)$(INCLUDEDIR)"
	install -dm755 -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak"
	install -m644 -- src/libkeccak.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak.h"
	install -m644 -- src/libkeccak/digest.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak/digest.h"
	install -m644 -- src/libkeccak/files.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak/files.h"
	install -m644 -- src/libkeccak/generalised-spec.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak/generalised-spec.h"
	install -m644 -- src/libkeccak/hex.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak/hex.h"
	install -m644 -- src/libkeccak/spec.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak/spec.h"
	install -m644 -- src/libkeccak/state.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak/state.h"

.PHONY: install-dynamic-lib
install-dynamic-lib: bin/libkeccak.so.$(LIB_VERSION)
	install -dm755 -- "$(DESTDIR)$(LIBDIR)"
	install -m755 bin/libkeccak.so.$(LIB_VERSION) -- "$(DESTDIR)$(LIBDIR)/libkeccak.so.$(LIB_VERSION)"
	ln -sf libkeccak.so.$(LIB_VERSION) -- "$(DESTDIR)$(LIBDIR)/libkeccak.so.$(LIB_MAJOR)"
	ln -sf libkeccak.so.$(LIB_VERSION) -- "$(DESTDIR)$(LIBDIR)/libkeccak.so"

.PHONY: install-static-lib
install-static-lib: bin/libkeccak.a
	install -dm755 -- "$(DESTDIR)$(LIBDIR)"
	install -m644 bin/libkeccak.a -- "$(DESTDIR)$(LIBDIR)/libkeccak.a"

.PHONY: install-copyright
install-copyright: install-copying install-license

.PHONY: install-copying
install-copying:
	install -dm755 -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)"
	install -m644 COPYING -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/COPYING"

.PHONY: install-license
install-license:
	install -dm755 -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)"
	install -m644 LICENSE -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/LICENSE"



.PHONY: uninstall
uninstall:
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak.h"
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/digest.h"
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/files.h"
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/generalised-spec.h"
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/hex.h"
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/spec.h"
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/state.h"
	-rmdir -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak"
	-rm -- "$(DESTDIR)$(LIBDIR)/libkeccak.so.$(LIB_VERSION)"
	-rm -- "$(DESTDIR)$(LIBDIR)/libkeccak.so.$(LIB_MAJOR)"
	-rm -- "$(DESTDIR)$(LIBDIR)/libkeccak.so"
	-rm -- "$(DESTDIR)$(LIBDIR)/libkeccak.a"
	-rm -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/COPYING"
	-rm -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/LICENSE"
	-rmdir -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)"



.PHONY: clean
clean:
	-rm -r obj bin

