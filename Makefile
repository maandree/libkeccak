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
# The man pages path including prefix.
MANDIR = $(DATADIR)/man
# The section 3 man pages path including prefix.
MAN3DIR = $(MANDIR)/man3
# The section 7 man pages path including prefix.
MAN7DIR = $(MANDIR)/man7
# The license base path including prefix.
LICENSEDIR = $(DATADIR)/licenses

# The name of the package as it should be installed.
PKGNAME = libkeccak



# The version of the library.
LIB_MAJOR = 1
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


LIB_OBJ = digest files generalised-spec hex state mac/hmac

MAN3 =\
	libkeccak_behex_lower\
	libkeccak_behex_upper\
	libkeccak_degeneralise_spec\
	libkeccak_digest\
	libkeccak_fast_digest\
	libkeccak_fast_squeeze\
	libkeccak_fast_update\
	libkeccak_generalised_spec_initialise\
	libkeccak_generalised_sum_fd\
	libkeccak_hmac_copy\
	libkeccak_hmac_create\
	libkeccak_hmac_destroy\
	libkeccak_hmac_digest\
	libkeccak_hmac_duplicate\
	libkeccak_hmac_fast_destroy\
	libkeccak_hmac_fast_digest\
	libkeccak_hmac_fast_free\
	libkeccak_hmac_fast_update\
	libkeccak_hmac_free\
	libkeccak_hmac_initialise\
	libkeccak_hmac_marshal\
	libkeccak_hmac_marshal_size\
	libkeccak_hmac_reset\
	libkeccak_hmac_set_key\
	libkeccak_hmac_unmarshal\
	libkeccak_hmac_unmarshal_skip\
	libkeccak_hmac_update\
	libkeccak_hmac_wipe\
	libkeccak_keccaksum_fd\
	libkeccak_rawshakesum_fd\
	libkeccak_sha3sum_fd\
	libkeccak_shakesum_fd\
	libkeccak_simple_squeeze\
	libkeccak_spec_check\
	libkeccak_spec_rawshake\
	libkeccak_spec_sha3\
	libkeccak_spec_shake\
	libkeccak_squeeze\
	libkeccak_state_copy\
	libkeccak_state_create\
	libkeccak_state_destroy\
	libkeccak_state_duplicate\
	libkeccak_state_fast_destroy\
	libkeccak_state_fast_free\
	libkeccak_state_free\
	libkeccak_state_initialise\
	libkeccak_state_marshal\
	libkeccak_state_marshal_size\
	libkeccak_state_reset\
	libkeccak_state_unmarshal\
	libkeccak_state_unmarshal_skip\
	libkeccak_state_wipe\
	libkeccak_state_wipe_message\
	libkeccak_state_wipe_sponge\
	libkeccak_unhex\
	libkeccak_update


.PHONY: default
default: lib test info

.PHONY: all
all: lib test benchmark doc


.PHONY: lib
lib: so a


.PHONY: so
so: bin/libkeccak.so.$(LIB_VERSION) bin/libkeccak.so.$(LIB_MAJOR) bin/libkeccak.so

obj/libkeccak/%.o: src/libkeccak/%.c src/libkeccak.h src/libkeccak/*.h src/libkeccak/*/*.h
	@mkdir -p $$(dirname $@)
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


.PHONY: doc
doc: info pdf ps dvi

.PHONY: info
info: bin/libkeccak.info

.PHONY: pdf
pdf: bin/libkeccak.pdf

.PHONY: ps
ps: bin/libkeccak.ps

.PHONY: dvi
dvi: bin/libkeccak.dvi


bin/%.info: doc/info/%.texinfo doc/info/*.texinfo
	@mkdir -p bin
	$(MAKEINFO) $(TEXIFLAGS) $<
	mv $*.info bin

bin/%.pdf: doc/info/%.texinfo doc/info/*.texinfo
	@! test -d obj/pdf || rm -rf obj/pdf
	@mkdir -p obj/pdf bin
	cd obj/pdf && texi2pdf $(TEXIFLAGS) ../../$< < /dev/null
	mv obj/pdf/$*.pdf $@

bin/%.dvi: doc/info/%.texinfo doc/info/*.texinfo
	@! test -d obj/dvi || rm -rf obj/dvi
	@mkdir -p obj/dvi bin
	cd obj/dvi && $(TEXI2DVI) $(TEXIFLAGS) ../../$< < /dev/null
	mv obj/dvi/$*.dvi $@

bin/%.ps: doc/info/%.texinfo doc/info/*.texinfo
	@! test -d obj/ps || rm -rf obj/ps
	@mkdir -p obj/ps bin
	cd obj/ps && texi2pdf $(TEXIFLAGS) --ps ../../$< < /dev/null
	mv obj/ps/$*.ps $@



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
install: install-base install-info install-man

.PHONY: install-all
install-all: install-base install-doc

.PHONY: install-base
install-base: install-lib install-copyright

.PHONY: install-lib
install-lib: install-headers install-dynamic-lib install-static-lib

.PHONY: install-headers
install-headers:
	install -dm755 -- "$(DESTDIR)$(INCLUDEDIR)"
	install -dm755 -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak"
	install -dm755 -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/mac"
	install -m644 -- src/libkeccak.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak.h"
	install -m644 -- src/libkeccak/digest.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak/digest.h"
	install -m644 -- src/libkeccak/files.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak/files.h"
	install -m644 -- src/libkeccak/generalised-spec.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak/generalised-spec.h"
	install -m644 -- src/libkeccak/hex.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak/hex.h"
	install -m644 -- src/libkeccak/spec.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak/spec.h"
	install -m644 -- src/libkeccak/state.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak/state.h"
	install -m644 -- src/libkeccak/internal.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak/internal.h"
	install -m644 -- src/libkeccak/mac/hmac.h "$(DESTDIR)$(INCLUDEDIR)/libkeccak/mac/hmac.h"

.PHONY: install-dynamic-lib
install-dynamic-lib: bin/libkeccak.so.$(LIB_VERSION)
	install -dm755 -- "$(DESTDIR)$(LIBDIR)"
	install -m755 -- bin/libkeccak.so.$(LIB_VERSION) "$(DESTDIR)$(LIBDIR)/libkeccak.so.$(LIB_VERSION)"
	ln -sf -- libkeccak.so.$(LIB_VERSION) "$(DESTDIR)$(LIBDIR)/libkeccak.so.$(LIB_MAJOR)"
	ln -sf -- libkeccak.so.$(LIB_VERSION) "$(DESTDIR)$(LIBDIR)/libkeccak.so"

.PHONY: install-static-lib
install-static-lib: bin/libkeccak.a
	install -dm755 -- "$(DESTDIR)$(LIBDIR)"
	install -m644 -- bin/libkeccak.a "$(DESTDIR)$(LIBDIR)/libkeccak.a"

.PHONY: install-copyright
install-copyright: install-copying install-license

.PHONY: install-copying
install-copying:
	install -dm755 -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)"
	install -m644 -- COPYING "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/COPYING"

.PHONY: install-license
install-license:
	install -dm755 -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)"
	install -m644 -- LICENSE "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/LICENSE"

.PHONY: install-doc
install-doc: install-info install-pdf install-ps install-dvi install-man

.PHONY: install-info
install-info: bin/libkeccak.info
	install -dm755 -- "$(DESTDIR)$(INFODIR)"
	install -m644 -- $< "$(DESTDIR)$(INFODIR)/libkeccak.info"

.PHONY: install-pdf
install-pdf: bin/libkeccak.pdf
	install -dm755 -- "$(DESTDIR)$(DOCDIR)"
	install -m644 -- $< "$(DESTDIR)$(DOCDIR)/libkeccak.pdf"

.PHONY: install-ps
install-ps: bin/libkeccak.ps
	install -dm755 -- "$(DESTDIR)$(DOCDIR)"
	install -m644 -- $< "$(DESTDIR)$(DOCDIR)/libkeccak.ps"

.PHONY: install-dvi
install-dvi: bin/libkeccak.dvi
	install -dm755 -- "$(DESTDIR)$(DOCDIR)"
	install -m644 -- $< "$(DESTDIR)$(DOCDIR)/libkeccak.dvi"

.PHONY: install-man
install-man:
	install -dm755 -- "$(DESTDIR)$(MAN7DIR)"
	install -m644 -- doc/man/libkeccak.7 "$(DESTDIR)$(MAN7DIR)/libkeccak.7"
	install -dm755 -- "$(DESTDIR)$(MAN3DIR)"
	install -m644 -- $(foreach P,$(MAN3),doc/man/$(P).3) "$(DESTDIR)$(MAN3DIR)"

.PHONY: uninstall
uninstall:
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak.h"
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/digest.h"
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/files.h"
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/generalised-spec.h"
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/hex.h"
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/spec.h"
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/state.h"
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/internal.h"
	-rm -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/mac/hmac.h"
	-rmdir -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak/mac"
	-rmdir -- "$(DESTDIR)$(INCLUDEDIR)/libkeccak"
	-rm -- "$(DESTDIR)$(LIBDIR)/libkeccak.so.$(LIB_VERSION)"
	-rm -- "$(DESTDIR)$(LIBDIR)/libkeccak.so.$(LIB_MAJOR)"
	-rm -- "$(DESTDIR)$(LIBDIR)/libkeccak.so"
	-rm -- "$(DESTDIR)$(LIBDIR)/libkeccak.a"
	-rm -- "$(DESTDIR)$(INFODIR)/libkeccak.info"
	-rm -- "$(DESTDIR)$(DOCDIR)/libkeccak.pdf"
	-rm -- "$(DESTDIR)$(DOCDIR)/libkeccak.ps"
	-rm -- "$(DESTDIR)$(DOCDIR)/libkeccak.dvi"
	-rm -- "$(DESTDIR)$(MAN7DIR)/libkeccak.7"
	-rm -- $(foreach P,$(MAN3),"$(DESTDIR)$(MAN3DIR)/$(P).3")
	-rm -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/COPYING"
	-rm -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)/LICENSE"
	-rmdir -- "$(DESTDIR)$(LICENSEDIR)/$(PKGNAME)"



.PHONY: clean
clean:
	-rm -r obj bin

