.NONPOSIX:

# If possible, use CONFIGFILE=optimised.mk
CONFIGFILE = config.mk


# for Linux
LIBEXT = so
LIBFLAGS = -shared -Wl,-soname,libkeccak.$(LIBEXT).$(LIB_MAJOR)
# for Mac OS
#	LIBEXT = dylib
#	LIBFLAGS = -dynamiclib

include $(CONFIGFILE)


# The version of the library.
LIB_MAJOR = 1
LIB_MINOR = 1
LIB_VERSION = $(LIB_MAJOR).$(LIB_MINOR)



OBJ =\
	libkeccak/digest.o\
	libkeccak/files.o\
	libkeccak/generalised-spec.o\
	libkeccak/hex.o\
	libkeccak/state.o\
	libkeccak/mac/hmac.o

HDR =\
	libkeccak.h\
	libkeccak/digest.h\
	libkeccak/files.h\
	libkeccak/generalised-spec.h\
	libkeccak/hex.h\
	libkeccak/spec.h\
	libkeccak/state.h\
	libkeccak/internal.h\
	libkeccak/mac/hmac.h

MAN3 =\
	libkeccak_behex_lower.3\
	libkeccak_behex_upper.3\
	libkeccak_degeneralise_spec.3\
	libkeccak_digest.3\
	libkeccak_fast_digest.3\
	libkeccak_fast_squeeze.3\
	libkeccak_fast_update.3\
	libkeccak_generalised_spec_initialise.3\
	libkeccak_generalised_sum_fd.3\
	libkeccak_hmac_copy.3\
	libkeccak_hmac_create.3\
	libkeccak_hmac_destroy.3\
	libkeccak_hmac_digest.3\
	libkeccak_hmac_duplicate.3\
	libkeccak_hmac_fast_destroy.3\
	libkeccak_hmac_fast_digest.3\
	libkeccak_hmac_fast_free.3\
	libkeccak_hmac_fast_update.3\
	libkeccak_hmac_free.3\
	libkeccak_hmac_initialise.3\
	libkeccak_hmac_marshal.3\
	libkeccak_hmac_marshal_size.3\
	libkeccak_hmac_reset.3\
	libkeccak_hmac_set_key.3\
	libkeccak_hmac_unmarshal.3\
	libkeccak_hmac_unmarshal_skip.3\
	libkeccak_hmac_update.3\
	libkeccak_hmac_wipe.3\
	libkeccak_keccaksum_fd.3\
	libkeccak_rawshakesum_fd.3\
	libkeccak_sha3sum_fd.3\
	libkeccak_shakesum_fd.3\
	libkeccak_simple_squeeze.3\
	libkeccak_spec_check.3\
	libkeccak_spec_rawshake.3\
	libkeccak_spec_sha3.3\
	libkeccak_spec_shake.3\
	libkeccak_squeeze.3\
	libkeccak_state_copy.3\
	libkeccak_state_create.3\
	libkeccak_state_destroy.3\
	libkeccak_state_duplicate.3\
	libkeccak_state_fast_destroy.3\
	libkeccak_state_fast_free.3\
	libkeccak_state_free.3\
	libkeccak_state_initialise.3\
	libkeccak_state_marshal.3\
	libkeccak_state_marshal_size.3\
	libkeccak_state_reset.3\
	libkeccak_state_unmarshal.3\
	libkeccak_state_unmarshal_skip.3\
	libkeccak_state_wipe.3\
	libkeccak_state_wipe_message.3\
	libkeccak_state_wipe_sponge.3\
	libkeccak_unhex.3\
	libkeccak_update.3

MAN7 =\
	libkeccak.7


all: libkeccak.a libkeccak.$(LIBEXT) test benchmark

$(OBJ): $(HDR)
.c.o:
	$(CC) -fPIC -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

libkeccak.$(LIBEXT): $(OBJ)
	$(CC) $(LIBFLAGS) -o $@ $^ $(LDFLAGS)

libkeccak.a: $(OBJ)
	$(AR) rc $@ $?
	$(AR) -s $@


test: test.o libkeccak.a
	$(CC) $(FLAGS) -o $@ $^ $(LDFLAGS)

test.o: test.c $(HDR)
	$(CC) $(FLAGS) -O3 -c -o $@ test.c $(CFLAGS) $(CPPFLAGS)

benchmark: benchmark.o libkeccak.a
	$(CC) $(FLAGS) -o $@ $^ $(LDFLAGS)

benchmark.o: benchmark.c $(HDR)
	$(CC) $(FLAGS) -O3 -c -o $@ benchmark.c $(CFLAGS) $(CPPFLAGS)


info: libkeccak.info
libkeccak.info: libkeccak.texinfo
	$(MAKEINFO) $(TEXIFLAGS) libkeccak.texinfo

pdf: libkeccak.pdf
libkeccak.pdf: libkeccak.texinfo
	@! test -d obj/pdf || rm -rf obj/pdf
	@mkdir -p obj/pdf
	cd obj/pdf && texi2pdf $(TEXIFLAGS) ../../libkeccak.texinfo < /dev/null
	mv obj/pdf/$@ $@

dvi: libkeccak.dvi
libkeccak.dvi: libkeccak.texinfo
	@! test -d obj/dvi || rm -rf obj/dvi
	@mkdir -p obj/dvi
	cd obj/dvi && $(TEXI2DVI) $(TEXIFLAGS) ../../libkeccak.texinfo < /dev/null
	mv obj/dvi/$@ $@

ps: libkeccak.ps
libkeccak.ps: libkeccak.texinfo
	@! test -d obj/ps || rm -rf obj/ps
	@mkdir -p obj/ps
	cd obj/ps && texi2pdf $(TEXIFLAGS) --ps ../../libkeccak.texinfo < /dev/null
	mv obj/ps/$@ $@


check: test
	@test $$(sha256sum .testfile | cut -d ' ' -f 1) = \
	      e21d814d21ca269246849cc105faec1a71ac7d1cdb1a86023254f49d51b47231 || \
	      ( echo 'The file .testfile is incorrect, test will fail!' ; false )
	valgrind --leak-check=full ./test
	test $$(valgrind ./test 2>&1 >/dev/null | wc -l) = 14
# Using valgrind 3.10.0, its output to standard error should consist of 14 lines,
# the test itself never prints to standard error.

benchfile:
	dd if=/dev/urandom bs=1000 count=50 > $@

run-benchmark: benchmark benchfile
	for i in $$(seq 7) ; do ./benchmark ; done | median

install: libkeccak.$(LIBEXT) libkeccak.a
	mkdir -p -- "$(DESTDIR)$(PREFIX)/lib"
	cp -- libkeccak.$(LIBEXT) "$(DESTDIR)$(PREFIX)/lib/libkeccak.$(LIBEXT).$(LIB_VERSION)"
	ln -sf -- libkeccak.$(LIBEXT).$(LIB_VERSION) "$(DESTDIR)$(PREFIX)/lib/libkeccak.$(LIBEXT).$(LIB_MAJOR)"
	ln -sf -- libkeccak.$(LIBEXT).$(LIB_VERSION) "$(DESTDIR)$(PREFIX)/lib/libkeccak.$(LIBEXT)"
	cp -- libkeccak.a "$(DESTDIR)$(PREFIX)/lib/libkeccak.a"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/include/libkeccak/mac"
	for f in $(HDR); do cp -- "$$f" "$(DESTDIR)$(PREFIX)/include/$$f" || exit 1; done
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man3"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man7"
	cd man && cp -- $(MAN3) "$(DESTDIR)$(MANPREFIX)/man3"
	cd man && cp -- $(MAN7) "$(DESTDIR)$(MANPREFIX)/man7"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/share/licenses/libkeccak"
	cp -- LICENSE "$(DESTDIR)$(PREFIX)/share/licenses/libkeccak/"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libkeccak.$(LIBEXT).$(LIB_VERSION)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libkeccak.$(LIBEXT).$(LIB_MAJOR)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libkeccak.$(LIBEXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libkeccak.a"
	-rm -rf -- "$(DESTDIR)$(PREFIX)/include/libkeccak"
	-cd -- "$(DESTDIR)$(MANPREFIX)/man3" && rm -f -- $(MAN3)
	-cd -- "$(DESTDIR)$(MANPREFIX)/man7" && rm -f -- $(MAN7)
	-rm -rf -- "$(DESTDIR)$(PREFIX)/share/licenses/libkeccak"

clean:
	-rm -f -- *.o libkeccak/*.o libkeccak/mac/*.o
	-rm -f -- *.su libkeccak/*.su libkeccak/mac/*.su
	-rm -f -- *.info *.pdf *.ps *.dvi *.a libkeccak.$(LIBEXT)* test benchmark benchfile

.SUFFIXES: .c.o

.PHONY: all info pdf ps dvi check run-benchmark install uninstall clean
