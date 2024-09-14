.POSIX:

# If possible, use CONFIGFILE=optimised.mk
CONFIGFILE = config.mk

# Change to macos.mk for Mac OS
OSCONFIGFILE = linux.mk

include $(CONFIGFILE)
include $(OSCONFIGFILE)


# The version of the library.
LIB_MAJOR = 1
LIB_MINOR = 4
LIB_VERSION = $(LIB_MAJOR).$(LIB_MINOR)



OBJ =\
	digest.o\
	libkeccak_behex_lower.o\
	libkeccak_behex_upper.o\
	libkeccak_cshake_initialise.o\
	libkeccak_cshake_suffix.o\
	libkeccak_degeneralise_spec.o\
	libkeccak_generalised_spec_initialise.o\
	libkeccak_generalised_sum_fd.o\
	libkeccak_hmac_copy.o\
	libkeccak_hmac_create.o\
	libkeccak_hmac_destroy.o\
	libkeccak_hmac_digest.o\
	libkeccak_hmac_duplicate.o\
	libkeccak_hmac_fast_destroy.o\
	libkeccak_hmac_fast_digest.o\
	libkeccak_hmac_fast_free.o\
	libkeccak_hmac_fast_update.o\
	libkeccak_hmac_free.o\
	libkeccak_hmac_initialise.o\
	libkeccak_hmac_marshal.o\
	libkeccak_hmac_reset.o\
	libkeccak_hmac_set_key.o\
	libkeccak_hmac_unmarshal.o\
	libkeccak_hmac_update.o\
	libkeccak_hmac_wipe.o\
	libkeccak_keccaksum_fd.o\
	libkeccak_rawshakesum_fd.o\
	libkeccak_sha3sum_fd.o\
	libkeccak_shakesum_fd.o\
	libkeccak_spec_check.o\
	libkeccak_spec_rawshake.o\
	libkeccak_spec_sha3.o\
	libkeccak_state_copy.o\
	libkeccak_state_create.o\
	libkeccak_state_destroy.o\
	libkeccak_state_duplicate.o\
	libkeccak_state_fast_destroy.o\
	libkeccak_state_fast_free.o\
	libkeccak_state_free.o\
	libkeccak_state_initialise.o\
	libkeccak_state_marshal.o\
	libkeccak_state_reset.o\
	libkeccak_state_unmarshal.o\
	libkeccak_state_wipe.o\
	libkeccak_state_wipe_message.o\
	libkeccak_state_wipe_sponge.o\
	libkeccak_unhex.o\
	libkeccak_zerocopy_chunksize.o

HDR =\
	libkeccak.h\
	common.h\
	$(SUBHDR)

SUBHDR =\
	libkeccak/keccak.h\
	libkeccak/sha3.h\
	libkeccak/rawshake.h\
	libkeccak/shake.h\
	libkeccak/cshake.h\
	libkeccak/hmac.h\
	libkeccak/legacy.h\
	libkeccak/util.h

MAN3 =\
	libkeccak_behex_lower.3\
	libkeccak_behex_upper.3\
	libkeccak_cshake_initialise.3\
	libkeccak_cshake_suffix.3\
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
	libkeccak_hmac_reset.3\
	libkeccak_hmac_set_key.3\
	libkeccak_hmac_unmarshal.3\
	libkeccak_hmac_update.3\
	libkeccak_hmac_wipe.3\
	libkeccak_keccaksum_fd.3\
	libkeccak_rawshakesum_fd.3\
	libkeccak_sha3sum_fd.3\
	libkeccak_shakesum_fd.3\
	libkeccak_simple_squeeze.3\
	libkeccak_spec_check.3\
	libkeccak_spec_cshake.3\
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
	libkeccak_state_reset.3\
	libkeccak_state_unmarshal.3\
	libkeccak_state_wipe.3\
	libkeccak_state_wipe_message.3\
	libkeccak_state_wipe_sponge.3\
	libkeccak_unhex.3\
	libkeccak_update.3\
	libkeccak_zerocopy_chunksize.3\
	libkeccak_zerocopy_digest.3\
	libkeccak_zerocopy_update.3

MAN7 =\
	libkeccak.7


all: libkeccak.a libkeccak.$(LIBEXT) test benchmark

$(OBJ): $(HDR)
.c.o:
	$(CC) -fPIC -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

libkeccak.$(LIBEXT): $(OBJ)
	$(CC) $(LIBFLAGS) -o $@ $(OBJ) $(LDFLAGS)

libkeccak.a: $(OBJ)
	-rm -f -- $@
	$(AR) rc $@ $(OBJ)
	$(AR) -s $@


test: test.o libkeccak.a
	$(CC) $(FLAGS) -o $@ test.o libkeccak.a $(LDFLAGS)

test.o: test.c $(HDR)
	$(CC) $(FLAGS) -O3 -c -o $@ test.c $(CFLAGS) $(CPPFLAGS)

benchmark: benchmark.o libkeccak.a
	$(CC) $(FLAGS) -o $@ benchmark.o libkeccak.a $(LDFLAGS)

benchmark.o: benchmark.c $(HDR)
	$(CC) $(FLAGS) -O3 -c -o $@ benchmark.c $(CFLAGS) $(CPPFLAGS)


check: test
	@test $$(sha256sum .testfile | cut -d ' ' -f 1) = \
	      e21d814d21ca269246849cc105faec1a71ac7d1cdb1a86023254f49d51b47231 || \
	      ( echo 'The file .testfile is incorrect, test will fail!' ; false )
	$(CHECK_PREFIX) ./test

benchfile:
	dd if=/dev/urandom bs=1000 count=50 > $@

run-benchmark: benchmark benchfile
	for i in $$(seq 7) ; do ./benchmark ; done | median

install: libkeccak.$(LIBEXT) libkeccak.a
	mkdir -p -- "$(DESTDIR)$(PREFIX)/lib"
	cp -- libkeccak.$(LIBEXT) "$(DESTDIR)$(PREFIX)/lib/libkeccak.$(LIBMINOREXT)"
	$(FIX_INSTALL_NAME) "$(DESTDIR)$(PREFIX)/lib/libkeccak.$(LIBMINOREXT)"
	ln -sf -- libkeccak.$(LIBMINOREXT) "$(DESTDIR)$(PREFIX)/lib/libkeccak.$(LIBMAJOREXT)"
	ln -sf -- libkeccak.$(LIBMINOREXT) "$(DESTDIR)$(PREFIX)/lib/libkeccak.$(LIBEXT)"
	cp -- libkeccak.a "$(DESTDIR)$(PREFIX)/lib/libkeccak.a"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/include/libkeccak"
	cp -- libkeccak.h "$(DESTDIR)$(PREFIX)/include/"
	cp -- $(SUBHDR) "$(DESTDIR)$(PREFIX)/include/libkeccak/"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man3"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man7"
	cp -- $(MAN3) "$(DESTDIR)$(MANPREFIX)/man3"
	cp -- $(MAN7) "$(DESTDIR)$(MANPREFIX)/man7"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/share/licenses/libkeccak"
	cp -- LICENSE "$(DESTDIR)$(PREFIX)/share/licenses/libkeccak/"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libkeccak.$(LIBMINOREXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libkeccak.$(LIBMAJOREXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libkeccak.$(LIBEXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libkeccak.a"
	-cd -- "$(DESTDIR)$(PREFIX)/include/" && rm -f $(SUBHDIR)
	-cd -- "$(DESTDIR)$(MANPREFIX)/man3" && rm -f -- $(MAN3)
	-cd -- "$(DESTDIR)$(MANPREFIX)/man7" && rm -f -- $(MAN7)
	-rm -rf -- "$(DESTDIR)$(PREFIX)/share/licenses/libkeccak"

clean:
	-rm -f -- *.o *.su  test benchmark benchfile
	-rm -f -- *.a libkeccak.$(LIBEXT) libkeccak.$(LIBEXT).* libkeccak.*.$(LIBEXT)

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all check run-benchmark install uninstall clean
