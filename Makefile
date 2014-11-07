# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.


# The version of the library.
LIB_MAJOR = 1
LIB_MINOR = 0
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
	$(CC) $(FLAGS) $(CFLAGS) $(COPTIMISE) $(CPPFLAGS) -fPIC -c -o $@ $<

bin/libkeccak.so.$(LIB_VERSION): $(foreach O,$(LIB_OBJ),obj/libkeccak/$(O).o)
	@mkdir -p bin
	$(CC) $(FLAGS) $(LDFLAGS) $(LDOPTIMISE) -shared -Wl,-soname,libkeccak.so.$(LIB_MAJOR) -o $@ $^

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

bin/test: obj/test.o bin/libkeccak.so
	$(CC) $(FLAGS) $(LDFLAGS) -Lbin -lkeccak -o $@ $<

obj/test.o: src/test.c src/libkeccak/*.h src/libkeccak.h
	@mkdir -p obj
	$(CC) $(FLAGS) $(CFLAGS) $(CPPFLAGS) -Isrc -O3 -c -o $@ $<


.PHONY: benchmark
benchmark: bin/benchmark

bin/benchmark: obj/benchmark.o bin/libkeccak.so
	$(CC) $(FLAGS) $(LDFLAGS) -Lbin -lkeccak -o $@ $<

obj/benchmark.o: src/benchmark.c src/libkeccak/*.h src/libkeccak.h
	@mkdir -p obj
	$(CC) $(FLAGS) $(CFLAGS) $(CPPFLAGS) -Isrc -O3 -c -o $@ $<



.PHONY: check
check: bin/test bin/libkeccak.so
	@test $$(sha256sum LICENSE | cut -d ' ' -f 1) = \
	      57c8ff33c9c0cfc3ef00e650a1cc910d7ee479a8bc509f6c9209a7c2a11399d6 || \
	      ( echo 'The file LICENSE is incorrect, test will fail!' ; false )
	env LD_LIBRARY_PATH=bin valgrind --leak-check=full bin/test
	test $$(env LD_LIBRARY_PATH=bin valgrind bin/test 2>&1 >/dev/null | wc -l) = 14
# Using valgrind 3.10.0, its output to standard error should consist of 14 lines,
# the test itself never prints to standard error.


.PHONY: run-benchmark
run-benchmark: bin/benchmark bin/libkeccak.so
	for i in $$(seq 7) ; do env LD_LIBRARY_PATH=bin bin/benchmark ; done | median



.PHONY: clean
clean:
	-rm -r obj bin

