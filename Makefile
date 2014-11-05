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

LDOPTIMISE =
# -flto -flto-compression-level -flto-partition={1to1,balanced,mix,none} -flto-report -flto-report-wpa -fwpa

COPTIMISE = -march=native -O0 \
            -fdata-sections -fcrossjumping -fexpensive-optimizations                \
            -ffunction-sections -fkeep-inline-functions -fomit-frame-pointer        \
            -freorder-blocks-and-partition -ftree-ter -falign-functions=0

# -fira-algorithm=priority -fira-algorithm=CB
# -fira-region=all -fira-region=mixed -fira-region=one
# -fmerge-all-constants -fmerge-constants
# -fprofile-generate

# -faggressive-loop-optimizations -fauto-inc-dec -fbranch-target-load-optimize
# -fbranch-target-load-optimize2 -fbtr-bb-exclusive -fcaller-saves -fcheck-data-deps
# -fcombine-stack-adjustments -fconserve-stack -fcompare-elim -fcprop-registers
# -fcse-follow-jumps -fcse-skip-blocks -fcx-fortran-rules -fcx-limited-range -fdce
# -fdelete-null-pointer-checks -fdevirtualize -fdevirtualize-speculatively -fdse
# -fearly-inlining -fipa-sra  -ffat-lto-objects -fbranch-probabilities
# -fassociative-math -fforward-propagate -ffunction-sections -fforward-propagate
# -ffast-math -ffinite-math-only -ffloat-store -fgcse -fgcse-after-reload -fgcse-las
# -fgcse-lm -fgraphite-identity -fgcse-sm -fhoist-adjacent-loads -fif-conversion
# -fif-conversion2 -findirect-inlining -finline-functions -finline-functions-called-once
# -finline-small-functions -fipa-cp -fipa-cp-clone -fipa-pta -fipa-profile
# -fipa-pure-const -fipa-reference -fira-hoist-pressure -fira-loop-pressure
# -fno-ira-share-save-slots -fno-ira-share-spill-slots -fisolate-erroneous-paths-dereference
# -fisolate-erroneous-paths-attribute -fivopts -fkeep-static-consts -flive-range-shrinkage
# -floop-block -floop-interchange -floop-strip-mine -floop-nest-optimize
# -floop-parallelize-all -fmodulo-sched -fmodulo-sched-allow-regmoves -fmove-loop-invariants
# -fno-branch-count-reg -fno-defer-pop -fno-function-cse -fno-guess-branch-probability
# -fno-defer-pop -fno-function-cse -fno-guess-branch-probability -fno-inline -fno-math-errno
# -fno-peephole -fno-peephole2 -fno-sched-interblock -fno-sched-spec -fno-signed-zeros
# -fno-toplevel-reorder -fno-trapping-math -fno-zero-initialized-in-bss
# -foptimize-sibling-calls -fpartial-inlining -fpeel-loops -fpredictive-commoning
# -fprefetch-loop-arrays -fprofile-report -fprofile-use -fprofile-values
# -fprofile-reorder-functions -freciprocal-math -free -frename-registers -freorder-blocks
# -frerun-cse-after-loop -freschedule-modulo-scheduled-loops -frounding-math
# -fsched2-use-superblocks -fsched-pressure -fsched-spec-load -fsched-spec-load-dangerous
# -fsched-group-heuristic -fsched-critical-path-heuristic -fsched-spec-insn-heuristic
# -fsched-rank-heuristic -fsched-last-insn-heuristic -fsched-dep-count-heuristic
# -fselective-scheduling -fselective-scheduling2 -fsel-sched-pipelining
# -fsel-sched-pipelining-outer-loops -fshrink-wrap -fsignaling-nans
# -fsingle-precision-constant -fstrict-overflow -fthread-jumps -ftracer -ftree-bit-ccp
# -ftree-builtin-call-dce -ftree-ccp -ftree-ch -ftree-copyrename -ftree-dce
# -ftree-dominator-opts -ftree-dse -ftree-forwprop -ftree-fre -ftree-loop-if-convert
# -ftree-loop-if-convert-stores -ftree-loop-im -ftree-phiprop -ftree-loop-distribution
# -ftree-loop-distribute-patterns -ftree-loop-ivcanon -ftree-loop-linear
# -ftree-loop-optimize -ftree-loop-vectorize -ftree-pre -ftree-partial-pre -ftree-pta
# -ftree-reassoc -ftree-sink -ftree-slsr -ftree-sra -ftree-vectorize -ftree-vrp
# -funit-at-a-time -funroll-all-loops -funroll-loops -funsafe-loop-optimizations
# -funsafe-math-optimizations -funswitch-loops -fvariable-expansion-in-unroller
# -fvect-cost-model -fvpt -fweb -fprofile-correction -freorder-functions
# -fschedule-insns -fschedule-insns2 -fsplit-ivs-in-unroller -fsplit-wide-types
# -fstrict-aliasing -ftree-coalesce-vars -ftree-copy-prop -ftree-switch-conversion
# -ftree-switch-conversion -ftree-tail-merge -ftree-coalesce-inlined-vars
# -falign-jumps=0 -falign-labels=0 -falign-loops=0 -ftree-parallelize-loops=10
# -fsched-stalled-insns-dep=0 -fsched-stalled-insns=0

FLAGS = -std=gnu99 $(WARN)


LIB_OBJ = digest files generalised-spec hex state
TEST_OBJ = test


.PHONY: all
all: lib test


.PHONY: lib
lib: bin/libkeccak.so.$(LIB_VERSION) bin/libkeccak.so.$(LIB_MAJOR) bin/libkeccak.so

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


.PHONY: test
test: bin/test

bin/test: bin/libkeccak.so $(foreach O,$(TEST_OBJ),obj/test/$(O).o)
	$(CC) $(FLAGS) $(LDFLAGS) -Lbin -lkeccak -o $@ $(foreach O,$(TEST_OBJ),obj/test/$(O).o)

obj/test/%.o: src/test/%.c src/libkeccak/*.h src/libkeccak.h
	@mkdir -p obj/test
	$(CC) $(FLAGS) $(CFLAGS) $(CPPFLAGS) -Isrc -O3 -c -o $@ $<


.PHONY: check
check: bin/test
	@test $$(sha256sum LICENSE | cut -d ' ' -f 1) = \
	      57c8ff33c9c0cfc3ef00e650a1cc910d7ee479a8bc509f6c9209a7c2a11399d6 || \
	      ( echo 'The file LICENSE is incorrect, test will fail!' ; false )
	env LD_LIBRARY_PATH=bin valgrind --leak-check=full bin/test
	test $$(env LD_LIBRARY_PATH=bin valgrind bin/test 2>&1 >/dev/null | wc -l) = 14
# Using valgrind 3.10.0, its output to standard error should consist of 14 lines,
# the test itself never prints to standard error.



.PHONY: clean
clean:
	-rm -r obj bin

