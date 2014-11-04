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

FLAGS = -std=gnu99 $(WARN)


# TODO optimisation flags to test, and naturally -ON
#          -faggressive-loop-optimizations -falign-functions[=N]
#          -falign-jumps[=N]
#          -falign-labels[=N] -falign-loops[=N]
#          -fassociative-math -fauto-inc-dec -fbranch-probabilities
#          -fbranch-target-load-optimize -fbranch-target-load-optimize2
#          -fbtr-bb-exclusive -fcaller-saves
#          -fcheck-data-deps -fcombine-stack-adjustments -fconserve-stack
#          -fcompare-elim -fcprop-registers -fcrossjumping
#          -fcse-follow-jumps -fcse-skip-blocks -fcx-fortran-rules
#          -fcx-limited-range
#          -fdata-sections -fdce -fdelayed-branch
#          -fdelete-null-pointer-checks -fdevirtualize -fdevirtualize-speculatively -fdse
#          -fearly-inlining -fipa-sra -fexpensive-optimizations -ffat-lto-objects
#          -ffast-math -ffinite-math-only -ffloat-store -fexcess-precision=STYLE
#          -fforward-propagate -ffp-contract=STYLE -ffunction-sections
#          -fgcse -fgcse-after-reload -fgcse-las -fgcse-lm -fgraphite-identity
#          -fgcse-sm -fhoist-adjacent-loads -fif-conversion
#          -fif-conversion2 -findirect-inlining
#          -finline-functions -finline-functions-called-once -finline-limit=N
#          -finline-small-functions -fipa-cp -fipa-cp-clone
#          -fipa-pta -fipa-profile -fipa-pure-const -fipa-reference
#          -fira-algorithm=ALGORITHM
#          -fira-region=REGION -fira-hoist-pressure
#          -fira-loop-pressure -fno-ira-share-save-slots
#          -fno-ira-share-spill-slots -fira-verbose=N
#          -fisolate-erroneous-paths-dereference -fisolate-erroneous-paths-attribute
#          -fivopts -fkeep-inline-functions -fkeep-static-consts -flive-range-shrinkage
#          -floop-block -floop-interchange -floop-strip-mine -floop-nest-optimize
#          -floop-parallelize-all -flto -flto-compression-level
#          -flto-partition=ALG -flto-report -flto-report-wpa -fmerge-all-constants
#          -fmerge-constants -fmodulo-sched -fmodulo-sched-allow-regmoves
#          -fmove-loop-invariants -fno-branch-count-reg
#          -fno-defer-pop -fno-function-cse -fno-guess-branch-probability
#          -fno-inline -fno-math-errno -fno-peephole -fno-peephole2
#          -fno-sched-interblock -fno-sched-spec -fno-signed-zeros
#          -fno-toplevel-reorder -fno-trapping-math -fno-zero-initialized-in-bss
#          -fomit-frame-pointer -foptimize-sibling-calls
#          -fpartial-inlining -fpeel-loops -fpredictive-commoning
#          -fprefetch-loop-arrays -fprofile-report
#          -fprofile-correction -fprofile-dir=PATH -fprofile-generate
#          -fprofile-generate=PATH
#          -fprofile-use -fprofile-use=PATH -fprofile-values -fprofile-reorder-functions
#          -freciprocal-math -free -frename-registers -freorder-blocks
#          -freorder-blocks-and-partition -freorder-functions
#          -frerun-cse-after-loop -freschedule-modulo-scheduled-loops
#          -frounding-math -fsched2-use-superblocks -fsched-pressure
#          -fsched-spec-load -fsched-spec-load-dangerous
#          -fsched-stalled-insns-dep[=N] -fsched-stalled-insns[=N]
#          -fsched-group-heuristic -fsched-critical-path-heuristic
#          -fsched-spec-insn-heuristic -fsched-rank-heuristic
#          -fsched-last-insn-heuristic -fsched-dep-count-heuristic
#          -fschedule-insns -fschedule-insns2 -fsection-anchors
#          -fselective-scheduling -fselective-scheduling2
#          -fsel-sched-pipelining -fsel-sched-pipelining-outer-loops
#          -fshrink-wrap -fsignaling-nans -fsingle-precision-constant
#          -fsplit-ivs-in-unroller -fsplit-wide-types -fstack-protector
#          -fstack-protector-all -fstack-protector-strong -fstrict-aliasing
#          -fstrict-overflow -fthread-jumps -ftracer -ftree-bit-ccp
#          -ftree-builtin-call-dce -ftree-ccp -ftree-ch
#          -ftree-coalesce-inline-vars -ftree-coalesce-vars -ftree-copy-prop
#          -ftree-copyrename -ftree-dce -ftree-dominator-opts -ftree-dse
#          -ftree-forwprop -ftree-fre -ftree-loop-if-convert
#          -ftree-loop-if-convert-stores -ftree-loop-im
#          -ftree-phiprop -ftree-loop-distribution -ftree-loop-distribute-patterns
#          -ftree-loop-ivcanon -ftree-loop-linear -ftree-loop-optimize
#          -ftree-loop-vectorize
#          -ftree-parallelize-loops=N -ftree-pre -ftree-partial-pre -ftree-pta
#          -ftree-reassoc -ftree-sink -ftree-slsr -ftree-sra
#          -ftree-switch-conversion -ftree-tail-merge -ftree-ter
#          -ftree-vectorize -ftree-vrp
#          -funit-at-a-time -funroll-all-loops -funroll-loops
#          -funsafe-loop-optimizations -funsafe-math-optimizations -funswitch-loops
#          -fvariable-expansion-in-unroller -fvect-cost-model -fvpt -fweb
#          -fwhole-program -fwpa -fuse-ld=LINKER -fuse-linker-plugin



LIB_OBJ = digest files generalised-spec hex state
TEST_OBJ = test


.PHONY: all
all: lib test


.PHONY: lib
lib: bin/libkeccak.so.$(LIB_VERSION) bin/libkeccak.so.$(LIB_MAJOR) bin/libkeccak.so

obj/libkeccak/%.o: src/libkeccak/%.c src/libkeccak.h src/libkeccak/*.h
	@mkdir -p obj/libkeccak
	$(CC) $(FLAGS) $(CFLAGS) $(CPPFLAGS) -fPIC -c -o $@ $<

bin/libkeccak.so.$(LIB_VERSION): $(foreach O,$(LIB_OBJ),obj/libkeccak/$(O).o)
	@mkdir -p bin
	$(CC) $(FLAGS) $(LDFLAGS) -shared -Wl,-soname,libkeccak.so.$(LIB_MAJOR) -o $@ $^

bin/libkeccak.so.$(LIB_MAJOR):
	@mkdir -p bin
	ln -sf libkeccak.so.$(LIB_VERSION) $@

bin/libkeccak.so:
	@mkdir -p bin
	ln -sf libkeccak.so.$(LIB_VERSION) $@


.PHONY: test
test: bin/test

bin/test: lib $(foreach O,$(TEST_OBJ),obj/test/$(O).o)
	$(CC) $(FLAGS) $(LDFLAGS) -Lbin -lkeccak -o $@ $(foreach O,$(TEST_OBJ),obj/test/$(O).o)

obj/test/%.o: src/test/%.c src/libkeccak/*.h src/libkeccak.h
	@mkdir -p obj/test
	$(CC) $(FLAGS) $(CFLAGS) $(CPPFLAGS) -Isrc -c -o $@ $<



.PHONY: clean
clean:
	-rm -r obj bin

