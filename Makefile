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


OBJ = digest files generalised-spec hex state


.PHONY: all
all: $(foreach O,$(OBJ),obj/libkeccak/$(O).o)

obj/libkeccak/%.o: src/libkeccak/%.c src/libkeccak.h src/libkeccak/*.h
	@mkdir -p obj/libkeccak
	$(CC) $(FLAGS) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<


.PHONY: clean
clean:
	-rm -r obj bin

