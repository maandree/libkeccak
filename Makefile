FLAGS = -std=gnu99


OBJ = digest files generalised-spec hex state


.PHONY: all
all: $(foreach O,$(OBJ),obj/libkeccak/$(O).o)

obj/libkeccak/%.o: src/libkeccak/%.c src/libkeccak.h src/libkeccak/*.h
	@mkdir -p obj/libkeccak
	$(CC) $(FLAGS) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

