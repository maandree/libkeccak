PREFIX    = /usr
MANPREFIX = $(PREFIX)/share/man

CC = cc

CFLAGS   = -std=c99 -O3
CPPFLAGS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
LDFLAGS  = -s

# You can add -DALLOCA_LIMIT=# to CPPFLAGS, where # is a size_t
# value, to put a limit on how large allocation the library is
# allowed to make with alloca(3). For buffers that can have any
# size this limit will be used if it wants to allocate a larger
# buffer. Choose 0 to use malloc(3) instead of alloca(3).
