PREFIX = /usr/local
MANPREFIX = $(PREFIX)/share/man

# These have not been extensively tested but appear to:
#     * Produce false warnings
#     * Slowdown the library's performance
#   -flto -flto-compression-level -flto-partition={1to1,balanced,mix,none} -flto-report -flto-report-wpa -fwpa
CCOPTIMISE = -falign-functions=0 -fkeep-inline-functions -fmerge-all-constants -Ofast
LDOPTIMISE = -s

CFLAGS   = -std=c99 -Wall -Wextra $(CCOPTIMISE)
CPPFLAGS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
LDFLAGS  = $(LDOPTIMISE)
