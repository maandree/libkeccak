/* See LICENSE file for copyright and license details. */
#include "libkeccak.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


#ifndef MESSAGE_FILE
# define MESSAGE_FILE      "benchfile"
#endif
#ifndef MESSAGE_LEN
# define MESSAGE_LEN       50000
#endif


#ifndef BITRATE
# define BITRATE           1024
#endif
#ifndef CAPACITY
# define CAPACITY          576
#endif
#ifndef OUTPUT
# define OUTPUT            512
#endif

#ifndef UPDATE_RUNS
# define UPDATE_RUNS       100
#endif
#ifndef FAST_SQUEEZE_RUNS
# define FAST_SQUEEZE_RUNS 100
#endif
#ifndef SLOW_SQUEEZE_RUNS
# define SLOW_SQUEEZE_RUNS 100
#endif
#ifndef RERUNS
# define RERUNS            50
#endif



/**
 * Benchmark, will print the number of nanoseconds
 * spent with hashing algorithms and representation
 * conversion from binary to hexadecimal. The latter
 * can be compiled out by compiling with -DIGNORE_BEHEXING.
 * 
 * @return  Zero on success, 1 on error
 */
int
main(void)
{
	char message[MESSAGE_LEN];
	struct libkeccak_spec spec;
	struct libkeccak_state state;
	char hashsum[OUTPUT / 8];
#ifndef IGNORE_BEHEXING
	char hexsum[OUTPUT / 8 * 2 + 1];
#endif
	struct timespec start, end;
	long int i, r;
	int fd;
	ssize_t got;
	size_t ptr;

	/* Fill message with content from the file. */
	fd = open(MESSAGE_FILE, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	for (ptr = 0; ptr < MESSAGE_LEN; ptr += (size_t)got) {
		got = read(fd, message, MESSAGE_LEN - ptr);
		if (got <= 0) {
			perror("read");
			close(fd);
			return 1;
		}
	}
	close(fd);

	/* Initialise state. */
	spec.bitrate = BITRATE;
	spec.capacity = CAPACITY;
	spec.output = OUTPUT;
	if (libkeccak_state_initialise(&state, &spec)) {
		perror("libkeccak_state_initialise");
		return 1;
	}

	/* Get start-time. */
	if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start) < 0) {
		perror("clock_gettime");
		return 1;
	}

	/* Run benchmarking loop. */
	for (r = 0; r < RERUNS; r++) {
		/* Updates. */
#if UPDATE_RUNS > 0
		for (i = 0; i < UPDATE_RUNS; i++) {
			if (libkeccak_fast_update(&state, message, MESSAGE_LEN) < 0) {
				perror("libkeccak_update");
				return 1;
			}
		}
#endif

		/* Digest. */
		if (libkeccak_fast_digest(&state, NULL, 0, 0, NULL, hashsum) < 0) {
			perror("libkeccak_digest");
			return 1;
		}
#ifndef IGNORE_BEHEXING
		libkeccak_behex_lower(hexsum, hashsum, OUTPUT / 8);
#endif

		/* Fast squeezes. */
#if FAST_SQUEEZE_RUNS > 0
		libkeccak_fast_squeeze(&state, FAST_SQUEEZE_RUNS);
#endif

		/* Slow squeezes. */
#if SLOW_SQUEEZE_RUNS > 0
		for (i = 0; i < SLOW_SQUEEZE_RUNS; i++) {
			libkeccak_squeeze(&state, hashsum);
# ifndef IGNORE_BEHEXING
			libkeccak_behex_lower(hexsum, hashsum, OUTPUT / 8);
# endif
		}
#endif
	}

	/* Get end-time. */
	if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end) < 0) {
		perror("clock_gettime");
		return -1;
	}

	/* Print execution-time. */
	end.tv_sec -= start.tv_sec;
	end.tv_nsec -= start.tv_nsec;
	if (end.tv_nsec < 0) {
		end.tv_sec--;
		end.tv_nsec += 1000000000L;
	}
	printf("%03li%09li\n", (long)(end.tv_sec), end.tv_nsec);

	/* Release resources and exit. */
	libkeccak_state_fast_destroy(&state);
	return 0;

#if (UPDATE_RUNS == 0) && (SLOW_SQUEEZE_RUNS == 0)
	(void) i;
#endif
}
