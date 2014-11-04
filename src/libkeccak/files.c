/**
 * libkeccak – Keccak-family hashing library
 * 
 * Copyright © 2014  Mattias Andrée (maandree@member.fsf.org)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "files.h"


#include <stddef.h>
#include <unistd.h>
#include <sys/stat.h>
#include <alloca.h>


/**
 * Calculate a Keccak-family hashsum of a file
 * 
 * @param   fd       The file descriptor of the file to hash
 * @param   state    The hashing state, should not be initialised (memory leak otherwise)
 * @param   spec     Specifications for the hashing algorithm
 * @param   suffix   The data suffix, see `libkeccak_digest`
 * @param   hashsum  Output array for the hashsum, have an allocation size of
 *                   at least `(spec->output / 8) * sizeof(char)`, may be `NULL`
 * @return           Zero on success, -1 on error
 */
int libkeccak_generalised_sum_fd(int fd, libkeccak_state_t* restrict state,
				 const libkeccak_spec_t* restrict spec,
				 const char* restrict suffix, char* restrict hashsum)
{
  ssize_t got;
  struct stat attr;
  size_t blksize = 4096;
  char* chunk;
  
  if (libkeccak_state_initialise(state, spec) < 0)
    return -1;
  
  if (fstat(fd, &attr) == 0)
    if (attr.st_blksize > 0)
      blksize = attr.st_blksize;
  
  chunk = alloca(blksize);
  
  for (;;)
    {
      got = read(fd, chunk, blksize);
      if (got < 0)   return -1;
      if (got == 0)  break;
      if (libkeccak_update(state, chunk, (size_t)got) < 0)
	return -1;
    }
  
  return libkeccak_digest(state, NULL, 0, 0, suffix, hashsum);
}

