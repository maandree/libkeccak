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
#include <libkeccak.h>

#include <stdio.h>
#include <string.h>


/**
 * Test functions in <libkeccak/hex.h>
 * 
 * @return  Zero on success, -1 on error
 */
static int test_hex(void)
{
  const unsigned char bindata[] = {0x04, 0x2F, 0x12, 0x83, 0xFF, 0x80, 0xA3, 0x00};
  const char hexdata_upper[] = "042F1283FF80A300";
  const char hexdata_lower[] = "042f1283ff80a300";
  char hextest[2 * 8 + 1];
  
  printf("Testing libkeccak_behex_lower: ");
  libkeccak_behex_lower(hextest, (const char*)bindata, 8);
  if (!strcmp(hextest, hexdata_lower))
    printf("OK\n");
  else
    return printf("Fail\n"), -1;
  
  printf("Testing libkeccak_behex_upper: ");
  libkeccak_behex_upper(hextest, (const char*)bindata, 8);
  if (!strcmp(hextest, hexdata_upper))
    printf("OK\n");
  else
    return printf("Fail\n"), -1;
  
  printf("Testing libkeccak_unhex on uppercase: ");
  libkeccak_unhex(hextest, hexdata_upper);
  if (!memcmp(bindata, hextest, 8 * sizeof(char)))
    printf("OK\n");
  else
    return printf("Fail\n"), -1;
  
  printf("Testing libkeccak_unhex on lowercase: ");
  libkeccak_unhex(hextest, hexdata_lower);
  if (!memcmp(bindata, hextest, 8 * sizeof(char)))
    printf("OK\n");
  else
    return printf("Fail\n"), -1;
  
  printf("\n");
  return 0;
}


/**
 * Test functions in <libkeccak/state.h>
 * 
 * @param   spec  The specifications for the state
 * @return        Zero on success, -1 on error
 */
static int test_state(libkeccak_spec_t* restrict spec)
{
  libkeccak_state_t* restrict state;
  libkeccak_state_t* restrict state2;
  size_t marshal_size, marshalled_size, i, n;
  char* restrict marshalled_data;
  
  if (state = libkeccak_state_create(spec), state == NULL)
    return perror("libkeccak_state_initialise"), -1;
  
  n = state->mlen / 2;
  for (i = 0; i < n; i++)
    state->M[state->mptr++] = (char)(i & 255);
  
  if (state2 = libkeccak_state_duplicate(state), state2 == NULL)
    return perror("libkeccak_state_duplicate"), -1;
  
  if (state->M[state->mptr - 1] != state2->M[state2->mptr - 1])
    return printf("Inconsistency found between original state and duplicate state.\n"), -1;
  
  marshal_size = libkeccak_state_marshal_size(state2);
  if (marshalled_data = malloc(marshal_size), marshalled_data == NULL)
    return perror("malloc"), -1;
  
  marshalled_size = libkeccak_state_marshal(state2, marshalled_data);
  if (marshalled_size != marshal_size)
    return printf("libkeccak_state_marshal returned an unexpected value.\n"), -1;
  
  libkeccak_state_free(state);
  
  if (state = malloc(sizeof(libkeccak_state_t)), state == NULL)
    return perror("malloc"), -1;
  marshalled_size = libkeccak_state_unmarshal(state, marshalled_data);
  if (marshalled_size == 0)
    return perror("libkeccak_state_unmarshal"), -1;
  if (marshalled_size != marshal_size)
    return printf("libkeccak_state_unmarshal returned an unexpected value.\n"), -1;
  
  if (libkeccak_state_unmarshal_skip(marshalled_data) != marshal_size)
    return printf("libkeccak_state_unmarshal_skip returned an unexpected value.\n"), -1;
  
  if (state->M[state->mptr - 1] != state2->M[state2->mptr - 1])
    return printf("Inconsistency found between original state and unmarshalled state.\n"), -1;

  free(marshalled_data);
  libkeccak_state_free(state);
  libkeccak_state_free(state2);
  return 0;
}


int main(void)
{
  libkeccak_generalised_spec_t gspec;
  libkeccak_spec_t spec;
  
  libkeccak_generalised_spec_initialise(&gspec);
  if (libkeccak_degeneralise_spec(&gspec, &spec))
    return printf("libkeccak_degeneralise_spec failed with all members at automatic.\n"), 1;
  
  printf("Resolution of default specification:\n");
  printf("  bitrate:    %li\n", gspec.bitrate);
  printf("  capacity:   %li\n", gspec.capacity);
  printf("  output:     %li\n", gspec.output);
  printf("  state size: %li\n", gspec.state_size);
  printf("  word size:  %li\n", gspec.word_size);
  if (gspec.word_size * 25 != gspec.state_size)            return printf("Invalid information\n"), 1;
  if (gspec.bitrate + gspec.capacity != gspec.state_size)  return printf("Invalid information\n"), 1;
  if (gspec.state_size != 1600)                            return printf("Incorrect information\n"), 1;
  if (gspec.bitrate != gspec.output * 2)                   return printf("Incorrect information\n"), 1;
  if (gspec.output != 512)                                 return printf("Incorrect information\n"), 1;
  printf("\n");
  
  if (test_hex())         return 1;
  if (test_state(&spec))  return 1;
  
  return 0;
}

