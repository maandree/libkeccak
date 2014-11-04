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
 * Test functions in <libkeccak.h>
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


int main(void)
{
  libkeccak_generalised_spec_t gspec;
  libkeccak_spec_t spec;
  
  if (test_hex())
    return 1;
  
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
  
  return 0;
}

