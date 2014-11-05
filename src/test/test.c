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


/**
 * Run a test case for `libkeccak_digest`
 * 
 * @param   spec             The specification for the hashing
 * @param   suffix           The message suffix (padding prefix)
 * @param   message          The message to digest
 * @param   expected_answer  The expected answer, must be lowercase
 * @return                   Zero on success, -1 on error
 */
static int test_digest_case(const libkeccak_spec_t* restrict spec, const char* restrict suffix,
			    const char* restrict message, const char* restrict expected_answer)
{
  libkeccak_state_t state;
  char* restrict hashsum;
  char* restrict hexsum;
  char* restrict msg;
  int ok;
  
  if (libkeccak_state_initialise(&state, spec))
    return perror("libkeccak_state_initialise"), -1;
  if (hashsum = malloc((spec->output + 7) / 8), hashsum == NULL)
    return perror("malloc"), -1;
  if (hexsum = malloc((spec->output + 7) / 8 * 2 + 1), hexsum == NULL)
    return perror("malloc"), -1;
  if (msg = strdup(message), msg == NULL)
    return perror("strdup"), -1;
  
  libkeccak_digest(&state, msg, strlen(msg), 0, suffix, hashsum);
  libkeccak_state_fast_destroy(&state);
  free(msg);
  
  libkeccak_behex_lower(hexsum, hashsum, (spec->output + 7) / 8);
  ok = !strcmp(hexsum, expected_answer);
  printf("%s%s\n", ok ? "OK" : "Fail: ", ok ? "" : hexsum);
  if (!ok)
    printf("  r, c, n = %li, %li, %li\n", spec->bitrate, spec->capacity, spec->output);
  
  free(hashsum);
  free(hexsum);
  
  return ok - 1;
}


/**
 * Run test cases for `libkeccak_digest`
 * 
 * @return  Zero on success, -1 on error
 */
static int test_digest(void)
{
#define sha3(output, message)						\
  (printf("Testing SHA3-"#output"(\""message"\"): "),			\
   libkeccak_spec_sha3(&spec, output),					\
   test_digest_case(&spec, LIBKECCAK_SHA3_SUFFIX, message, answer))
  
  libkeccak_spec_t spec;
  const char* answer;
  
  answer = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";
  if (sha3(224, ""))  return -1;
  
  answer = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
  if (sha3(256, ""))  return -1;
  
  answer = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
  if (sha3(384, ""))  return -1;
  
  answer = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
           "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
  if (sha3(512, ""))  return -1;

  return 0;
#undef sha3
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
  if (test_digest())      return 1;
  
  return 0;
}

