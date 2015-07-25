/**
 * libkeccak – Keccak-family hashing library
 * 
 * Copyright © 2014, 2015  Mattias Andrée (maandree@member.fsf.org)
 * 
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <libkeccak.h>

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>


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
 * @param   msg              The message to digest
 * @param   bits             Bits at the end of `message` that does not make up a whole byte
 * @param   expected_answer  The expected answer, must be lowercase
 * @return                   Zero on success, -1 on error
 */
static int test_digest_case(const libkeccak_spec_t* restrict spec, const char* restrict suffix,
			    const char* restrict msg, long bits, const char* restrict expected_answer)
{
  libkeccak_state_t state;
  char* restrict hashsum;
  char* restrict hexsum;
  int ok;
  
  if (libkeccak_state_initialise(&state, spec))
    return perror("libkeccak_state_initialise"), -1;
  if (hashsum = malloc((spec->output + 7) / 8), hashsum == NULL)
    return perror("malloc"), -1;
  if (hexsum = malloc((spec->output + 7) / 8 * 2 + 1), hexsum == NULL)
    return perror("malloc"), -1;
  
  if (libkeccak_digest(&state, msg, strlen(msg) - !!bits, bits, suffix, hashsum))
    return perror("libkeccak_digest"), -1;
  libkeccak_state_fast_destroy(&state);
  
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
#define sha3(output, message)								\
  (printf("  Testing SHA3-"#output"(%s): ", #message),					\
   libkeccak_spec_sha3(&spec, output),							\
   test_digest_case(&spec, LIBKECCAK_SHA3_SUFFIX, message, 0, answer))
#define keccak(output, message)								\
  (printf("  Testing Keccak-"#output"(%s): ", #message),				\
   libkeccak_spec_sha3(&spec, output) /* sic! */,					\
   test_digest_case(&spec, "", message, 0, answer))
#define keccak_bits(output, message, bits)						\
  (printf("  Testing Keccak-"#output"(%s-%i): ", #message, bits),			\
   libkeccak_spec_sha3(&spec, output) /* sic! */,					\
   test_digest_case(&spec, "", message, bits, answer))
#define rawshake(semicapacity, output, message)						\
  (printf("  Testing RawSHAKE-"#semicapacity"(%s, %i): ", #message, output),		\
   libkeccak_spec_rawshake(&spec, semicapacity, output),				\
   test_digest_case(&spec, LIBKECCAK_RAWSHAKE_SUFFIX, message, 0, answer))
#define rawshake_bits(semicapacity, output, message, bits)				\
  (printf("  Testing RawSHAKE-"#semicapacity"(%s-%i, %i): ", #message, bits, output),	\
   libkeccak_spec_rawshake(&spec, semicapacity, output),				\
   test_digest_case(&spec, LIBKECCAK_RAWSHAKE_SUFFIX, message, bits, answer))
#define shake(semicapacity, output, message)						\
  (printf("  Testing SHAKE-"#semicapacity"(%s, %i): ", #message, output),		\
   libkeccak_spec_shake(&spec, semicapacity, output),					\
   test_digest_case(&spec, LIBKECCAK_SHAKE_SUFFIX, message, 0, answer))
#define keccak_g(b, c, o, message)							\
  (printf("  Testing Keccak[%i,%i,%i](%s): ", b, c, o, #message),			\
   spec.bitrate = b, spec.capacity = c, spec.output = o,				\
   test_digest_case(&spec, "", message, 0, answer))
  
  
  libkeccak_spec_t spec;
  const char* answer;
  
  printf("Testing libkeccak_digest:\n");
  
  
  answer = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";
  if (sha3(224, ""))  return -1;
  
  answer = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
  if (sha3(256, ""))  return -1;
  
  answer = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
  if (sha3(384, ""))  return -1;
  
  answer = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
           "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
  if (sha3(512, ""))  return -1;
  
  
  answer = "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd";
  if (keccak(224, ""))  return -1;
  
  answer = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
  if (keccak(256, ""))  return -1;
  
  answer = "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff";
  if (keccak(384, ""))  return -1;
  
  answer = "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304"
           "c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e";
  if (keccak(512, ""))  return -1;
  
  
  answer = "22c8017ac8bcf65f59d1b7e92c9d4c6739d25e34ce5cb608b24ff096";
  if (sha3(224, "withdrew hypothesis snakebird qmc2"))  return -1;
  
  answer = "43808dde2662143dc4eed5dac5e98c74b06711829f02a3b121bd74f3";
  if (sha3(224, "intensifierat sturdiness perl-image-exiftool vingla"))  return -1;
  
  answer = "d32b4ac86065774dee5eb5cdd2f67b4e86501086d7373884e8b20a36";
  if (sha3(224, "timjan avogadro uppdriven lib32-llvm-amdgpu-snapshot"))  return -1;
  
  answer = "efbd76d45bfa952485148f8ad46143897f17c27ffdc8eb7287f9353b";
  if (sha3(224, "grilo-plugins auditorium tull dissimilarity's"))  return -1;
  
  answer = "6705aa36ecf58f333e0e6364ac1d0b7931d402e13282127cfd6f876c";
  if (sha3(224, "royalty tt yellowstone deficiencies"))  return -1;
  
  answer = "803a0ff09dda0df306e483a9f91b20a3dbbf9c2ebb8d0a3b28f3b9e0";
  if (sha3(224, "kdegames-kdiamond tunisisk occurrence's outtalad"))  return -1;
  
  answer = "a64779aca943a6aef1d2e7c9a0f4e997f4dabd1f77112a22121d3ed5";
  if (sha3(224, "chevalier slat's spindel representations"))  return -1;
  
  answer = "f0a3e0587af7723f0aa4719059d3f5107115a5b3667cd5209cc4d867";
  if (sha3(224, "archery lexicographical equine veered"))  return -1;
  
  answer = "312e7e3c6403ab1a086155fb9a52b22a3d0d257876afd2b93fb7272e";
  if (sha3(224, "splay washbasin opposing there"))  return -1;
  
  answer = "270ba05b764221ff5b5d94adfb4fdb1f36f07fe7c438904a5f3df071";
  if (sha3(224, "faktum desist thundered klen"))  return -1;
  
  
  answer = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
  if (keccak_bits(256, "\x02", 2))  return -1;
  
  answer = "3a1108d4a90a31b85a10bdce77f4bfbdcc5b1d70dd405686f8bbde834aa1a410";
  if (keccak_bits(256, "\x03", 2))  return -1;
  
  answer = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";
  if (keccak_bits(256, "\x0F", 4))  return -1;
  
  
  answer = "3a1108d4a90a31b85a10bdce77f4bfbd";
  if (rawshake(256, 128, ""))  return -1;
  
  answer = "46b9dd2b0ba88d13233b3feb743eeb24";
  if (rawshake_bits(256, 128, "\x03", 2))  return -1;
  
  answer = "46b9dd2b0ba88d13233b3feb743eeb24";
  if (shake(256, 128, ""))  return -1;
  
  
  answer = "65070cdd6f91c0aadcfc470895a2606c828bce7ce3fa723418c9013de92253515713cce8"
           "d2098be1c82df40b40e375549c0eeb655f92d718f01f147ba1c7c67844c7ba8b11492cd6";
  if (keccak_g(1024, 1600 - 1024, 576, "capitol's kvistfri broadly raping"))  return -1;
  
  answer = "65070cdd6f91c0aadcfc470895a2606c828bce7ce3fa723418c9013de92253515713cce8"
           "d2098be1c82df40b40e375549c0eeb655f92d718f01f147ba1c7c67844c7ba8b11492cd6"
           "143466958504c110522f772fe746573b1dc905f943ed1ec6ecf858575798596beeca4eb6"
           "bb7bea635bcea6331315728fb57866370bf1ad5d";
  if (keccak_g(1024, 1600 - 1024, 1024, "capitol's kvistfri broadly raping"))  return -1;
  
  answer = "65070cdd6f91c0aadcfc470895a2606c828bce7ce3fa723418c9013de92253515713cce8"
           "d2098be1c82df40b40e375549c0eeb655f92d718f01f147ba1c7c67844c7ba8b11492cd6"
           "143466958504c110522f772fe746573b1dc905f943ed1ec6ecf858575798596beeca4eb6"
           "bb7bea635bcea6331315728fb57866370bf1ad5decbc56d28d47ce53f18376d9f5531551"
           "7a976d52dd3f98b7025e0b3c513c6d17d40462cddb5406d693bbe859a136af5375b5dd6e"
           "3478934b00aa6cd44aa7ae2cd0271d83fbab699b";
  if (keccak_g(1024, 1600 - 1024, 1600, "capitol's kvistfri broadly raping"))  return -1;
  
  answer = "65070cdd6f91c0aadcfc470895a2606c828bce7ce3fa723418c9013de92253515713cce8"
           "d2098be1c82df40b40e375549c0eeb655f92d718f01f147ba1c7c67844c7ba8b11492cd6"
           "143466958504c110522f772fe746573b1dc905f943ed1ec6ecf858575798596beeca4eb6"
           "bb7bea635bcea6331315728fb57866370bf1ad5decbc56d28d47ce53f18376d9f5531551"
           "7a976d52dd3f98b7025e0b3c513c6d17d40462cddb5406d693bbe859a136af5375b5dd6e"
           "3478934b00aa6cd44aa7ae2cd0271d83fbab699b9c";
  if (keccak_g(1024, 1600 - 1024, 1608, "capitol's kvistfri broadly raping"))  return -1;
  
  answer = "65070cdd6f91c0aadcfc470895a2606c828bce7ce3fa723418c9013de92253515713cce8"
           "d2098be1c82df40b40e375549c0eeb655f92d718f01f147ba1c7c67844c7ba8b11492cd6"
           "143466958504c110522f772fe746573b1dc905f943ed1ec6ecf858575798596beeca4eb6"
           "bb7bea635bcea6331315728fb57866370bf1ad5decbc56d28d47ce53f18376d9f5531551"
           "7a976d52dd3f98b7025e0b3c513c6d17d40462cddb5406d693bbe859a136af5375b5dd6e"
           "3478934b00aa6cd44aa7ae2cd0271d83fbab699b9c58351bf7d26586b9c32282f1ac6356"
           "1981b79791d7ab2b6e01f5b8e6cf0cab8b2076fd82bd99df015a602cdda5684162fea982"
           "0f5a441c4620f549fbaf4e818201f292dbf4f6c9f82af8aa80b4124984da6f65b2874e0e"
           "f01d042c08e9aedbb6ce4c10526e38c1a4e8b108c4f14b066f9d42640687b55124b081da"
           "a9f9ae4232f313740b4fb787545dc19e7778f7082b3fa5824d2400c012be1a6c5ade7149"
           "e452d310752fa9ebb964ab36fde0c8f46f47a0e2c9b20f24e3cca904bbedaa7ea176f662"
           "33cd2d95";
  if (keccak_g(1024, 1600 - 1024, 3200, "capitol's kvistfri broadly raping"))  return -1;
  
  answer = "65070cdd6f91c0aadcfc470895a2606c828bce7ce3fa723418c9013de9225351";
  if (keccak_g(1024, 1600 - 1024, 256, "capitol's kvistfri broadly raping"))  return -1;
  
  answer = "e6f86ebc15b962f73f36f36fc8a84c3ae84b1c1023bfd4c5f1829389135aecc3";
  if (keccak_g(512, 1600 - 512, 256, "capitol's kvistfri broadly raping"))  return -1;
  
  answer = "420b97fc88962c87ec2adaa8f48d74d9ff4ea7ae7d691f9c33b8713ca1d3d573";
  if (keccak_g(256, 1600 - 256, 256, "capitol's kvistfri broadly raping"))  return -1;
  
  answer = "524790afbe4706d938b6f753e14104f556890e2a415e211b0564d60499db0333";
  if (keccak_g(512, 800 - 512, 256, "capitol's kvistfri broadly raping"))  return -1;
  
  answer = "04a6b4ad08b3018eefba0fb756272d949ac0f71c26f836d31dd13b28b884aa0f";
  if (keccak_g(256, 800 - 256, 256, "capitol's kvistfri broadly raping"))  return -1;
  
  answer = "d56f547791225e54460e6274ed31e57b7085820c11d65f1f322a16a3352c85ed";
  if (keccak_g(256, 400 - 256, 256, "capitol's kvistfri broadly raping"))  return -1;
  
  answer = "ceec066a57b9b31a5a0661df7bafec4183a26d0ed81e50bc958471f84fa347a7";
  if (keccak_g(128, 400 - 128, 256, "capitol's kvistfri broadly raping"))  return -1;
  
  answer = "b18f679c7105a72a993f70fa5adb3f17ef7ccffaffb4dc0f6fed74aa2f565194";
  if (keccak_g(128, 200 - 128, 256, "capitol's kvistfri broadly raping"))  return -1;
  
  answer = "9b845c1ecc2b1b3a48ba42ef29ccc4b348da8ab15074a870d8e799ca33c15e4b";
  if (keccak_g(64, 200 - 64, 256, "capitol's kvistfri broadly raping"))  return -1;
  
  
  printf("\n");
  return 0;
  
#undef keccak_g
#undef shake
#undef rawshake_bits
#undef rawshake
#undef keccak_bits
#undef keccak
#undef sha3
}


/**
 * Run a test case for `libkeccak_update`
 * 
 * @param   spec             The specification for the hashing
 * @param   suffix           The message suffix (padding prefix)
 * @param   msg              The message to digest
 * @param   expected_answer  The expected answer, must be lowercase
 * @return                   Zero on success, -1 on error
 */
static int test_update_case(const libkeccak_spec_t* restrict spec, const char* restrict suffix,
			    const char* restrict msg, const char* restrict expected_answer)
{
  libkeccak_state_t state;
  char* restrict hashsum;
  char* restrict hexsum;
  int ok;
  
  if (libkeccak_state_initialise(&state, spec))
    return perror("libkeccak_state_initialise"), -1;
  if (hashsum = malloc((spec->output + 7) / 8), hashsum == NULL)
    return perror("malloc"), -1;
  if (hexsum = malloc((spec->output + 7) / 8 * 2 + 1), hexsum == NULL)
    return perror("malloc"), -1;
  
  if (libkeccak_update(&state, msg, strlen(msg)))
    return perror("libkeccak_update"), -1;
  if (libkeccak_digest(&state, NULL, 0, 0, suffix, hashsum))
    return perror("libkeccak_digest"), -1;
  libkeccak_state_fast_destroy(&state);
  
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
 * Run test cases for `libkeccak_update`
 * 
 * @return  Zero on success, -1 on error
 */
static int test_update(void)
{
#define sha3(output, message)						\
  (printf("  Testing SHA3-"#output"(%s): ", #message),			\
   libkeccak_spec_sha3(&spec, output),					\
   test_update_case(&spec, LIBKECCAK_SHA3_SUFFIX, message, answer))
  
  libkeccak_spec_t spec;
  const char* answer;
  
  printf("Testing libkeccak_update:\n");
  
  
  answer = "22c8017ac8bcf65f59d1b7e92c9d4c6739d25e34ce5cb608b24ff096";
  if (sha3(224, "withdrew hypothesis snakebird qmc2"))  return -1;
  
  answer = "43808dde2662143dc4eed5dac5e98c74b06711829f02a3b121bd74f3";
  if (sha3(224, "intensifierat sturdiness perl-image-exiftool vingla"))  return -1;
  
  answer = "d32b4ac86065774dee5eb5cdd2f67b4e86501086d7373884e8b20a36";
  if (sha3(224, "timjan avogadro uppdriven lib32-llvm-amdgpu-snapshot"))  return -1;
  
  answer = "efbd76d45bfa952485148f8ad46143897f17c27ffdc8eb7287f9353b";
  if (sha3(224, "grilo-plugins auditorium tull dissimilarity's"))  return -1;
  
  answer = "6705aa36ecf58f333e0e6364ac1d0b7931d402e13282127cfd6f876c";
  if (sha3(224, "royalty tt yellowstone deficiencies"))  return -1;
  
  answer = "803a0ff09dda0df306e483a9f91b20a3dbbf9c2ebb8d0a3b28f3b9e0";
  if (sha3(224, "kdegames-kdiamond tunisisk occurrence's outtalad"))  return -1;
  
  answer = "a64779aca943a6aef1d2e7c9a0f4e997f4dabd1f77112a22121d3ed5";
  if (sha3(224, "chevalier slat's spindel representations"))  return -1;
  
  answer = "f0a3e0587af7723f0aa4719059d3f5107115a5b3667cd5209cc4d867";
  if (sha3(224, "archery lexicographical equine veered"))  return -1;
  
  answer = "312e7e3c6403ab1a086155fb9a52b22a3d0d257876afd2b93fb7272e";
  if (sha3(224, "splay washbasin opposing there"))  return -1;
  
  answer = "270ba05b764221ff5b5d94adfb4fdb1f36f07fe7c438904a5f3df071";
  if (sha3(224, "faktum desist thundered klen"))  return -1;
  
  
  printf("\n");
  return 0;
  
#undef sha3
}


/**
 * Run a test for `libkeccak_*squeeze` functions
 * 
 * @param   state            The state whould should use, we will reset it
 * @param   spec             The specification for the hashing
 * @param   fast_squeezes    The number of fast squeezes to perform
 * @param   squeezes         The number of extra squeezes to perform in total
 * @param   fast_digest      Whether `libkeccak_digest` should do a fast squeeze rather than a slow squeeze
 * @param   hashsum          A buffer in which we can used to store the binary hashsum
 * @param   hexsum           A buffer in which we can used to store the hexadecimal hashsum
 * @param   expected_answer  The hashum we expect, must be in lowercase hexadecimal
 * @return                   Zero on success, -1 on error
 */
static int test_squeeze_case(libkeccak_state_t* restrict state, const libkeccak_spec_t* restrict spec,
			     long fast_squeezes, long squeezes, int fast_digest, char* restrict hashsum,
			     char* restrict hexsum, const char* restrict expected_answer)
{
#define message  "withdrew hypothesis snakebird qmc2"
  long i;
  int ok;
  
  libkeccak_state_reset(state);
  if (libkeccak_digest(state, message, strlen(message), 0, LIBKECCAK_SHA3_SUFFIX, fast_digest ? NULL : hashsum))
    return perror("libkeccak_digest"), -1;
  
  libkeccak_fast_squeeze(state, fast_squeezes);
  for (i = fast_squeezes; i < squeezes; i++)
    libkeccak_squeeze(state, hashsum);
  
  libkeccak_behex_lower(hexsum, hashsum, (spec->output + 7) / 8);
  ok = !strcmp(hexsum, expected_answer);
  printf("%s%s\n", ok ? "OK" : "Fail: ", ok ? "" : hexsum);
  if (!ok)
    printf("  r, c, n = %li, %li, %li\n", spec->bitrate, spec->capacity, spec->output);
  
  return ok - 1;
#undef message
}


/**
 * Test `libkeccak_*squeeze` functions
 * 
 * @return  Zero on success, -1 on error
 */
static int test_squeeze(void)
{
#define answer1  "03fe12b4b51d56d96377d927e5cd498fc4bc3aee389b2f2ff8393aa5"
#define answer2  "0b8fb64ee5d8836956f49cbe4577afbc638c855c1d553452fc1eceb8"
#define answer3  "1e03b4cd9eef3892a7b5e865fce393c4bc90120d9aea84d0a0dff3b8"
#define answer4  "aac92fbfd22ce62e83ddaf2e61bd7bf696326e46d1327defa4530e20"
  
#define run_test(fast_squeezes, squeezes, fast_digest)  \
  test_squeeze_case(&state, &spec, fast_squeezes, squeezes, fast_digest, hashsum, hexsum, answer##squeezes)
  
  libkeccak_spec_t spec;
  libkeccak_state_t state;
  char* restrict hashsum;
  char* restrict hexsum;
  
  libkeccak_spec_sha3(&spec, 224);
  if (hashsum = malloc((spec.output + 7) / 8), hashsum == NULL)
    return perror("malloc"), -1;
  if (hexsum = malloc((spec.output + 7) / 8 * 2 + 1), hexsum == NULL)
    return perror("malloc"), -1;
  if (libkeccak_state_initialise(&state, &spec))
    return perror("libkeccak_state_initialise"), -1;
  
  printf("Testing squeeze functions with slow initial digest:\n");
  printf("  1 extra squeeze,  including 0 fast squeezes: "), run_test(0, 1, 0);
  printf("  2 extra squeezes, including 0 fast squeezes: "), run_test(0, 2, 0);
  printf("  2 extra squeezes, including 1 fast squeeze:  "), run_test(1, 2, 0);
  printf("  3 extra squeezes, including 0 fast squeezes: "), run_test(0, 3, 0);
  printf("  3 extra squeezes, including 1 fast squeeze:  "), run_test(1, 3, 0);
  printf("  3 extra squeezes, including 2 fast squeezes: "), run_test(2, 3, 0);
  printf("  4 extra squeezes, including 0 fast squeezes: "), run_test(0, 4, 0);
  printf("  4 extra squeezes, including 1 fast squeeze:  "), run_test(1, 4, 0);
  printf("  4 extra squeezes, including 2 fast squeezes: "), run_test(2, 4, 0);
  printf("  4 extra squeezes, including 3 fast squeezes: "), run_test(3, 4, 0);
  printf("\n");
  
  printf("Testing squeeze functions with fast initial digest:\n");
  printf("  1 extra squeeze,  including 0 fast squeezes: "), run_test(0, 1, 1);
  printf("  2 extra squeezes, including 0 fast squeezes: "), run_test(0, 2, 1);
  printf("  2 extra squeezes, including 1 fast squeeze:  "), run_test(1, 2, 1);
  printf("  3 extra squeezes, including 0 fast squeezes: "), run_test(0, 3, 1);
  printf("  3 extra squeezes, including 1 fast squeeze:  "), run_test(1, 3, 1);
  printf("  3 extra squeezes, including 2 fast squeezes: "), run_test(2, 3, 1);
  printf("  4 extra squeezes, including 0 fast squeezes: "), run_test(0, 4, 1);
  printf("  4 extra squeezes, including 1 fast squeeze:  "), run_test(1, 4, 1);
  printf("  4 extra squeezes, including 2 fast squeezes: "), run_test(2, 4, 1);
  printf("  4 extra squeezes, including 3 fast squeezes: "), run_test(3, 4, 1);
  printf("\n");
  
  libkeccak_state_fast_destroy(&state);
  free(hashsum);
  free(hexsum);
  return 0;
  
#undef run_test
#undef answer4
#undef answer3
#undef answer2
#undef answer1
}



/**
 * Run a test for `libkeccak_generalised_sum_fd`
 * 
 * @param   spec             The specification for the hashing
 * @param   suffix           The message suffix (padding prefix)
 * @param   filename         The name of the file we should hash
 * @param   expected_answer  The hashum we expect, must be in lowercase hexadecimal
 * @return                   Zero on success, -1 on error
 */
static int test_file(const libkeccak_spec_t* restrict spec, const char* restrict suffix,
		     const char* restrict filename, const char* restrict expected_answer)
{
  libkeccak_state_t state;
  char* restrict hashsum;
  char* restrict hexsum;
  int ok, fd;
  
  printf("Testing libkeccak_generalised_sum_fd on %s: ", filename);
  
  if (hashsum = malloc((spec->output + 7) / 8), hashsum == NULL)
    return perror("malloc"), -1;
  if (hexsum = malloc((spec->output + 7) / 8 * 2 + 1), hexsum == NULL)
    return perror("malloc"), -1;
  
  if (fd = open(filename, O_RDONLY), fd < 0)
    return perror("open"), -1;
  
  if (libkeccak_generalised_sum_fd(fd, &state, spec, suffix, hashsum))
    return perror("libkeccak_generalised_sum_fd"), close(fd), -1;
  
  libkeccak_behex_lower(hexsum, hashsum, (spec->output + 7) / 8);
  ok = !strcmp(hexsum, expected_answer);
  printf("%s%s\n", ok ? "OK" : "Fail: ", ok ? "" : hexsum);
  if (!ok)
    printf("  r, c, n = %li, %li, %li\n", spec->bitrate, spec->capacity, spec->output);
  
  close(fd);
  free(hashsum);
  free(hexsum);
  libkeccak_state_fast_destroy(&state);
  return ok - 1;
}


/**
 * Basically, verify the correctness of the library.
 * The current working path must be the root directory
 * of the repository (the project directory).
 * 
 * @return  Zero on success, 1 on failure or incorrectness
 */
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
  if (test_update())      return 1;
  if (test_squeeze())     return 1;
  
  if (test_file(&spec, LIBKECCAK_SHA3_SUFFIX, "LICENSE",
		"68dd720832a594c1986078d2d09ab21d80b9d66d98c52f2679e81699519e2f8a"
		"3c970bb9c514206b574a944ffaa6466d546eb17f64f47c01ec053ab4ce35575a"))
    return 1;
  
  return 0;
}

