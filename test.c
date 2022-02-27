/* See LICENSE file for copyright and license details. */
#include "libkeccak.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


/**
 * Test hexdecimal-coding functions
 * 
 * @return  Zero on success, -1 on error
 */
static int
test_hex(void)
{
	const unsigned char bindata[] = {0x04, 0x2F, 0x12, 0x83, 0xFF, 0x80, 0xA3, 0x00};
	const char hexdata_upper[] = "042F1283FF80A300";
	const char hexdata_lower[] = "042f1283ff80a300";
	char hextest[2 * 8 + 1];

	printf("Testing libkeccak_behex_lower: ");
	libkeccak_behex_lower(hextest, (const char *)bindata, 8);
	if (!strcmp(hextest, hexdata_lower)) {
		printf("OK\n");
	} else {
		printf("Fail\n");
		return -1;
	}

	printf("Testing libkeccak_behex_upper: ");
	libkeccak_behex_upper(hextest, (const char *)bindata, 8);
	if (!strcmp(hextest, hexdata_upper)) {
		printf("OK\n");
	} else {
		printf("Fail\n");
		return -1;
	}

	printf("Testing libkeccak_unhex on uppercase: ");
	libkeccak_unhex(hextest, hexdata_upper);
	if (!memcmp(bindata, hextest, 8 * sizeof(char))) {
		printf("OK\n");
	} else {
		printf("Fail\n");
		return -1;
	}

	printf("Testing libkeccak_unhex on lowercase: ");
	libkeccak_unhex(hextest, hexdata_lower);
	if (!memcmp(bindata, hextest, 8 * sizeof(char))) {
		printf("OK\n");
	} else {
		printf("Fail\n");
		return -1;
	}

	printf("\n");
	return 0;
}


/**
 * Test state functions
 * 
 * @param   spec  The specifications for the state
 * @return        Zero on success, -1 on error
 */
static int
test_state(struct libkeccak_spec *restrict spec)
{
	struct libkeccak_state *restrict state;
	struct libkeccak_state *restrict state2;
	size_t marshal_size, marshalled_size, i, n;
	char *restrict marshalled_data;

	state = libkeccak_state_create(spec);
	if (!state) {
		perror("libkeccak_state_initialise");
		return -1;
	}

	n = state->mlen / 2;
	for (i = 0; i < n; i++)
		state->M[state->mptr++] = (unsigned char)i;

	state2 = libkeccak_state_duplicate(state);
	if (!state2) {
		perror("libkeccak_state_duplicate");
		return -1;
	}

	if (state->M[state->mptr - 1] != state2->M[state2->mptr - 1]) {
		printf("Inconsistency found between original state and duplicate state.\n");
		return -1;
	}

	marshal_size = libkeccak_state_marshal(state2, NULL);
	marshalled_data = malloc(marshal_size);
	if (!marshalled_data) {
		perror("malloc");
		return -1;
	}

	marshalled_size = libkeccak_state_marshal(state2, marshalled_data);
	if (marshalled_size != marshal_size) {
		printf("libkeccak_state_marshal returned an unexpected value.\n");
		return -1;
	}

	libkeccak_state_free(state);

	state = malloc(sizeof(struct libkeccak_state));
	if (!state) {
		perror("malloc");
		return -1;
	}
	marshalled_size = libkeccak_state_unmarshal(state, marshalled_data);
	if (!marshalled_size) {
		perror("libkeccak_state_unmarshal");
		return -1;
	}
	if (marshalled_size != marshal_size) {
		printf("libkeccak_state_unmarshal returned an unexpected value.\n");
		return -1;
	}

	if (libkeccak_state_unmarshal(NULL, marshalled_data) != marshal_size) {
		printf("libkeccak_state_unmarshal(NULL, .) returned an unexpected value.\n");
		return -1;
	}

	if (state->M[state->mptr - 1] != state2->M[state2->mptr - 1]) {
		printf("Inconsistency found between original state and unmarshalled state.\n");
		return -1;
	}

	free(marshalled_data);
	libkeccak_state_free(state);
	libkeccak_state_free(state2);
	return 0;
}


/**
 * Run a test case for `libkeccak_digest`
 * 
 * @param   state            Already initialised state
 * @param   spec             The specification for the hashing
 * @param   suffix           The message suffix (padding prefix)
 * @param   msg              The message to digest
 * @param   bytes            Number of while bytes in `msg`
 * @param   bits             Bits at the end of `msg` that does not make up a whole byte
 * @param   expected_answer  The expected answer, must be lowercase
 * @return                   Zero on success, -1 on error
 */
static int
test_digest_case_inited(struct libkeccak_state *restrict state, const struct libkeccak_spec *restrict spec,
                        const char *restrict suffix, const char *restrict msg, size_t bytes, size_t bits,
                        const char *restrict expected_answer)
{
	unsigned char *restrict hashsum;
	char *restrict hexsum;
	int ok;

	hashsum = malloc((size_t)((spec->output + 7) / 8));
	if (!hashsum) {
		perror("malloc");
		return -1;
	}
	hexsum = malloc((size_t)((spec->output + 7) / 8 * 2 + 1));
	if (!hexsum) {
		perror("malloc");
		return -1;
	}

	if (libkeccak_digest(state, msg, bytes, bits, suffix, hashsum)) {
		perror("libkeccak_digest");
		return -1;
	}

	libkeccak_behex_lower(hexsum, hashsum, (size_t)((spec->output + 7) / 8));
	ok = !strcmp(hexsum, expected_answer);
	printf("%s%s\n", ok ? "OK" : "Fail: ", ok ? "" : hexsum);
	if (!ok)
		printf("  r, c, n = %li, %li, %li\n", spec->bitrate, spec->capacity, spec->output);

	free(hashsum);
	free(hexsum);

	return ok - 1;
}


/**
 * Run a test case for `libkeccak_digest`
 * 
 * @param   spec             The specification for the hashing
 * @param   suffix           The message suffix (padding prefix)
 * @param   msg              The message to digest
 * @param   bytes            Number of while bytes in `msg`
 * @param   bits             Bits at the end of `msg` that does not make up a whole byte
 * @param   expected_answer  The expected answer, must be lowercase
 * @return                   Zero on success, -1 on error
 */
static int
test_digest_case(const struct libkeccak_spec *restrict spec, const char *restrict suffix,
                 const char *restrict msg, size_t bytes, size_t bits, const char *restrict expected_answer)
{
	struct libkeccak_state state;
	int ret;
	if (libkeccak_state_initialise(&state, spec)) {
		perror("libkeccak_state_initialise");
		return -1;
	}
	ret = test_digest_case_inited(&state, spec, suffix, msg, bytes, bits, expected_answer);
	libkeccak_state_fast_destroy(&state);
	return ret;
}


/**
 * Run a test case for `libkeccak_digest` with cSHAKE
 * 
 * @param   spec             The specification for the hashing
 * @param   suffix           The message suffix (padding prefix)
 * @param   n_text           Function name-string
 * @param   n_len            Byte-length of `n_text` (only whole byte)
 * @param   n_bits           Bit-length of `n_text`, minus `n_len * 8`
 * @param   n_suffix         Bit-string, represented by a NUL-terminated
 *                           string of '1':s and '0's:, making up the part
 *                           after `n_text` of the function-name bit-string;
 *                           `NULL` is treated as the empty string
 * @param   s_text           Customisation-string
 * @param   s_len            Byte-length of `s_text` (only whole byte)
 * @param   s_bits           Bit-length of `s_text`, minus `s_len * 8`
 * @param   s_suffix         Bit-string, represented by a NUL-terminated
 *                           string of '1':s and '0's:, making up the part
 *                           after `s_text` of the customisation bit-string;
 *                           `NULL` is treated as the empty string
 * @param   msg              The message to digest
 * @param   bytes            Number of while bytes in `msg`
 * @param   bits             Bits at the end of `msg` that does not make up a whole byte
 * @param   expected_answer  The expected answer, must be lowercase
 * @return                   Zero on success, -1 on error
 */
static int
test_digest_case_cshake(const struct libkeccak_spec *restrict spec, const char *restrict suffix,
                        const void *n_text, size_t n_len, size_t n_bits, const char *n_suffix,
                        const void *s_text, size_t s_len, size_t s_bits, const char *s_suffix,
                        const char *restrict msg, size_t bytes, size_t bits, const char *restrict expected_answer)
{
	struct libkeccak_state state;
	int ret;
	if (libkeccak_state_initialise(&state, spec)) {
		perror("libkeccak_state_initialise");
		return -1;
	}
	libkeccak_cshake_initialise(&state, n_text, n_len, n_bits, n_suffix, s_text, s_len, s_bits, s_suffix);
	ret = test_digest_case_inited(&state, spec, suffix, msg, bytes, bits, expected_answer);
	libkeccak_state_fast_destroy(&state);
	return ret;
}


/**
 * Run test cases for `libkeccak_digest`
 * 
 * @return  Zero on success, -1 on error
 */
static int
test_digest(void)
{
#define sha3(output, message)\
	(printf("  Testing SHA3-"#output"(%s): ", #message),\
	 libkeccak_spec_sha3(&spec, output),\
	 test_digest_case(&spec, LIBKECCAK_SHA3_SUFFIX, message, strlen(message), 0, answer))

#define keccak(output, message)\
	(printf("  Testing Keccak-"#output"(%s): ", #message),\
	 libkeccak_spec_sha3(&spec, output) /* sic! */,\
	 test_digest_case(&spec, "", message, strlen(message), 0, answer))

#define keccak_bits(output, message, msg_bits)\
	(printf("  Testing Keccak-"#output"(%s:%i): ", #message, msg_bits),\
	 libkeccak_spec_sha3(&spec, output) /* sic! */,\
	 test_digest_case(&spec, "", message, msg_bits / 8, msg_bits % 8, answer))

#define rawshake(semicapacity, output, message)\
	(printf("  Testing RawSHAKE-"#semicapacity"(%s, %i): ", #message, output),\
	 libkeccak_spec_rawshake(&spec, semicapacity, output),\
	 test_digest_case(&spec, LIBKECCAK_RAWSHAKE_SUFFIX, message, strlen(message), 0, answer))

#define rawshake_bits(semicapacity, output, message, bits)\
	(printf("  Testing RawSHAKE-"#semicapacity"(%s-%i, %i): ", #message, bits, output),\
	 libkeccak_spec_rawshake(&spec, semicapacity, output),\
	 test_digest_case(&spec, LIBKECCAK_RAWSHAKE_SUFFIX, message, strlen(message) - !!bits, bits, answer))

#define shake(semicapacity, output, message)\
	(printf("  Testing SHAKE-"#semicapacity"(%s, %i): ", #message, output),\
	 libkeccak_spec_shake(&spec, semicapacity, output),\
	 test_digest_case(&spec, LIBKECCAK_SHAKE_SUFFIX, message, strlen(message), 0, answer))

#define keccak_g(b, c, o, message)\
	(printf("  Testing Keccak[%i,%i,%i](%s): ", b, c, o, #message),\
	 spec.bitrate = b, spec.capacity = c, spec.output = o,\
	 test_digest_case(&spec, "", message, strlen(message), 0, answer))


	struct libkeccak_spec spec;
	const char *answer;

	printf("Testing libkeccak_digest:\n");


	answer = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";
	if (sha3(224, ""))
		return -1;

	answer = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
	if (sha3(256, ""))
		return -1;

	answer = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
	if (sha3(384, ""))
		return -1;

	answer = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
	         "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
	if (sha3(512, ""))
		return -1;


	answer = "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd";
	if (keccak(224, ""))
		return -1;

	answer = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
	if (keccak(256, ""))
		return -1;

	answer = "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff";
	if (keccak(384, ""))
		return -1;

	answer = "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304"
	         "c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e";
	if (keccak(512, ""))
		return -1;


	answer = "22c8017ac8bcf65f59d1b7e92c9d4c6739d25e34ce5cb608b24ff096";
	if (sha3(224, "withdrew hypothesis snakebird qmc2"))
		return -1;

	answer = "43808dde2662143dc4eed5dac5e98c74b06711829f02a3b121bd74f3";
	if (sha3(224, "intensifierat sturdiness perl-image-exiftool vingla"))
		return -1;

	answer = "d32b4ac86065774dee5eb5cdd2f67b4e86501086d7373884e8b20a36";
	if (sha3(224, "timjan avogadro uppdriven lib32-llvm-amdgpu-snapshot"))
		return -1;

	answer = "efbd76d45bfa952485148f8ad46143897f17c27ffdc8eb7287f9353b";
	if (sha3(224, "grilo-plugins auditorium tull dissimilarity's"))
		return -1;

	answer = "6705aa36ecf58f333e0e6364ac1d0b7931d402e13282127cfd6f876c";
	if (sha3(224, "royalty tt yellowstone deficiencies"))
		return -1;

	answer = "803a0ff09dda0df306e483a9f91b20a3dbbf9c2ebb8d0a3b28f3b9e0";
	if (sha3(224, "kdegames-kdiamond tunisisk occurrence's outtalad"))
		return -1;

	answer = "a64779aca943a6aef1d2e7c9a0f4e997f4dabd1f77112a22121d3ed5";
	if (sha3(224, "chevalier slat's spindel representations"))
		return -1;

	answer = "f0a3e0587af7723f0aa4719059d3f5107115a5b3667cd5209cc4d867";
	if (sha3(224, "archery lexicographical equine veered"))
		return -1;

	answer = "312e7e3c6403ab1a086155fb9a52b22a3d0d257876afd2b93fb7272e";
	if (sha3(224, "splay washbasin opposing there"))
		return -1;

	answer = "270ba05b764221ff5b5d94adfb4fdb1f36f07fe7c438904a5f3df071";
	if (sha3(224, "faktum desist thundered klen"))
		return -1;


	answer = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
	if (keccak_bits(256, "\x00", 0))
		return -1;

	answer = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
	if (keccak_bits(256, "\x02", 2))
		return -1;

	answer = "3a1108d4a90a31b85a10bdce77f4bfbdcc5b1d70dd405686f8bbde834aa1a410";
	if (keccak_bits(256, "\x03", 2))
		return -1;

	answer = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";
	if (keccak_bits(256, "\x0F", 4))
		return -1;


	answer = "3a1108d4a90a31b85a10bdce77f4bfbd";
	if (rawshake(256, 128, ""))
		return -1;

	answer = "46b9dd2b0ba88d13233b3feb743eeb24";
	if (rawshake_bits(256, 128, "\x03", 2))
		return -1;

	answer = "46b9dd2b0ba88d13233b3feb743eeb24";
	if (shake(256, 128, ""))
		return -1;


	answer = "65070cdd6f91c0aadcfc470895a2606c828bce7ce3fa723418c9013de92253515713cce8"
	         "d2098be1c82df40b40e375549c0eeb655f92d718f01f147ba1c7c67844c7ba8b11492cd6";
	if (keccak_g(1024, 1600 - 1024, 576, "capitol's kvistfri broadly raping"))
		return -1;

	answer = "65070cdd6f91c0aadcfc470895a2606c828bce7ce3fa723418c9013de92253515713cce8"
	         "d2098be1c82df40b40e375549c0eeb655f92d718f01f147ba1c7c67844c7ba8b11492cd6"
	         "143466958504c110522f772fe746573b1dc905f943ed1ec6ecf858575798596beeca4eb6"
	         "bb7bea635bcea6331315728fb57866370bf1ad5d";
	if (keccak_g(1024, 1600 - 1024, 1024, "capitol's kvistfri broadly raping"))
		return -1;

	answer = "65070cdd6f91c0aadcfc470895a2606c828bce7ce3fa723418c9013de92253515713cce8"
	         "d2098be1c82df40b40e375549c0eeb655f92d718f01f147ba1c7c67844c7ba8b11492cd6"
	         "143466958504c110522f772fe746573b1dc905f943ed1ec6ecf858575798596beeca4eb6"
	         "bb7bea635bcea6331315728fb57866370bf1ad5decbc56d28d47ce53f18376d9f5531551"
	         "7a976d52dd3f98b7025e0b3c513c6d17d40462cddb5406d693bbe859a136af5375b5dd6e"
	         "3478934b00aa6cd44aa7ae2cd0271d83fbab699b";
	if (keccak_g(1024, 1600 - 1024, 1600, "capitol's kvistfri broadly raping"))
		return -1;

	answer = "65070cdd6f91c0aadcfc470895a2606c828bce7ce3fa723418c9013de92253515713cce8"
	         "d2098be1c82df40b40e375549c0eeb655f92d718f01f147ba1c7c67844c7ba8b11492cd6"
	         "143466958504c110522f772fe746573b1dc905f943ed1ec6ecf858575798596beeca4eb6"
	         "bb7bea635bcea6331315728fb57866370bf1ad5decbc56d28d47ce53f18376d9f5531551"
	         "7a976d52dd3f98b7025e0b3c513c6d17d40462cddb5406d693bbe859a136af5375b5dd6e"
	         "3478934b00aa6cd44aa7ae2cd0271d83fbab699b9c";
	if (keccak_g(1024, 1600 - 1024, 1608, "capitol's kvistfri broadly raping"))
		return -1;

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
	if (keccak_g(1024, 1600 - 1024, 3200, "capitol's kvistfri broadly raping"))
		return -1;

	answer = "65070cdd6f91c0aadcfc470895a2606c828bce7ce3fa723418c9013de9225351";
	if (keccak_g(1024, 1600 - 1024, 256, "capitol's kvistfri broadly raping"))
		return -1;

	answer = "e6f86ebc15b962f73f36f36fc8a84c3ae84b1c1023bfd4c5f1829389135aecc3";
	if (keccak_g(512, 1600 - 512, 256, "capitol's kvistfri broadly raping"))
		return -1;

	answer = "420b97fc88962c87ec2adaa8f48d74d9ff4ea7ae7d691f9c33b8713ca1d3d573";
	if (keccak_g(256, 1600 - 256, 256, "capitol's kvistfri broadly raping"))
		return -1;

	answer = "524790afbe4706d938b6f753e14104f556890e2a415e211b0564d60499db0333";
	if (keccak_g(512, 800 - 512, 256, "capitol's kvistfri broadly raping"))
		return -1;

	answer = "04a6b4ad08b3018eefba0fb756272d949ac0f71c26f836d31dd13b28b884aa0f";
	if (keccak_g(256, 800 - 256, 256, "capitol's kvistfri broadly raping"))
		return -1;

	answer = "d56f547791225e54460e6274ed31e57b7085820c11d65f1f322a16a3352c85ed";
	if (keccak_g(256, 400 - 256, 256, "capitol's kvistfri broadly raping"))
		return -1;

	answer = "ceec066a57b9b31a5a0661df7bafec4183a26d0ed81e50bc958471f84fa347a7";
	if (keccak_g(128, 400 - 128, 256, "capitol's kvistfri broadly raping"))
		return -1;

	answer = "b18f679c7105a72a993f70fa5adb3f17ef7ccffaffb4dc0f6fed74aa2f565194";
	if (keccak_g(128, 200 - 128, 256, "capitol's kvistfri broadly raping"))
		return -1;

	answer = "9b845c1ecc2b1b3a48ba42ef29ccc4b348da8ab15074a870d8e799ca33c15e4b";
	if (keccak_g(64, 200 - 64, 256, "capitol's kvistfri broadly raping"))
		return -1;


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
 * Run test cases for `libkeccak_digest`
 * 
 * @return  Zero on success, -1 on error
 */
static int
test_digest_bits(void)
{
#define MSG0 ""
#define MSG5 "\x13" /* 1 1001 */
#define MSG30 "\x53\x58\x7B\x19" /* 1100 1010  0001 1010  1101 1110  10 0110 */
#define MSG1600_32 "\xA3\xA3\xA3\xA3" /* (1100 0101)x4 */
#define MSG1600_160 MSG1600_32 MSG1600_32 MSG1600_32 MSG1600_32 MSG1600_32
#define MSG1600_800 MSG1600_160 MSG1600_160 MSG1600_160 MSG1600_160 MSG1600_160
#define MSG1600 MSG1600_800 MSG1600_800
#define MSG1605 MSG1600_800 MSG1600_800 "\x03"
#define MSG1630 MSG1600_800 MSG1600_800 "\xA3\xA3\xA3\x23"
#define SEQ1600 "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"\
                "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"\
                "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"\
                "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F"\
                "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F"\
                "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F"\
                "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F"\
                "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F"\
                "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F"\
                "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F"\
                "\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF"\
                "\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"\
                "\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7"

#define sha3(output, message, msg_bits)\
	(printf("  Testing SHA3-"#output"(%s:%i): ", #message, msg_bits),\
	 libkeccak_spec_sha3(&spec, output),\
	 test_digest_case(&spec, LIBKECCAK_SHA3_SUFFIX, message, msg_bits / 8, msg_bits % 8, answer))

#define shake(semicapacity, message, msg_bits)\
	(printf("  Testing SHAKE-"#semicapacity"(%s:%i): ", #message, msg_bits),\
	 libkeccak_spec_shake(&spec, semicapacity, (long int)strlen(answer) * 4),\
	 test_digest_case(&spec, LIBKECCAK_SHAKE_SUFFIX, message, msg_bits / 8, msg_bits % 8, answer))

#define cshake(semicapacity, n, s, message, msg_bits)			\
	(printf("  Testing cSHAKE-"#semicapacity"(%s, %s, %s:%i): ", #n, #s, #message, msg_bits),\
	 libkeccak_spec_cshake(&spec, semicapacity, (long int)strlen(answer) * 4),\
	 test_digest_case_cshake(&spec, libkeccak_cshake_suffix(strlen(n), strlen(s)), n, strlen(n), 0, NULL,\
	                         s, strlen(s), 0, NULL, message, msg_bits / 8, msg_bits % 8, answer))


	struct libkeccak_spec spec;
	const char *answer;

	printf("Testing libkeccak_digest with binary input:\n");


	answer = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a68"
	         "6e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2"
	         "badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af"
	         "0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d"
	         "ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c922a96188d032675c8ac850933c7aff15"
	         "33b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b"
	         "1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f1368ec2967fc84ef2ae9aff268e0b170"
	         "0affc6820b523a3d917135f2dff2ee06bfe72b3124721d4a26c04e53a75e30e73a7a9c4a95d91c55d495e9f51dd0b5e9"
	         "d83c6d5e8ce803aa62b8d654db53d09b8dcff273cdfeb573fad8bcd45578bec2e770d01efde86e721a3f7c6cce275dab"
	         "e6e2143f1af18da7efddc4c7b70b5e345db93cc936bea323491ccb38a388f546a9ff00dd4e1300b9b2153d2041d205b4"
	         "43e41b45a653f2a5c4492c1add544512dda2529833462b71a41a45be97290b6f";
	if (shake(128, MSG0, 0))
		return -1;

	answer = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6"
	         "fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853"
	         "349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd943b6aec468a2d62"
	         "1a7c06c6a957c62b54dafc3be87567d677231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5c"
	         "aaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea203bdc970f50ae55428a91f7f53ac266b"
	         "28419c3778a15fd248d339ede785fb7f5a1aaa96d313eacc890936c173cdcd0fab882c45755feb3aed96d477ff96390b"
	         "f9a66d1368b208e21f7c10d04a3dbd4e360633e5db4b602601c14cea737db3dcf722632cc77851cbdde2aaf0a33a07b3"
	         "73445df490cc8fc1e4160ff118378f11f0477de055a81a9eda57a4a2cfb0c83929d310912f729ec6cfa36c6ac6a75837"
	         "143045d791cc85eff5b21932f23861bcf23a52b5da67eaf7baae0f5fb1369db78f3ac45f8c4ac5671d85735cdddb09d2"
	         "b1e34a1fc066ff4a162cb263d6541274ae2fcc865f618abe27c124cd8b074ccd516301b91875824d09958f341ef274bd"
	         "ab0bae316339894304e35877b0c28a9b1fd166c796b9cc258a064a8f57e27f2a";
	if (shake(256, MSG0, 0))
		return -1;


	answer = "ffbad5da96bad71789330206dc6768ecaeb1b32dca6b3301489674ab";
	if (sha3(224, MSG5, 5))
		return -1;

	answer = "7b0047cf5a456882363cbf0fb05322cf65f4b7059a46365e830132e3b5d957af";
	if (sha3(256, MSG5, 5))
		return -1;

	answer = "737c9b491885e9bf7428e792741a7bf8dca9653471c3e148473f2c236b6a0a6455eb1dce9f779b4b6b237fef171b1c64";
	if (sha3(384, MSG5, 5))
		return -1;

	answer = "a13e01494114c09800622a70288c432121ce70039d753cadd2e006e4d961cb27"
	         "544c1481e5814bdceb53be6733d5e099795e5e81918addb058e22a9f24883f37";
	if (sha3(512, MSG5, 5))
		return -1;

	answer = "2e0abfba83e6720bfbc225ff6b7ab9ffce58ba027ee3d898764fef287ddeccca3e6e5998411e7ddb32f67538f500b18c"
	         "8c97c452c370ea2cf0afca3e05de7e4de27fa441a9cb34fd17c978b42d5b7e7f9ab18ffeffc3c5ac2f3a455eebfdc76c"
	         "eaeb0a2cca22eef6e637f4cabe5c51ded2e3fad8b95270a321845664f107d16496bb7abfbe7504b6ede2e89e4b996fb5"
	         "8efdc4181f9163381cbe7bc006a7a205989c526cd1bd68983693b4bdc53728b241c1cff42bb611502c35205cabb28875"
	         "5655d620c67994f06451187f6fd17e046682ba1286063ff88fe2508d1fcaf9035a1231ad4150a9c9b24c9b2d66b2ad1b"
	         "de0bd0bbcb8be05b835229ef7919737323424401e1d837b66eb4e630ff1de70cb317c2bacb08001d3477b7a70a576d20"
	         "869033589d85a01ddb2b6646c043b59fc011311da666fa5ad1d6387fa9bc4015a38a51d1da1ea61d648dc8e39a88b9d6"
	         "22bde207fdabc6f2827a880c330bbf6df733774b653e57305d78dce112f10a2c71f4cdad92ed113e1cea63b91925ed28"
	         "191e6dbbb5aa5a2afda51fc05a3af5258b87665243550f28948ae2b8beb6bc9c770b35f067eaa641efe65b1a44909d1b"
	         "149f97eea601391c609ec81d1930f57c18a4e0fab491d1cadfd50483449edc0f07ffb24d2c6f9a9a3bff39ae3d57f560"
	         "654d7d75c908abe62564753eac39d7503da6d37c2e32e1af3b8aec8ae3069cd9";
	if (shake(128, MSG5, 5))
		return -1;

	answer = "48a5c11abaeeff092f3646ef0d6b3d3ff76c2f55f9c732ac6470c03764008212e21b1467778b181989f88858211b45df"
	         "8799cf961f800dfac99e644039e2979a4016f5456ff421c5b385da2b855da7e31c8c2e8e4ba41eb4095cb999d9759cb4"
	         "0358da8562a2e61349e05a2e13f1b74ec9e69f5b426dc74138ffcdc571c32b39b9f55563e1a99dc422c306026d6a0f9d"
	         "e85162b386794ca0688b764b3d32200cc459749732a0f3a341c0efc96a22c63bad7d96cc9ba4768c6fcfa1f200107cf9"
	         "fae5c0d754958c5a756b376a3be69f88074f200e9e95a8ca5bcf969998db1dc37d0d3d916f6caab3f03782c9c44a2e14"
	         "e80786bece4587b9ef82cbf454e0e34bd175ae57d36af4e726b221332ced36c8ce2e06203c656ae8da037d08e7160b48"
	         "0c1a8516bf06dd97bf4aa4c0249310dc0b065dc639576355384d165c6a509b12f7bbd1e15b22bce02fa048ddfaacf741"
	         "5f49b6324c1d067b5264e1125f7f75427f312bd9346eb4e400b1f7cb31288c9e3f735eca9ced0db888e2e2f402243bd6"
	         "4618a23e10f9c229397440542d0ab1b2e10dacc5c95e597f2c7ea38438105f97803dbb03fcc0fd416b0905a41d184deb"
	         "238905775891f93501fb4176a3bd6c464461d36ee8b008aabd9e26a34055e80c8c813eeba07f728ab32b15605ad161a0"
	         "669f6fce5c5509fbb6afd24aeacc5fa4a51523e6b173246ed4bfa521d74fc6bb";
	if (shake(256, MSG5, 5))
		return -1;


	answer = "d666a514cc9dba25ac1ba69ed3930460deaac9851b5f0baab007df3b";
	if (sha3(224, MSG30, 30))
		return -1;

	answer = "c8242fef409e5ae9d1f1c857ae4dc624b92b19809f62aa8c07411c54a078b1d0";
	if (sha3(256, MSG30, 30))
		return -1;

	answer = "955b4dd1be03261bd76f807a7efd432435c417362811b8a50c564e7ee9585e1ac7626dde2fdc030f876196ea267f08c3";
	if (sha3(384, MSG30, 30))
		return -1;

	answer = "9834c05a11e1c5d3da9c740e1c106d9e590a0e530b6f6aaa7830525d075ca5db"
	         "1bd8a6aa981a28613ac334934a01823cd45f45e49b6d7e6917f2f16778067bab";
	if (sha3(512, MSG30, 30))
		return -1;

	answer = "6d5d39c55f3cca567feaf422dc64ba17401d07756d78b0fa3d546d66afc27671e0010685fc69a7ec3c5367b8fa5fda39"
	         "d57ce53f153fa4031d277206770aec6b2ddf16aefab669110d6e4a296a14fb1486b0846b690543e4057f7f42aa8c0e6a"
	         "5a56b60b688d55a196df6f3976e30688cbb6afd48525d76490357f3fd897bafc8736d907b9bac816591fc24e79360be3"
	         "a7ffa62982c45abb0e584c07ec93a19530509d9f816215d7277bb999437c821450f0759281cd8e16a3483e3cc752091b"
	         "7aae92909d2f501ef7dce989759891b3377ceab493ffe496010a0c7e51959994f56f565e633af6093ac6e1e0f0048871"
	         "ec4778f48ef8bd5bcb80ea7df9ff4711c81e24c0221c2ad9744fba7935eaeca114224fd108efc5ac74c66252089275b4"
	         "277673708c4af92f8813b193599fd64bd7484f2e5ec369e3646499768e581dd053aa4814d8bf1acff5fd774519a749be"
	         "66754741ebc5362212a9fea8a814e9e010bc2720b3b7d94fab74bc7f923e1072b8a5dddda83ba0157d8cba55c192df69"
	         "65cb7dba46a3340df8c3fa89c7c4db539d38dc406f1d2cf54e5905580b4404bfd7b3719561c5a59d5dfdb1bf93df1382"
	         "5225edcce0fa7d87efcd239feb49fc9e2de9d828feeb1f2cf579b95dd050ab2ca47105a8d30f3fd2a1154c15f87fb37b"
	         "2c7156bd7f3cf2b745c912a40bc1b559b656e3e903cc5733e86ba15dfef70678";
	if (shake(128, MSG30, 30))
		return -1;

	answer = "465d081dff875e396200e4481a3e9dcd88d079aa6d66226cb6ba454107cb81a7841ab02960de279ccbe34b42c36585ad"
	         "86964db0db52b6e7b4369ece8f7248589ba78ab1828ffc335cb12397119bfd2b87eb7898aeb956b6f23ddf0bd4004386"
	         "a8e526554ef4e483facee30dd32e204fff8c36bbd602a576d139089c75a8050266fcbf721e4443de4645832922eb8aae"
	         "39d1f572845364817b0033543899940023f2e965a60a80eb221eb19dc57b121291564c6f693583b3ac7c6f272f4f67a1"
	         "9a7678d4234b0bf4a2ebc08aa235b9788db787161f6617022865c0ef9aa533802d136cdbc7aeba532acf1be183b0295a"
	         "b0e33a2ef69be356daaf309687153e2f99a1243609d603126a8c823e8843e459bfc72b30691cdcc3ddb27cf028afd51e"
	         "4437ee3b71c0c1ec87a93436f0c247b7e8c50ce96825c97029997a74c318afacaa18a0180bc7f2f0f1c5e7ef1a2d183a"
	         "c7ee7e4915c3b68c30978ab6c428193441df4705b722ce25a08a1fadca0eef1fafe83adf13021d520de5c827ff9a97b7"
	         "5546193a9b923f0590385dc4bff7c49d4915b5a365db4c84ddcb185de8f9eeb334965a42f1381c8badc22ba1f8ee4c0e"
	         "4daaf7a88e7f42ddb8148f3bf8d3b8d74f098155a37cb4cb27876b85da602e5c789c10e03be73407bab8c49213f8c74e"
	         "1266ce9b11286e674ca9c10c9c9955049a66e9051d9a2b1fc9afe26798e9cec6";
	if (shake(256, MSG30, 30))
		return -1;


	answer = "9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0";
	if (sha3(224, MSG1600, 1600))
		return -1;

	answer = "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787";
	if (sha3(256, MSG1600, 1600))
		return -1;

	answer = "1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd76197a31fd55ee989f2d7050dd473e8f";
	if (sha3(384, MSG1600, 1600))
		return -1;

	answer = "e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca8"
	         "1b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00";
	if (sha3(512, MSG1600, 1600))
		return -1;

	answer = "131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037cf232ef7164a6d1eb448c8908186ad85"
	         "2d3f85a5cf28da1ab6fe3438171978467f1c05d58c7ef38c284c41f6c2221a76f12ab1c04082660250802294fb871802"
	         "13fdef5b0ecb7df50ca1f8555be14d32e10f6edcde892c09424b29f597afc270c904556bfcb47a7d40778d390923642b"
	         "3cbd0579e60908d5a000c1d08b98ef933f806445bf87f8b009ba9e94f7266122ed7ac24e5e266c42a82fa1bbefb7b8db"
	         "0066e16a85e0493f07df4809aec084a593748ac3dde5a6d7aae1e8b6e5352b2d71efbb47d4caeed5e6d633805d2d323e"
	         "6fd81b4684b93a2677d45e7421c2c6aea259b855a698fd7d13477a1fe53e5a4a6197dbec5ce95f505b520bcd9570c4a8"
	         "265a7e01f89c0c002c59bfec6cd4a5c109258953ee5ee70cd577ee217af21fa70178f0946c9bf6ca8751793479f6b537"
	         "737e40b6ed28511d8a2d7e73eb75f8daac912ff906e0ab955b083bac45a8e5e9b744c8506f37e9b4e749a184b30f43eb"
	         "188d855f1b70d71ff3e50c537ac1b0f8974f0fe1a6ad295ba42f6aec74d123a7abedde6e2c0711cab36be5acb1a5a11a"
	         "4b1db08ba6982efccd716929a7741cfc63aa4435e0b69a9063e880795c3dc5ef3272e11c497a91acf699fefee206227a"
	         "44c9fb359fd56ac0a9a75a743cff6862f17d7259ab075216c0699511643b6439";
	if (shake(128, MSG1600, 1600))
		return -1;

	answer = "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d2d700caae7396ece96604440577da4f3"
	         "aa22aeb8857f961c4cd8e06f0ae6610b1048a7f64e1074cd629e85ad7566048efc4fb500b486a3309a8f26724c0ed628"
	         "001a1099422468de726f1061d99eb9e93604d5aa7467d4b1bd6484582a384317d7f47d750b8f5499512bb85a226c4243"
	         "556e696f6bd072c5aa2d9b69730244b56853d16970ad817e213e470618178001c9fb56c54fefa5fee67d2da524bb3b0b"
	         "61ef0e9114a92cdbb6cccb98615cfe76e3510dd88d1cc28ff99287512f24bfafa1a76877b6f37198e3a641c68a7c42d4"
	         "5fa7acc10dae5f3cefb7b735f12d4e589f7a456e78c0f5e4c4471fffa5e4fa0514ae974d8c2648513b5db494cea84715"
	         "6d277ad0e141c24c7839064cd08851bc2e7ca109fd4e251c35bb0a04fb05b364ff8c4d8b59bc303e25328c09a882e952"
	         "518e1a8ae0ff265d61c465896973d7490499dc639fb8502b39456791b1b6ec5bcc5d9ac36a6df622a070d43fed781f5f"
	         "149f7b62675e7d1a4d6dec48c1c7164586eae06a51208c0b791244d307726505c3ad4b26b6822377257aa152037560a7"
	         "39714a3ca79bd605547c9b78dd1f596f2d4f1791bc689a0e9b799a37339c04275733740143ef5d2b58b96a363d4e0807"
	         "6a1a9d7846436e4dca5728b6f760eef0ca92bf0be5615e96959d767197a0beeb";
	if (shake(256, MSG1600, 1600))
		return -1;


	answer = "22d2f7bb0b173fd8c19686f9173166e3ee62738047d7eadd69efb228";
	if (sha3(224, MSG1605, 1605))
		return -1;

	answer = "81ee769bed0950862b1ddded2e84aaa6ab7bfdd3ceaa471be31163d40336363c";
	if (sha3(256, MSG1605, 1605))
		return -1;

	answer = "a31fdbd8d576551c21fb1191b54bda65b6c5fe97f0f4a69103424b43f7fdb835979fdbeae8b3fe16cb82e587381eb624";
	if (sha3(384, MSG1605, 1605))
		return -1;

	answer = "fc4a167ccb31a937d698fde82b04348c9539b28f0c9d3b4505709c03812350e4"
	         "990e9622974f6e575c47861c0d2e638ccfc2023c365bb60a93f528550698786b";
	if (sha3(512, MSG1605, 1605))
		return -1;

	answer = "4ac38ebd1678b4a452792c5673f9777d36b55451aaae2424924942d318a2f6f51bbc837dcc7022c5403b69d29ac99a74"
	         "5f06d06f2a41b0cc243cd270fa44d43065af00d2ad358bd5a5d06d331bc230cd8dda4655628f9102711adafb7636c160"
	         "b2d25ec6235a2fe0f37394d87fc5ffd7dbf1993e558aebea6c61e907188c61f5fcde278e264f958ffd7b3382dc10139b"
	         "625e1241ab5bbc2a1fbcac31a335cfc7b20e427712246cbb55232259a7ef1602bd56f6567d66942d4a7149f4222210b0"
	         "74ea54154b38e8fdfa0dcf4fa3ecd2154e8318a6578b535dbcfc217a3cab52532965846f89781457025563e2dc15cc3a"
	         "f902ba2ad280ffbbbfa4c52b60fa41bac21f4ab23536268119fc98cd982da5cd5da21e1b5692d47105de9f1e0132c6fe"
	         "315d67fa464997c2ab5533c79f98e6e64ff80802a7fe96ca04a81f885527370a2206b10b3936dd81b8246353f4cd9051"
	         "1089268d744f210ac689d49d2875054a727b604d13d269b37190d427c7d15cccdcd7870e0b8adbeb977111a9bcf7781a"
	         "161356a5941c799907ef9d3b1a441f09515f2831c4fafde3dc7c1e9b5aa57d3e83cd6734da3d8b9ef3fc448805ea29c9"
	         "9cba6b352bcabe2fd970ae9580d2bf25152b960e6b806d87d7d0608b247f61089e298692c27f19c52d03ebe395a36806"
	         "ad540bec2d046c18e355faf8313d2ef8995ee6aae42568f314933e3a21e5be40";
	if (shake(128, MSG1605, 1605))
		return -1;

	answer = "98d093b067475760124ffb9204a5b327c6bb05c54ff234f0b43fac7240415166a8c705ea0d739f0808b06576d996662c"
	         "1f376694d98f515719b66407720dcf781c51cd56ef8b610c668ddc1ac1c2c429ea4d6f274aa7a773bf8b0cab306f1eee"
	         "2a171b91334ea0facd2aac1f51d4d5eb0e63a4e6754ecafeec246b7aaf58d0e0a974c7ff4058bdbdedb33ed04b0fa45d"
	         "70c7c84f3da13e4f7d1beddb534d37e5abdfb29f2b44c4fb0d6ccab831d90ba46a00530662f907dedd479e9b5428e5e2"
	         "db8040b0e2b1f174ce347f32a06a5ac22b19aafe927b8878d0c8103a4d2f19e32336c64cfadc1b9acb3978a8298571dc"
	         "d89c36a65692816d0c61ce0ed17942367017bd40f59dfbae34635827920afe7a27bf567009a138403f06b6e4de94da07"
	         "7db49773c235466119426f79888d3a81b407dfeba87e01cd48f90e01b6f90243c40125de47e8c8f3e6ea3388cbfeeb36"
	         "541ef23d2c8348458ea28caa5066f4983776f0cb2fdc66049cf88ac8eae51212aace867bea4c3caee44f147a9bf99d04"
	         "874e8722d03d3f5ff6ef3bebe7642fe4916c5f10ff3fd61387d5d91bcd32f9e8e4593dcaad23eccc05d2fc9be2c1cd63"
	         "0ea123dca9cb6938d60cddedc11e1e9bc9d268a5456ba9ccff18597c5ff9735708413b9d84b9f4721937cc6595712797"
	         "532b48d6f1a2d1723b07d5460bc13916d96e88180713ac33d2c232e35e764e04";
	if (shake(256, MSG1605, 1605))
		return -1;


	answer = "4e907bb1057861f200a599e9d4f85b02d88453bf5b8ace9ac589134c";
	if (sha3(224, MSG1630, 1630))
		return -1;

	answer = "52860aa301214c610d922a6b6cab981ccd06012e54ef689d744021e738b9ed20";
	if (sha3(256, MSG1630, 1630))
		return -1;

	answer = "3485d3b280bd384cf4a777844e94678173055d1cbc40c7c2c3833d9ef12345172d6fcd31923bb8795ac81847d3d8855c";
	if (sha3(384, MSG1630, 1630))
		return -1;

	answer = "cf9a30ac1f1f6ac0916f9fef1919c595debe2ee80c85421210fdf05f1c6af73a"
	         "a9cac881d0f91db6d034a2bbadc1cf7fbcb2ecfa9d191d3a5016fb3fad8709c9";
	if (sha3(512, MSG1630, 1630))
		return -1;

	answer = "89846dc776ac0f014572ea79f560773451002938248e6882569ac32aeab191fcacde68eb07557539c4845fb444108e6e"
	         "0545e731fcca2d4f67a3bfd41cff3eaf35eefb53441177965bb516950cf5dcb2aafcbbc6300e8eefd9bcd0e5f32d1a4e"
	         "872e0f1dbd8f8e00cbb878698c5883e3ca184b9490389e46002c08a0b16b05a36b2cb5a1cae08e11ad972fd24af70101"
	         "ce4746c84f1671877f0df6c415d1670ff40b8ddedd89cc3e656db9058049d609b6784cc9d05e60cc6ac9c8194993ba29"
	         "158fd4db8cf225e9574f18a77f66ec1052bf17993bda206a17737d785bd4c18cee4c76aa5735a5223f3c55e79daec13d"
	         "4bf60f1562e0ad0fa3b558eccfa8ab3eef61474d576e8caf4c11e4de5ccb36d7df7d892c1fca2017be8bbda5a4719544"
	         "8cc67a078e628a2ef763ffe1dc9d9d6ff78e68961c33ffd9000c11dee7f7408d8da5c605b0b4d56bb55e9364c77bfad9"
	         "c8191ed6e1fe7b7a937c6d07095fe5ea91a700b4bdfc17b428d036922aa8ab5e2cd585846fb81fc693b8d59bf85c74bc"
	         "700cd2bc3e6aab437d93d8a30f1cf692efef43602028e0ce5742eb3f4f4d5b029158dd6896acb5e3a7f684d9aa8914e7"
	         "0974b223a6fec38d76c7473e86e4b9b32c621e2015c55e947dd016c675c82368ce26fb456a5b65881af513bfdc88687c"
	         "6381676abbd2d9104ed23a9e89310246b026cedd57595b1ab6fe88a784be0c06";
	if (shake(128, MSG1630, 1630))
		return -1;
	if (cshake(128, "", "", MSG1630, 1630))
		return -1;

	answer = "8a8325079b0fc3265d52f59855cafe655df438aa639f6fec991f2494330ce32fa37f7db90f6966d8e4a46e50c5ede57b"
	         "9b8f082a96627f730475029a619229d84f432ed69fd059234d4d7dd358e8393f6a36a45ccf041f90fc0a4e5802d73063"
	         "d36531336a0090ecfe1a4d4d29aa824ba42b4937b4bb98f4f33a0e3bd8b511e69528d59537110d7521fb78aca018df76"
	         "160f54a3421b84149264ed032f6dce467a731a8e34048e3a46e98039df3c328debfbe5d1bc8be7ff4ef8917b01f0b789"
	         "3672492d6ee5c71df2d0531f8b684764ba0a2b57ec6a4f60ba4f36fe2db0e65ad7aa5f14f3ef9f34a0ab5bc33d488733"
	         "ba36bf4b2b4fce028eff8c6ce03b192cf075cc9f00d29c0e06c35c4489d27f07fa49a91ca92471e34dab7787ae24a6e0"
	         "f309ef0ba53f7c8b2992520a07bedd509a0b6dbea570a5960ed624826dd8ecd1915c87327e74491c405a7411c12c0d44"
	         "97512689bd7f5adbedb02c6d2e68474e8bf31b884040818f4bca03a45217eac7083ad3a33cb8477a04c9e3266a133477"
	         "de45e71830a40eb0d075afccfcd9dc548d0d529460ea7ac2adac722e7678ef597dd3b495bd7d1a8ff39448bbab1dc6a8"
	         "8481801cf5a8010e873c31e479a5e3db3d4e67d1d948e67cc66fd75a4a19c120662ef55977bddbac0721c80d69902693"
	         "c83d5ef7bc27efa393af4c439fc39958e0e75537358802ef0853b7470b0f19ac";
	if (shake(256, MSG1630, 1630))
		return -1;
	if (cshake(256, "", "", MSG1630, 1630))
		return -1;


	answer = "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5";
	if (cshake(128, "", "Email Signature", "\x00\x01\x02\x03", 32))
		return -1;

	answer = "c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b";
	if(cshake(128, "", "Email Signature", SEQ1600, 1600))
		return -1;

	answer = "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd1"
	         "64020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c";
	if (cshake(256, "", "Email Signature", "\x00\x01\x02\x03", 32))
		return -1;

	answer = "07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac864302730917"
	         "27f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb";
	if(cshake(256, "", "Email Signature", SEQ1600, 1600))
		return -1;


	printf("\n");
	return 0;

#undef sha3
#undef shake
#undef cshake
#undef MSG0
#undef MSG5
#undef MSG30
#undef MSG1600_32
#undef MSG1600_160
#undef MSG1600_800
#undef MSG1600
#undef MSG1605
#undef MSG1630
#undef SEQ1600
}


/**
 * Run test cases for `libkeccak_digest` with
 * outputs that are not multiples of 8
 * 
 * @return  Zero on success, -1 on error
 */
static int
test_digest_trunc(void)
{
#define shake(semicapacity, output, output_lastbyte)\
	(printf("  Testing SHAKE-"#semicapacity"('', %i): ", output),\
	 libkeccak_spec_shake(&spec, semicapacity, output),\
	 test_digest_case(&spec, LIBKECCAK_SHAKE_SUFFIX, "", 0, 0, INCOMPLETE_ANSWER output_lastbyte))
#define INCOMPLETE_ANSWER\
	"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a68"\
	"6e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2"\
	"badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af"\
	"0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d"\
	"ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c922a96188d032675c8ac850933c7aff15"\
	"33b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b"\
	"1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f1368ec2967fc84ef2ae9aff268e0b170"\
	"0affc6820b523a3d917135f2dff2ee06bfe72b3124721d4a26c04e53a75e30e73a7a9c4a95d91c55d495e9f51dd0b5e9"\
	"d83c6d5e8ce803aa62b8d654db53d09b8dcff273cdfeb573fad8bcd45578bec2e770d01efde86e721a3f7c6cce275dab"\
	"e6e2143f1af18da7efddc4c7b70b5e345db93cc936bea323491ccb38a388f546a9ff00dd4e1300b9b2153d2041d205b4"\
	"43e41b45a653f2a5c4492c1add544512dda2529833462b71a41a45be97290b"


	struct libkeccak_spec spec;

	printf("Testing libkeccak_digest with byte-incomplete output:\n");


	if (shake(128, 4096, "6f"))
		return -1;

	if (shake(128, 4095, "6f"))
		return -1;

	if (shake(128, 4094, "2f"))
		return -1;

	if (shake(128, 4093, "0f"))
		return -1;

	if (shake(128, 4092, "0f"))
		return -1;

	if (shake(128, 4091, "07"))
		return -1;

	if (shake(128, 4090, "03"))
		return -1;

	if (shake(128, 4089, "01"))
		return -1;

	if (shake(128, 4088, ""))
		return -1;


	printf("\n");
	return 0;

#undef shake
#undef INCOMPLETE_ANSWER
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
static int
test_update_case(const struct libkeccak_spec *restrict spec, const char *restrict suffix,
                 const char *restrict msg, const char *restrict expected_answer)
{
	struct libkeccak_state state;
	unsigned char *restrict hashsum;
	char *restrict hexsum;
	int ok;

	if (libkeccak_state_initialise(&state, spec)) {
		perror("libkeccak_state_initialise");
		return -1;
	}
	hashsum = malloc((size_t)((spec->output + 7) / 8));
	if (!hashsum) {
		perror("malloc");
		return -1;
	}
	hexsum = malloc((size_t)((spec->output + 7) / 8 * 2 + 1));
	if (!hexsum) {
		perror("malloc");
		return -1;
	}

	if (libkeccak_update(&state, msg, strlen(msg))) {
		perror("libkeccak_update");
		return -1;
	}
	if (libkeccak_digest(&state, NULL, 0, 0, suffix, hashsum)) {
		perror("libkeccak_digest");
		return -1;
	}
	libkeccak_state_fast_destroy(&state);

	libkeccak_behex_lower(hexsum, hashsum, (size_t)((spec->output + 7) / 8));
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
static int
test_update(void)
{
#define sha3(output, message)\
	(printf("  Testing SHA3-"#output"(%s): ", #message),\
	 libkeccak_spec_sha3(&spec, output),\
	 test_update_case(&spec, LIBKECCAK_SHA3_SUFFIX, message, answer))

	struct libkeccak_spec spec;
	const char *answer;

	printf("Testing libkeccak_update:\n");


	answer = "22c8017ac8bcf65f59d1b7e92c9d4c6739d25e34ce5cb608b24ff096";
	if (sha3(224, "withdrew hypothesis snakebird qmc2"))
		return -1;

	answer = "43808dde2662143dc4eed5dac5e98c74b06711829f02a3b121bd74f3";
	if (sha3(224, "intensifierat sturdiness perl-image-exiftool vingla"))
		return -1;

	answer = "d32b4ac86065774dee5eb5cdd2f67b4e86501086d7373884e8b20a36";
	if (sha3(224, "timjan avogadro uppdriven lib32-llvm-amdgpu-snapshot"))
		return -1;

	answer = "efbd76d45bfa952485148f8ad46143897f17c27ffdc8eb7287f9353b";
	if (sha3(224, "grilo-plugins auditorium tull dissimilarity's"))
		return -1;

	answer = "6705aa36ecf58f333e0e6364ac1d0b7931d402e13282127cfd6f876c";
	if (sha3(224, "royalty tt yellowstone deficiencies"))
		return -1;

	answer = "803a0ff09dda0df306e483a9f91b20a3dbbf9c2ebb8d0a3b28f3b9e0";
	if (sha3(224, "kdegames-kdiamond tunisisk occurrence's outtalad"))
		return -1;

	answer = "a64779aca943a6aef1d2e7c9a0f4e997f4dabd1f77112a22121d3ed5";
	if (sha3(224, "chevalier slat's spindel representations"))
		return -1;

	answer = "f0a3e0587af7723f0aa4719059d3f5107115a5b3667cd5209cc4d867";
	if (sha3(224, "archery lexicographical equine veered"))
		return -1;

	answer = "312e7e3c6403ab1a086155fb9a52b22a3d0d257876afd2b93fb7272e";
	if (sha3(224, "splay washbasin opposing there"))
		return -1;

	answer = "270ba05b764221ff5b5d94adfb4fdb1f36f07fe7c438904a5f3df071";
	if (sha3(224, "faktum desist thundered klen"))
		return -1;


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
static int
test_squeeze_case(struct libkeccak_state *restrict state, const struct libkeccak_spec *restrict spec,
                  long int fast_squeezes, long int squeezes, int fast_digest, void *restrict hashsum,
                  char *restrict hexsum, const char *restrict expected_answer)
{
#define message "withdrew hypothesis snakebird qmc2"
	long int i;
	int ok;

	libkeccak_state_reset(state);
	if (libkeccak_digest(state, message, strlen(message), 0, LIBKECCAK_SHA3_SUFFIX, fast_digest ? NULL : hashsum)) {
		perror("libkeccak_digest");
		return -1;
	}

	libkeccak_fast_squeeze(state, fast_squeezes);
	for (i = fast_squeezes; i < squeezes; i++)
		libkeccak_squeeze(state, hashsum);

	libkeccak_behex_lower(hexsum, hashsum, (size_t)((spec->output + 7) / 8));
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
static int
test_squeeze(void)
{
#define answer1 "03fe12b4b51d56d96377d927e5cd498fc4bc3aee389b2f2ff8393aa5"
#define answer2 "0b8fb64ee5d8836956f49cbe4577afbc638c855c1d553452fc1eceb8"
#define answer3 "1e03b4cd9eef3892a7b5e865fce393c4bc90120d9aea84d0a0dff3b8"
#define answer4 "aac92fbfd22ce62e83ddaf2e61bd7bf696326e46d1327defa4530e20"

#define run_test(fast_squeezes, squeezes, fast_digest)\
	test_squeeze_case(&state, &spec, fast_squeezes, squeezes, fast_digest, hashsum, hexsum, answer##squeezes)

	struct libkeccak_spec spec;
	struct libkeccak_state state;
	unsigned char *restrict hashsum;
	char *restrict hexsum;

	libkeccak_spec_sha3(&spec, 224);
	hashsum = malloc((size_t)((spec.output + 7) / 8));
	if (!hashsum) {
		perror("malloc");
		return -1;
	}
	hexsum = malloc((size_t)((spec.output + 7) / 8 * 2 + 1));
	if (!hexsum) {
		perror("malloc");
		return -1;
	}
	if (libkeccak_state_initialise(&state, &spec)) {
		perror("libkeccak_state_initialise");
		return -1;
	}

# if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wcomma"
# endif

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

# if defined(__clang__)
#  pragma clang diagnostic pop
# endif

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
static int
test_file(const struct libkeccak_spec *restrict spec, const char *restrict suffix,
          const char *restrict filename, const char *restrict expected_answer)
{
	struct libkeccak_state state;
	unsigned char *restrict hashsum;
	char *restrict hexsum;
	int ok, fd;

	printf("Testing libkeccak_generalised_sum_fd on %s: ", filename);

	hashsum = malloc((size_t)((spec->output + 7) / 8));
	if (!hashsum) {
		perror("malloc");
		return -1;
	}
	hexsum = malloc((size_t)((spec->output + 7) / 8 * 2 + 1));
	if (!hexsum) {
		perror("malloc");
		return -1;
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	if (libkeccak_generalised_sum_fd(fd, &state, spec, suffix, hashsum)) {
		perror("libkeccak_generalised_sum_fd");
		close(fd);
		return -1;
	}

	libkeccak_behex_lower(hexsum, hashsum, (size_t)((spec->output + 7) / 8));
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
int
main(void)
{
	struct libkeccak_generalised_spec gspec;
	struct libkeccak_spec spec;

	libkeccak_generalised_spec_initialise(&gspec);
	if (libkeccak_degeneralise_spec(&gspec, &spec)) {
		printf("libkeccak_degeneralise_spec failed with all members at automatic.\n");
		return 1;
	}

	printf("Resolution of default specification:\n");
	printf("  bitrate:    %li\n", gspec.bitrate);
	printf("  capacity:   %li\n", gspec.capacity);
	printf("  output:     %li\n", gspec.output);
	printf("  state size: %li\n", gspec.state_size);
	printf("  word size:  %li\n", gspec.word_size);

	if (gspec.word_size * 25 != gspec.state_size ||
	    gspec.bitrate + gspec.capacity != gspec.state_size) {
		printf("Invalid information\n");
		return 1;
	}
	if (gspec.state_size != 1600 ||
	    gspec.bitrate != gspec.output * 2 ||
	    gspec.output != 512) {
		printf("Incorrect information\n");
		return 1;
	}
	printf("\n");

	if (test_hex() ||
	    test_state(&spec) ||
	    test_digest() ||
	    test_digest_bits() ||
	    test_digest_trunc() ||
	    test_update() ||
	    test_squeeze())
		return 1;

	if (test_file(&spec, LIBKECCAK_SHA3_SUFFIX, ".testfile",
	              "a95484492e9ade0f1d28f872d197ff45d891e85e78f918643f41d524c5d6ab0f"
	              "17974dc08ec82870b132612dcbeb062213bf594881dc764d6078865a7c694c57"))
		return 1;
  
	return 0;
}
