#include "libkeccak.h"
#include "stdio.h"

char*
test_digest_case(const libkeccak_spec_t *restrict spec, const char *restrict suffix,
                 const char *restrict msg, long bits)
{
	libkeccak_state_t state;
	char *restrict hashsum;
	char *restrict hexsum;
	int ok;
	if (libkeccak_state_initialise(&state, spec))
		return perror("libkeccak_state_initialise"), "-1";
	if (hashsum = malloc((spec->output + 7) / 8), hashsum == NULL)
		return perror("malloc"), "-1";
	if (hexsum = malloc((spec->output + 7) / 8 * 2 + 1), hexsum == NULL)
		return perror("malloc"), "-1";
	if (libkeccak_digest(&state, msg, strlen(msg) - !!bits, bits, suffix, hashsum))
		return perror("libkeccak_digest"), "-1";
	libkeccak_state_fast_destroy(&state);
	libkeccak_behex_lower(hexsum, hashsum, (spec->output + 7) / 8);
	static char ptr[100];
        sprintf (ptr, "%s", hexsum);

	free(hashsum);
	free(hexsum);
	return ptr;
}



static char* test_digest(char * msg)
{
#define keccak(output, message)\
	 (libkeccak_spec_sha3(&spec, output) ,\
	 test_digest_case(&spec, "", message, 0))

#define keccak_bits(output, message, bits)\
	(libkeccak_spec_sha3(&spec, output),\
	 test_digest_case(&spec, "", message, bits))
        char key[32] =
        {0x01,0x02};

	libkeccak_spec_t spec;
	char* bo;
	char *result;
	//bo = keccak(256, msg);
	//bo = keccak_bits(256, "\x02", 2);
        bo = keccak_bits(256, key/*"\x01\x02"*/, 0);
	if(bo== "-1"){
		return "-1";
	}
	//printf("%s\n",bo);
	return bo;
#undef keccak
}


int main(void)
{
	char digest_re[64];
	char digest_msg[200]="e2018609184e72a000822710940000000000000000000000000000000000000009077f";
	sprintf(digest_re,"%s",test_digest(digest_msg));
	printf("%s\n",digest_re);
}
