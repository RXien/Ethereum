#include "libkeccak.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(){
        libkeccak_spec_t spec;
        const char *answer;
libkeccak_spec_sha3(&spec, 256);

printf("%i",spec.bitrate);

//keccak(256, "");
	

}
