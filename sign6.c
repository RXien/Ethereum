#include "secp256k1/include/secp256k1.h"
#include <stdio.h>
#include <string.h>


char bytesToSecp256(char* key,char* msg,unsigned char *re){
    secp256k1_context *ctx;
    secp256k1_ecdsa_signature signature;
    unsigned char rands[64];
    unsigned int i;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_sign(ctx, &signature, msg, key, NULL, NULL);
    secp256k1_ecdsa_signature_serialize_compact(ctx, rands, &signature);

    for (i=0; i<64; i++){
	unsigned char tmp[2];
        sprintf(tmp,"%02x", rands[i]);
	strcat(re,tmp);
	}
    secp256k1_context_destroy(ctx);
}

void strToBytes(const char * str,char* msgr){

        char msg[32];
        int strlen = 32;
        int i;
        for (i =0;i< strlen;i++){
                char * tmp1;
                char * tmp2;
                char ptr[2];
                char ptr2[2];
                char re[2];
                strcpy(re,"");
                sprintf(ptr,"%c",str[2*i]);
                sprintf(ptr2,"%c",str[2*i+1]);
                strcat(re,ptr);
                strcat(re,ptr2);
                sscanf(re,"%2hhx",&msg[i]);
        }
	memcpy(msgr,msg,32);
}


int main()
{
	char key[32] =
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

	char msg[32] =
        {0x06, 0xef, 0x2b, 0x19, 0x3b, 0x83, 0xb3, 0xd7,
         0x01, 0xf7, 0x65, 0xf1, 0xdb, 0x34, 0x67, 0x2a,
         0xb8, 0x48, 0x97, 0xe1, 0x25, 0x23, 0x43, 0xcc,
         0x21, 0x97, 0x82, 0x9a, 0xf3, 0xa3, 0x04, 0x56};

	char msgy[32];
        const char *msgs = "06ef2b193b83b3d701f765f1db34672ab84897e1252343cc2197829af3a30456";
        char keyy[32];
        const char *keys = "0000000000000000000000000000000000000000000000000000000000000001";

	unsigned char re[128];
	strToBytes(msgs,msgy);
	strToBytes(keys,keyy);

	bytesToSecp256(keyy,msgy,re);
	printf("%s\n",re);
}


