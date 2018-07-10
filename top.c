

#include <stdio.h>
#include <string.h>
#include "RLP/utils.c"
#include "RLP/RLP.c"
#include "libkeccak.h"
#include "stdio.h"

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

void strToByteslen(const char * str,char* msgr,int l){

        char msg[l];
        int strlen = l;
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
        memcpy(msgr,msg,l);
}


char*
test_digest_case(const libkeccak_spec_t *restrict spec, const char *restrict suffix,
                 const char *restrict msg, long bits,int len)
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
//printf("%i\n",len);
	if (libkeccak_digest(&state, msg, len/*strlen(msg)*/ - !!bits, bits, suffix, hashsum))
		return perror("libkeccak_digest"), "-1";
	libkeccak_state_fast_destroy(&state);
	libkeccak_behex_lower(hexsum, hashsum, (spec->output + 7) / 8);
	static char ptr[100];
        sprintf (ptr, "%s", hexsum);

	free(hashsum);
	free(hexsum);
	return ptr;
}



static char* test_digest(char * msg,int len)
{
#define keccak(output, message,len)\
	 (libkeccak_spec_sha3(&spec, output) ,\
	 test_digest_case(&spec, "", message, 0,len))

#define keccak_bits(output, message, bits,len)\
	(libkeccak_spec_sha3(&spec, output),\
	 test_digest_case(&spec, "", message, bits,len))

	libkeccak_spec_t spec;
	char* bo;
	char *result;
        bo = keccak_bits(256, msg/*"\x01\x02"*/, 0,len);
	if(bo== "-1"){
		return "-1";
	}
	return bo;
#undef keccak
}




struct RawtxStruct{
    const char *nonce;
    const char *gas_price;
    const char *gas_limit;
    const char *to;
    const char *value;
    const char *data;
    const char *r;
    const char *s;
    uint32_t v;
	
};

int wallet_ethereum_assemble_tx(EthereumSignTx *msg, EthereumSig *tx, uint64_t *rawTx) {
    EncodeEthereumSignTx new_msg;
    EncodeEthereumTxRequest new_tx;
    memset(&new_msg, 0, sizeof(new_msg));
    memset(&new_tx, 0, sizeof(new_tx));
    wallet_encode_element(msg->nonce.bytes, msg->nonce.size,
                          new_msg.nonce.bytes, &(new_msg.nonce.size), false);
    wallet_encode_element(msg->gas_price.bytes, msg->gas_price.size,
                          new_msg.gas_price.bytes, &(new_msg.gas_price.size), false);
    wallet_encode_element(msg->gas_limit.bytes, msg->gas_limit.size,
                          new_msg.gas_limit.bytes, &(new_msg.gas_limit.size), false);
    wallet_encode_element(msg->to.bytes, msg->to.size, new_msg.to.bytes,
                          &(new_msg.to.size), false);
    wallet_encode_element(msg->value.bytes, msg->value.size,
                          new_msg.value.bytes, &(new_msg.value.size), false);
    wallet_encode_element(msg->data_initial_chunk.bytes,
                          msg->data_initial_chunk.size, new_msg.data_initial_chunk.bytes,
                          &(new_msg.data_initial_chunk.size), false);
    wallet_encode_int(tx->signature_v, &(new_tx.signature_v));
    wallet_encode_element(tx->signature_r.bytes, tx->signature_r.size,
                          new_tx.signature_r.bytes, &(new_tx.signature_r.size), true);
    wallet_encode_element(tx->signature_s.bytes, tx->signature_s.size,
                          new_tx.signature_s.bytes, &(new_tx.signature_s.size), true);
    int length = wallet_encode_list(&new_msg, &new_tx, rawTx);
    //printf("%x",data_initial_chunk.bytes);
    return length;
}

int wallet_ethereum_assemble_tx_s(EthereumSignTx *msg, EthereumSig *tx, uint64_t *rawTx) {
    EncodeEthereumSignTx new_msg;
    EncodeEthereumTxRequest new_tx;
    memset(&new_msg, 0, sizeof(new_msg));
    memset(&new_tx, 0, sizeof(new_tx));
    wallet_encode_element(msg->nonce.bytes, msg->nonce.size,
                          new_msg.nonce.bytes, &(new_msg.nonce.size), false);
    wallet_encode_element(msg->gas_price.bytes, msg->gas_price.size,
                          new_msg.gas_price.bytes, &(new_msg.gas_price.size), false);
    wallet_encode_element(msg->gas_limit.bytes, msg->gas_limit.size,
                          new_msg.gas_limit.bytes, &(new_msg.gas_limit.size), false);
    wallet_encode_element(msg->to.bytes, msg->to.size, new_msg.to.bytes,
                          &(new_msg.to.size), false);
    wallet_encode_element(msg->value.bytes, msg->value.size,
                          new_msg.value.bytes, &(new_msg.value.size), false);
    wallet_encode_element(msg->data_initial_chunk.bytes,
                          msg->data_initial_chunk.size, new_msg.data_initial_chunk.bytes,
                          &(new_msg.data_initial_chunk.size), false);
/*
    wallet_encode_int(tx->signature_v, &(new_tx.signature_v));
    wallet_encode_element(tx->signature_r.bytes, tx->signature_r.size,
                          new_tx.signature_r.bytes, &(new_tx.signature_r.size), true);
    wallet_encode_element(tx->signature_s.bytes, tx->signature_s.size,
                          new_tx.signature_s.bytes, &(new_tx.signature_s.size), true);
*/
    int length = wallet_encode_list_s(&new_msg, &new_tx, rawTx);
    //printf("%x",data_initial_chunk.bytes);
    return length;
}

void assembleTx(struct RawtxStruct txParam,int type, char * rlpre) {
    static char rawTx[256];
    EthereumSignTx tx;
    EthereumSig signature;
    uint64_t raw_tx_bytes[24];

    const char *nonce = txParam.nonce;
    const char *gas_price = txParam.gas_price;
    const char *gas_limit = txParam.gas_limit;
    const char *to = txParam.to;
    const char *value = txParam.value;
    const char *data = txParam.data;
    const char *r = txParam.r;
    const char *s = txParam.s;
    uint32_t v = txParam.v;

    tx.nonce.size = size_of_bytes(strlen(nonce));
    hex2byte_arr(nonce, strlen(nonce), tx.nonce.bytes, tx.nonce.size);
    tx.gas_price.size = size_of_bytes(strlen(gas_price));
    hex2byte_arr(gas_price, strlen(gas_price), tx.gas_price.bytes, tx.gas_price.size);
    tx.gas_limit.size = size_of_bytes(strlen(gas_limit));
    hex2byte_arr(gas_limit, strlen(gas_limit), tx.gas_limit.bytes, tx.gas_limit.size);
    tx.to.size = size_of_bytes(strlen(to));
    hex2byte_arr(to, strlen(to), tx.to.bytes, tx.to.size);
    tx.value.size = size_of_bytes(strlen(value));
    hex2byte_arr(value, strlen(value), tx.value.bytes, tx.value.size);
    tx.data_initial_chunk.size = size_of_bytes(strlen(data));
    hex2byte_arr(data, strlen(data), tx.data_initial_chunk.bytes,
                 tx.data_initial_chunk.size);
    signature.signature_v = 27;
    signature.signature_r.size = size_of_bytes(strlen(r));
    hex2byte_arr(r, strlen(r), signature.signature_r.bytes, signature.signature_r.size);
    signature.signature_s.size = size_of_bytes(strlen(s));
    hex2byte_arr(s, strlen(s), signature.signature_s.bytes, signature.signature_s.size);
    int length;
    if (type ==1 ){    
	length = wallet_ethereum_assemble_tx(&tx, &signature, raw_tx_bytes);}
    else if (type ==2 ){ 
	length = wallet_ethereum_assemble_tx_s(&tx, &signature, raw_tx_bytes);}
    //printf("%i",raw_tx_bytes);
    //int length = 110;
    int8_to_char((uint8_t *) raw_tx_bytes, length, rawTx);
    sprintf(rlpre,"%s", rawTx);
}

void top(char *keys,struct RawtxStruct txS) {
	char rlpre[200];
	assembleTx(txS,2,rlpre);
	printf("RLP:%s\n",rlpre);
	char rlpy[200];
        char digest_re[64];
	int len = strlen(rlpre)/2;
	strToByteslen(rlpre,rlpy,len);
	printf("%s\n",rlpy);
        sprintf(digest_re,"%s",test_digest(rlpy,len));
        printf("keccak:%s\n",digest_re);
	char msgy[32];
        const char *msgs = digest_re;
        char keyy[32];
	unsigned char re[128];
	strToBytes(msgs,msgy);
	strToBytes(keys,keyy);
	bytesToSecp256(keyy,msgy,re);
	printf("sec:%s\n",re);
	char rResult[65];
	strncpy(rResult,re,64);
	rResult[64] = 0;
        char sResult[65];
        strncpy(sResult,re+64,64);
        sResult[64] = 0;
	txS.r = rResult;
	txS.s = sResult;
	char rlpre2[3000];
	assembleTx(txS,1,rlpre2);
	printf("%s\n",rlpre2);
}

int main(){
        char *keys = "0000000000000000000000000000000000000000000000000000000000000001";
        struct RawtxStruct txS;
        txS.nonce = "01";
        txS.gas_price = "9184e72a000";
        txS.gas_limit = "2710";
        txS.to = "0000000000000000000000000000000000000009";
        txS.value = "7";
        txS.data = "7f";
        txS.r = "";
        txS.s = "";
        txS.v = 27;
	top(keys,txS);
}



