/*
 * Copyright (c) 2016-2018, Evercoin. All Rights Reserved.
 */

#include <stdio.h>
#include <string.h>
#include "RLP/utils.c"
#include "RLP/RLP.c"

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

void assembleTx(struct RawtxStruct txParam,int type) {
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
    printf("raw transaction: %s\n", rawTx);
}

int main() {
    struct RawtxStruct txS;
    txS.nonce = "01";
    txS.gas_price = "9184e72a000";
    txS.gas_limit = "2710";
    txS.to = "0000000000000000000000000000000000000009";
    txS.value = "7";
    txS.data = "7f";
    txS.r = "60a88658e28e9e30fe9648dddae040cc5e07bc84fd38c721a3d5bc2bebc91b26";
    txS.s = "697801e06992ab9b630a3d083b0f382b1bd6499d26e1445b1a57b2dfb666aad6";
    txS.v = 27;

    assembleTx(txS,2);
    return 0;
}
