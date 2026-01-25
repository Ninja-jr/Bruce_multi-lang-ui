#include "fastpair_crypto.h"
#include <mbedtls/entropy.h>
#include <mbedtls/ecdh.h>
#include "esp_random.h"

FastPairCrypto::FastPairCrypto() {
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);
    
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                         (const uint8_t*)"fastpair", 8);
    
    mbedtls_entropy_free(&entropy);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
}

FastPairCrypto::~FastPairCrypto() {
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ctr_drbg_free(&ctr_drbg);
}

bool FastPairCrypto::generateValidKeyPair(uint8_t* public_key, size_t* pub_len) {
    int ret = mbedtls_ecdh_gen_public(&grp, &d, &Q, 
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
    if(ret != 0) {
        Serial.printf("[Crypto] Key gen failed: -0x%04X\n", -ret);
        return false;
    }
    
    if(*pub_len >= 65) {
        size_t olen;
        ret = mbedtls_ecp_point_write_binary(&grp, &Q, 
                                            MBEDTLS_ECP_PF_UNCOMPRESSED,
                                            &olen, public_key, *pub_len);
        if(ret == 0 && olen == 65) {
            *pub_len = 65;
            return true;
        }
    }
    
    return false;
}

void FastPairCrypto::generatePlausibleSharedSecret(const uint8_t* their_pubkey, uint8_t* output) {
    if(looksLikeValidPublicKey(their_pubkey, 65)) {
        esp_fill_random(output, 32);
        for(int i = 0; i < 32; i += 8) {
            if(output[i] >= 0x80) output[i] &= 0x7F;
        }
    } else {
        esp_fill_random(output, 32);
    }
}

void FastPairCrypto::generatePlausibleAccountKey(const uint8_t* nonce, uint8_t* output) {
    uint8_t buffer[64];
    memcpy(buffer, nonce, 16);
    esp_fill_random(&buffer[16], 32);
    memcpy(&buffer[48], "account_key", 11);
    buffer[59] = 0x00;
    
    for(int i = 0; i < 16; i++) {
        output[i] = 0;
        for(int j = 0; j < 4; j++) {
            output[i] ^= buffer[i * 4 + j];
        }
        output[i] = (output[i] ^ 0x36) + 0x5C;
    }
}

void FastPairCrypto::generateValidNonce(uint8_t* nonce) {
    uint32_t time_part = millis();
    memcpy(nonce, &time_part, 4);
    esp_fill_random(&nonce[4], 4);
    
    for(int i = 8; i < 16; i++) {
        nonce[i] = esp_random() & 0xFF;
        if(i == 8) nonce[i] |= 0x80;
    }
}

bool FastPairCrypto::looksLikeValidPublicKey(const uint8_t* key, size_t len) {
    if(len != 65) return false;
    if(key[0] != 0x04) return false;
    return (key[1] < 0xFF && key[33] < 0xFF);
}

void FastPairCrypto::hexDump(const char* label, const uint8_t* data, size_t len) {
    Serial.printf("[Crypto] %s: ", label);
    for(size_t i = 0; i < len; i++) {
        if(data[i] < 0x10) Serial.print("0");
        Serial.print(data[i], HEX);
    }
    Serial.println();
}