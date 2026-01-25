#pragma once
#include <Arduino.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ctr_drbg.h>

class FastPairCrypto {
private:
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_ctr_drbg_context ctr_drbg;
    uint8_t shared_secret[32];

public:
    FastPairCrypto();
    ~FastPairCrypto();
    
    bool generateValidKeyPair(uint8_t* public_key, size_t* pub_len);
    void generatePlausibleSharedSecret(const uint8_t* their_pubkey, uint8_t* output);
    void generatePlausibleAccountKey(const uint8_t* nonce, uint8_t* output);
    void generateValidNonce(uint8_t* nonce);
    bool looksLikeValidPublicKey(const uint8_t* key, size_t len);
    void hexDump(const char* label, const uint8_t* data, size_t len);
};