#pragma once
#include <mbedtls/ecdh.h>
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <Arduino.h>

class FastPairCrypto {
private:
    mbedtls_ecdh_context ecdh_ctx;
    mbedtls_aes_context aes_ctx;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    
    uint8_t shared_secret[32];
    uint8_t account_key[16];
    
public:
    FastPairCrypto();
    ~FastPairCrypto();
    
    bool generateKeyPair(uint8_t* public_key, size_t* pub_len);
    bool computeSharedSecret(const uint8_t* peer_public, size_t peer_len);
    bool deriveFastPairKeys(const uint8_t* nonce, size_t nonce_len);
    
    void encryptCTR(uint8_t* data, size_t len, const uint8_t* key, const uint8_t* nonce);
    void decryptCTR(uint8_t* data, size_t len, const uint8_t* key, const uint8_t* nonce);
    
    void generateAccountKey();
    const uint8_t* getAccountKey() { return account_key; }
    const uint8_t* getSharedSecret() { return shared_secret; }
    
    void benchmark();
};
