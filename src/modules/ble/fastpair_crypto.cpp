#include "fastpair_crypto.h"
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/ccm.h>
#include <esp_timer.h>
#include <Arduino.h>

FastPairCrypto::FastPairCrypto() {
    mbedtls_ecdh_init(&ecdh_ctx);
    mbedtls_ccm_init(&ccm_ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    
    const char* pers = "fastpair_exploit";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                         (const uint8_t*)pers, strlen(pers));
    
    memset(shared_secret, 0, 32);
    memset(account_key, 0, 16);
}

FastPairCrypto::~FastPairCrypto() {
    mbedtls_ecdh_free(&ecdh_ctx);
    mbedtls_ccm_free(&ccm_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

bool FastPairCrypto::generateKeyPair(uint8_t* public_key, size_t* pub_len) {
    int ret = mbedtls_ecdh_gen_public(&ecdh_ctx, MBEDTLS_ECP_DP_SECP256R1,
                                      mbedtls_ctr_drbg_random, &ctr_drbg,
                                      public_key, *pub_len, pub_len);
    return ret == 0;
}

bool FastPairCrypto::computeSharedSecret(const uint8_t* peer_public, size_t peer_len) {
    int ret = mbedtls_ecdh_compute_shared(&ecdh_ctx, MBEDTLS_ECP_DP_SECP256R1,
                                          shared_secret, 32,
                                          peer_public, peer_len,
                                          mbedtls_ctr_drbg_random, &ctr_drbg);
    return ret == 0;
}

bool FastPairCrypto::deriveFastPairKeys(const uint8_t* nonce, size_t nonce_len) {
    if(nonce_len != 16) return false;
    
    // FastPair HKDF-SHA256
    const uint8_t salt[] = "Fast Pairing";  // 11 bytes
    const size_t salt_len = 11;
    
    // Info = Nonce || "account_key" || 0x00 || 0x10 0x00 0x00 0x00
    uint8_t info[32];
    memcpy(info, nonce, 16);
    memcpy(info + 16, "account_key", 11);
    info[27] = 0x00;
    info[28] = 0x10;  // Output length = 16 bytes
    info[29] = 0x00;
    info[30] = 0x00;
    info[31] = 0x00;
    
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    
    int ret = mbedtls_hkdf(md_info, 
                          salt, salt_len,
                          shared_secret, 32,
                          info, 32,
                          account_key, 16);
    
    if(ret != 0) {
        Serial.println("[Crypto] HKDF failed, using fallback");
        memcpy(account_key, shared_secret, 16);
    }
    
    return true;
}

void FastPairCrypto::encryptCCM(uint8_t* data, size_t len, 
                               const uint8_t* key, const uint8_t* nonce,
                               const uint8_t* add, size_t add_len,
                               uint8_t* tag) {
    mbedtls_ccm_setkey(&ccm_ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
    
    uint8_t output[256];
    mbedtls_ccm_encrypt_and_tag(&ccm_ctx, len, nonce, 13,
                                add, add_len, data, output, tag, 8);
    
    memcpy(data, output, len);
}

void FastPairCrypto::decryptCCM(uint8_t* data, size_t len,
                               const uint8_t* key, const uint8_t* nonce,
                               const uint8_t* add, size_t add_len,
                               const uint8_t* tag) {
    mbedtls_ccm_setkey(&ccm_ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
    
    uint8_t output[256];
    mbedtls_ccm_auth_decrypt(&ccm_ctx, len, nonce, 13,
                             add, add_len, data, output, tag, 8);
    
    memcpy(data, output, len);
}

void FastPairCrypto::encryptCTR(uint8_t* data, size_t len, 
                               const uint8_t* key, const uint8_t* nonce) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);
    
    size_t nc_off = 0;
    uint8_t stream_block[16] = {0};
    uint8_t counter[16];
    memcpy(counter, nonce, 16);
    
    mbedtls_aes_crypt_ctr(&ctx, len, &nc_off, counter, 
                         stream_block, data, data);
    mbedtls_aes_free(&ctx);
}

void FastPairCrypto::decryptCTR(uint8_t* data, size_t len,
                               const uint8_t* key, const uint8_t* nonce) {
    encryptCTR(data, len, key, nonce);
}

const uint8_t* FastPairCrypto::getSharedSecret() {
    return shared_secret;
}

void FastPairCrypto::generateAccountKey() {
    mbedtls_ctr_drbg_random(&ctr_drbg, account_key, 16);
}

void FastPairCrypto::benchmark() {
    uint64_t start = esp_timer_get_time();
    
    uint8_t pub[65];
    size_t pub_len = 65;
    generateKeyPair(pub, &pub_len);
    
    uint64_t end = esp_timer_get_time();
    Serial.printf("[Crypto] Key gen: %llu us\n", end - start);
}