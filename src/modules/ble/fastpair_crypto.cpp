#include "fastpair_crypto.h"
#include <esp_timer.h>

FastPairCrypto::FastPairCrypto() {
    mbedtls_ecdh_init(&ecdh_ctx);
    mbedtls_aes_init(&aes_ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    
    const char* pers = "fastpair_crypto";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                         (const uint8_t*)pers, strlen(pers));
}

FastPairCrypto::~FastPairCrypto() {
    mbedtls_ecdh_free(&ecdh_ctx);
    mbedtls_aes_free(&aes_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

bool FastPairCrypto::generateKeyPair(uint8_t* public_key, size_t* pub_len) {
    int ret = mbedtls_ecdh_gen_public(&ecdh_ctx, 
                                      MBEDTLS_ECP_DP_SECP256R1,
                                      mbedtls_ctr_drbg_random, 
                                      &ctr_drbg);
    return ret == 0;
}

bool FastPairCrypto::computeSharedSecret(const uint8_t* peer_public, size_t peer_len) {
    mbedtls_ecp_point peer_point;
    mbedtls_ecp_point_init(&peer_point);
    
    int ret = mbedtls_ecp_point_read_binary(&ecdh_ctx.grp, &peer_point, 
                                           peer_public, peer_len);
    if(ret != 0) {
        mbedtls_ecp_point_free(&peer_point);
        return false;
    }
    
    ret = mbedtls_ecdh_get_params(&ecdh_ctx, MBEDTLS_ECDH_THEIRS, &peer_point);
    mbedtls_ecp_point_free(&peer_point);
    if(ret != 0) return false;
    
    size_t olen;
    ret = mbedtls_ecdh_calc_secret(&ecdh_ctx, &olen, 
                                   shared_secret, sizeof(shared_secret),
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
    return ret == 0 && olen == 32;
}

bool FastPairCrypto::deriveFastPairKeys(const uint8_t* nonce, size_t nonce_len) {
    uint8_t input[64];
    if(nonce_len != 16) return false;
    
    memcpy(input, nonce, 16);
    memcpy(input + 16, shared_secret, 32);
    
    uint8_t derived[32];
    mbedtls_aes_setkey_enc(&aes_ctx, shared_secret, 256);
    
    uint8_t counter[16] = {0};
    mbedtls_aes_crypt_ctr(&aes_ctx, 32, counter, input, derived);
    
    memcpy(account_key, derived, 16);
    return true;
}

void FastPairCrypto::encryptCTR(uint8_t* data, size_t len, const uint8_t* key, const uint8_t* nonce) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);
    
    uint8_t counter[16];
    memcpy(counter, nonce, 16);
    mbedtls_aes_crypt_ctr(&ctx, len, counter, data, data);
    
    mbedtls_aes_free(&ctx);
}

void FastPairCrypto::decryptCTR(uint8_t* data, size_t len, const uint8_t* key, const uint8_t* nonce) {
    encryptCTR(data, len, key, nonce);
}

void FastPairCrypto::generateAccountKey() {
    mbedtls_ctr_drbg_random(&ctr_drbg, account_key, 16);
}

void FastPairCrypto::benchmark() {
    uint64_t start = esp_timer_get_time();
    
    uint8_t pub_key[65];
    size_t pub_len = 0;
    generateKeyPair(pub_key, &pub_len);
    
    uint64_t keygen_time = esp_timer_get_time() - start;
    Serial.printf("[Crypto] ECDH Key Gen: %.2f ms\n", keygen_time / 1000.0);
    
    start = esp_timer_get_time();
    computeSharedSecret(pub_key, pub_len);
    uint64_t secret_time = esp_timer_get_time() - start;
    Serial.printf("[Crypto] Shared Secret: %.2f ms\n", secret_time / 1000.0);
    
    Serial.printf("[Crypto] Total: %.2f ms\n", (keygen_time + secret_time) / 1000.0);
    Serial.printf("[Crypto] Free Heap: %d bytes\n", ESP.getFreeHeap());
}
