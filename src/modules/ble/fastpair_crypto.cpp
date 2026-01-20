#include "fastpair_crypto.h"
#include <esp_timer.h>
#include <Arduino.h>

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
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi d;
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    
    int ret = mbedtls_ecdh_gen_public(&grp, &d, &Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    if(ret != 0) {
        mbedtls_ecp_group_free(&grp);
        mbedtls_mpi_free(&d);
        mbedtls_ecp_point_free(&Q);
        return false;
    }
    
    *pub_len = 65;
    public_key[0] = 0x04;
    size_t olen;
    ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &olen, public_key, *pub_len);
    
    mbedtls_mpi_copy(&ecdh_ctx.d, &d);
    mbedtls_ecp_copy(&ecdh_ctx.Q, &Q);
    mbedtls_ecp_group_copy(&ecdh_ctx.grp, &grp);
    
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    
    return ret == 0;
}

bool FastPairCrypto::computeSharedSecret(const uint8_t* peer_public, size_t peer_len) {
    mbedtls_ecp_point peer_point;
    mbedtls_ecp_point_init(&peer_point);
    
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    
    int ret = mbedtls_ecp_point_read_binary(&grp, &peer_point, peer_public, peer_len);
    if(ret != 0) {
        mbedtls_ecp_point_free(&peer_point);
        mbedtls_ecp_group_free(&grp);
        return false;
    }
    
    mbedtls_mpi z;
    mbedtls_mpi_init(&z);
    
    ret = mbedtls_ecdh_compute_shared(&grp, &z, &peer_point, &ecdh_ctx.d,
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
    
    mbedtls_mpi_copy(&ecdh_ctx.z, &z);
    
    mbedtls_ecp_point_free(&peer_point);
    mbedtls_mpi_free(&z);
    mbedtls_ecp_group_free(&grp);
    
    return ret == 0;
}

bool FastPairCrypto::deriveFastPairKeys(const uint8_t* nonce, size_t nonce_len) {
    if(nonce_len != 16) return false;
    
    uint8_t input[64];
    memcpy(input, nonce, 16);
    
    size_t z_len = 32;
    uint8_t z_buf[32];
    mbedtls_mpi_write_binary(&ecdh_ctx.z, z_buf, z_len);
    memcpy(&input[16], z_buf, 32);
    
    uint8_t derived[32];
    mbedtls_aes_setkey_enc(&aes_ctx, &input[16], 256);
    
    size_t nc_off = 0;
    uint8_t stream_block[16] = {0};
    uint8_t counter[16] = {0};
    
    int ret = mbedtls_aes_crypt_ctr(&aes_ctx, 32, &nc_off, counter, 
                                   stream_block, input, derived);
    
    if(ret != 0) return false;
    
    memcpy(account_key, derived, 16);
    return true;
}

void FastPairCrypto::encryptCTR(uint8_t* data, size_t len, const uint8_t* key, const uint8_t* nonce) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key, 128);
    
    size_t nc_off = 0;
    uint8_t stream_block[16] = {0};
    uint8_t counter[16];
    memcpy(counter, nonce, 16);
    
    mbedtls_aes_crypt_ctr(&ctx, len, &nc_off, counter, stream_block, data, data);
    
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
    size_t pub_len = 65;
    if(!generateKeyPair(pub_key, &pub_len)) {
        Serial.println("[Crypto] Key gen failed");
        return;
    }
    
    uint64_t keygen_time = esp_timer_get_time() - start;
    Serial.printf("[Crypto] ECDH Key Gen: %.2f ms\n", keygen_time / 1000.0);
    
    start = esp_timer_get_time();
    if(!computeSharedSecret(pub_key, pub_len)) {
        Serial.println("[Crypto] Shared secret failed");
        return;
    }
    
    uint64_t secret_time = esp_timer_get_time() - start;
    Serial.printf("[Crypto] Shared Secret: %.2f ms\n", secret_time / 1000.0);
    
    Serial.printf("[Crypto] Total: %.2f ms\n", (keygen_time + secret_time) / 1000.0);
    Serial.printf("[Crypto] Free Heap: %ld bytes\n", ESP.getFreeHeap());
}
