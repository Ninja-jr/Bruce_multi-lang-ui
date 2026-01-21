#include "fastpair_crypto.h"
#include <esp_timer.h>
#include <Arduino.h>

FastPairCrypto::FastPairCrypto() {
    mbedtls_ecdh_init(&ecdh_ctx);
    mbedtls_aes_init(&aes_ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_ecp_group_init(&ecdh_grp);
    mbedtls_mpi_init(&ecdh_d);
    mbedtls_ecp_point_init(&ecdh_Q);
    mbedtls_mpi_init(&ecdh_z);
    const char* pers = "fastpair_crypto";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                         (const uint8_t*)pers, strlen(pers));
}

FastPairCrypto::~FastPairCrypto() {
    mbedtls_ecdh_free(&ecdh_ctx);
    mbedtls_aes_free(&aes_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_ecp_group_free(&ecdh_grp);
    mbedtls_mpi_free(&ecdh_d);
    mbedtls_ecp_point_free(&ecdh_Q);
    mbedtls_mpi_free(&ecdh_z);
}

bool FastPairCrypto::generateKeyPair(uint8_t* public_key, size_t* pub_len) {
    mbedtls_ecp_group_load(&ecdh_grp, MBEDTLS_ECP_DP_SECP256R1);
    int ret = mbedtls_ecdh_gen_public(&ecdh_grp, &ecdh_d, &ecdh_Q, 
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
    if(ret != 0) return false;
    *pub_len = 65;
    public_key[0] = 0x04;
    size_t olen;
    ret = mbedtls_ecp_point_write_binary(&ecdh_grp, &ecdh_Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &olen, public_key, *pub_len);
    return ret == 0;
}

bool FastPairCrypto::computeSharedSecret(const uint8_t* peer_public, size_t peer_len) {
    mbedtls_ecp_point peer_point;
    mbedtls_ecp_point_init(&peer_point);
    int ret = mbedtls_ecp_point_read_binary(&ecdh_grp, &peer_point, peer_public, peer_len);
    if(ret != 0) {
        mbedtls_ecp_point_free(&peer_point);
        return false;
    }
    ret = mbedtls_ecdh_compute_shared(&ecdh_grp, &ecdh_z, &peer_point, &ecdh_d,
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_mpi_write_binary(&ecdh_z, shared_secret, 32);
    mbedtls_ecp_point_free(&peer_point);
    return ret == 0;
}

bool FastPairCrypto::deriveFastPairKeys(const uint8_t* nonce, size_t nonce_len) {
    if(nonce_len != 16) return false;
    uint8_t input[64];
    memcpy(input, nonce, 16);
    memcpy(&input[16], shared_secret, 32);
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

const uint8_t* FastPairCrypto::getSharedSecret() {
    mbedtls_mpi_write_binary(&ecdh_z, shared_secret, 32);
    return shared_secret;
}

void FastPairCrypto::generateAccountKey() {
    mbedtls_ctr_drbg_random(&ctr_drbg, account_key, 16);
}

void FastPairCrypto::benchmark() {
}