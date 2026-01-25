#include "whisperpair_audio.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include <globals.h>
#include "driver/ledc.h"

AudioCommandService::AudioCommandService() : pServer(nullptr), pAudioService(nullptr), pCmdCharacteristic(nullptr), isConnected(false) {}

void AudioCommandService::start() {
    NimBLEDevice::init("Audio-Injector");
    pServer = NimBLEDevice::createServer();
    pServer->setCallbacks(new class: public NimBLEServerCallbacks {
        void onConnect(NimBLEServer* pServer) { isConnected = true; }
        void onDisconnect(NimBLEServer* pServer) { isConnected = false; }
    });
    
    pAudioService = pServer->createService("AUDIO1234-5678-9012-3456-789012345678");
    pCmdCharacteristic = pAudioService->createCharacteristic(
        "CMD1234-5678-9012-3456-789012345678",
        NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR
    );
    
    pAudioService->start();
    NimBLEAdvertising* pAdvertising = NimBLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(pAudioService->getUUID());
    pAdvertising->start();
}

void AudioCommandService::stop() {
    if(pServer) {
        NimBLEDevice::deinit(true);
    }
}

void AudioCommandService::injectCommand(const uint8_t* cmd, size_t len) {
    if(pCmdCharacteristic && isConnected) {
        pCmdCharacteristic->setValue(cmd, len);
    }
}

bool AudioCommandService::isDeviceConnected() {
    return isConnected;
}

AudioToneGenerator::AudioToneGenerator(int pin) : buzzerPin(pin) {
    pinMode(buzzerPin, OUTPUT);
    ledcSetup(0, 2000, 8);
    ledcAttachPin(buzzerPin, 0);
}

void AudioToneGenerator::playTone(int freq, int duration) {
    ledcWriteTone(0, freq);
    delay(duration);
    ledcWrite(0, 0);
}

void AudioToneGenerator::playSimpsonsTheme() {
    int melody[] = {
        392, 330, 294, 262, 294, 330, 392, 392, 392,
        440, 392, 349, 330, 349, 392, 440, 440,
        494, 440, 392, 349, 392, 440, 494, 494,
        523, 494, 440, 392, 440, 494, 523, 523
    };
    
    int durations[] = {
        300, 300, 300, 300, 300, 300, 600, 300, 300,
        300, 300, 300, 300, 300, 600, 300, 300,
        300, 300, 300, 300, 300, 600, 300, 300,
        300, 300, 300, 300, 300, 600, 600, 600
    };
    
    for(int i = 0; i < 32; i++) {
        playTone(melody[i], durations[i]);
        delay(50);
    }
}

void AudioToneGenerator::playAlertTone() {
    playTone(1000, 200);
    delay(100);
    playTone(1500, 200);
    delay(100);
    playTone(1000, 200);
}

void AudioToneGenerator::playSuccessTone() {
    playTone(2000, 100);
    delay(50);
    playTone(2500, 100);
}

void AudioToneGenerator::playErrorTone() {
    playTone(300, 500);
}

void audioCommandHijackTest() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("AUDIO HIJACK");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("1. Start audio service");
    tft.setCursor(20, 90);
    tft.print("2. Connect target device");
    tft.setCursor(20, 120);
    tft.print("3. Inject audio commands");
    tft.setCursor(20, 160);
    tft.print("SEL: Start  ESC: Back");
    while(true) {
        if(check(EscPress)) return;
        if(check(SelPress)) break;
        delay(50);
    }
    showAdaptiveMessage("Starting audio service...", "", "", "", TFT_WHITE, false, true);
    AudioCommandService audioCmd;
    audioCmd.start();
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("AUDIO INJECTION");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Service: RUNNING");
    tft.setCursor(20, 90);
    tft.print("Waiting for connection...");
    tft.setCursor(20, 120);
    tft.print("Connected: ");
    tft.setCursor(120, 120);
    if(audioCmd.isDeviceConnected()) {
        tft.print("YES");
    } else {
        tft.print("NO");
    }
    tft.setCursor(20, 160);
    tft.print("SEL: Inject  ESC: Stop");
    unsigned long startTime = millis();
    while(millis() - startTime < 30000) {
        if(check(EscPress)) {
            audioCmd.stop();
            showAdaptiveMessage("Service stopped", "OK", "", "", TFT_WHITE);
            return;
        }
        if(check(SelPress)) {
            if(audioCmd.isDeviceConnected()) {
                uint8_t volume_up[] = {0x01, 0x00, 0x00, 0x00};
                audioCmd.injectCommand(volume_up, 4);
                showAdaptiveMessage("Volume up sent!", "", "", "", TFT_GREEN, false, true);
                delay(500);
                uint8_t play_pause[] = {0x02, 0x00, 0x00, 0x00};
                audioCmd.injectCommand(play_pause, 4);
                showAdaptiveMessage("Play/Pause sent!", "", "", "", TFT_GREEN, false, true);
                delay(500);
                uint8_t next_track[] = {0x03, 0x00, 0x00, 0x00};
                audioCmd.injectCommand(next_track, 4);
                showAdaptiveMessage("Next track sent!", "", "", "", TFT_GREEN, false, true);
                delay(500);
            } else {
                showErrorMessage("No device connected!");
                delay(1000);
            }
        }
        delay(100);
    }
    audioCmd.stop();
    showAdaptiveMessage("Timeout - service stopped", "OK", "", "", TFT_WHITE);
}