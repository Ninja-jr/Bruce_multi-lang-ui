#pragma once
#include <Arduino.h>
#include <NimBLEDevice.h>

class AudioCommandService {
private:
    NimBLEServer* pServer;
    NimBLEService* pAudioService;
    NimBLECharacteristic* pCmdCharacteristic;
    bool isConnected;

public:
    AudioCommandService();
    void start();
    void stop();
    void injectCommand(const uint8_t* cmd, size_t len);
    bool isDeviceConnected();
};

class AudioToneGenerator {
private:
    int buzzerPin;
    
public:
    AudioToneGenerator(int pin = 25);
    void playTone(int freq, int duration);
    void playSimpsonsTheme();
    void playAlertTone();
    void playSuccessTone();
    void playErrorTone();
};

void audioCommandHijackTest();