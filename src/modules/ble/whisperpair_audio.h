#pragma once
#include <NimBLEDevice.h>

bool requireButtonHoldConfirmation(const char* message, uint32_t ms = 3000);

class AudioCommandService {
private:
    NimBLEServer* pServer;
    NimBLEService* pService;
    NimBLECharacteristic* pAudioCmdChar;
    NimBLECharacteristic* pAudioDataChar;
    bool isRunning = false;
    
    class AudioCmdCallbacks : public NimBLECharacteristicCallbacks {
        void onWrite(NimBLECharacteristic* pCharacteristic);
    };
    
public:
    void begin();
    void sendAudioCommand(const char* cmd);
    void sendAudioTone(uint8_t frequency, uint16_t duration_ms);
    void stop();
    bool isActive() { return isRunning; }
};

extern AudioCommandService audioCmd;
bool attemptAudioCommandHijack(NimBLEAddress target);
void audioCommandHijackTest();