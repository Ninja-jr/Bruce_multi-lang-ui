#pragma once

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <vector>
#include "fastpair_crypto.h"

class BLEAttackManager {
private:
    bool wasScanning = false;
    bool isInAttackMode = false;
    
public:
    void prepareForConnection();
    void cleanupAfterAttack();
    bool connectToDevice(NimBLEAddress target, NimBLEClient** outClient);
};

class WhisperPairExploit {
private:
    FastPairCrypto crypto;
    BLEAttackManager bleManager;
    
    bool performHandshake(NimBLERemoteCharacteristic* kbpChar);
    bool sendExploitPayload(NimBLERemoteCharacteristic* kbpChar);
    bool testForVulnerability(NimBLERemoteCharacteristic* kbpChar);
    NimBLERemoteCharacteristic* findKBPCharacteristic(NimBLERemoteService* fastpairService);
    
public:
    WhisperPairExploit() = default;
    
    bool execute(NimBLEAddress target);
    bool executeSilent(NimBLEAddress target);
};

class AudioAttackService {
private:
    bool findAndAttackAudioServices(NimBLEClient* pClient);
    bool attackAVRCP(NimBLERemoteService* avrcpService);
    bool attackAudioMedia(NimBLERemoteService* mediaService);
    bool attackTelephony(NimBLERemoteService* teleService);
    
public:
    bool executeAudioAttack(NimBLEAddress target);
    bool injectMediaCommands(NimBLEAddress target);
    bool crashAudioStack(NimBLEAddress target);
};

void whisperPairMenu();
void showAttackProgress(const char* message, uint32_t color = TFT_YELLOW);
void showAttackResult(bool success, const char* message = nullptr);
bool confirmAttack(const char* targetName);
void runWhisperPairAttack();
void runAudioHijackTest();
void runAudioStackCrash();
void runMediaCommandHijack();
void runQuickTest();