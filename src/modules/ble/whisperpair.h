#pragma once

#include <NimBLEDevice.h>
#include <NimBLEServer.h>
#include <NimBLEUtils.h>
#include <NimBLEAdvertisedDevice.h>
#include <NimBLEBeacon.h>
#include <NimBLEScan.h>

#include <Arduino.h>
#include <MenuItemInterface.h>
#include "core/display.h"
#include <functional>
#include <vector>

extern int loopOptions(std::vector<Option>& options, uint8_t type, const char* title, int index, bool interpreter);
bool initBLEIfNeeded(const char* deviceName = "whisperpair");
bool requireSimpleConfirmation(const char* message);
void testFastPairVulnerability();
String selectTargetFromScan(const char* title);
void whisperPairMenu();
NimBLEAddress parseAddress(const String& addressInfo);
bool whisperPairEfficientExploit(NimBLEAddress target);
bool attemptProtocolExploit(NimBLEAddress target);
bool bruteForceCharacteristics(NimBLEAddress target);
void maxVolumeAttack(NimBLEAddress target);
void forcePlayCommand(NimBLEAddress target);
void runAnnoyanceAttackSuite(NimBLEAddress target);
void simpsonsAttack(NimBLEAddress target);
void audioAnnoyanceMenu();
void jamAndConnectMenu();
int8_t showAdaptiveMessage(const char* line1, const char* btn1 = "", const char* btn2 = "", const char* btn3 = "", uint16_t color = TFT_WHITE, bool showEscHint = true, bool autoProgress = false);
void showErrorMessage(const char* message);
void showSuccessMessage(const char* message);
void showWarningMessage(const char* message);
bool check(uint8_t key);
extern struct BruceConfig bruceConfig;
extern volatile int tftWidth;

void diagnoseConnection(NimBLEAddress target);
bool connectWithRetry(NimBLEAddress target, int maxRetries, NimBLEClient** outClient);
void testConnectionDiagnostic();
void audioCommandHijackTest();
void showDeviceInfoScreen(const char* title, const std::vector<String>& lines, uint16_t bgColor = TFT_BLACK, uint16_t textColor = TFT_WHITE);