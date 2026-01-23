#pragma once
#include <Arduino.h>
#include <BLEDevice.h>
#include <MenuItemInterface.h>
#include <functional>
#include <vector>
extern int loopOptions(std::vector<Option>& options, uint8_t type, const char* title, int index, bool interpreter);
bool initBLEIfNeeded(const char* deviceName = "whisperpair");
bool requireSimpleConfirmation(const char* message);
void testFastPairVulnerability();
bool attemptKeyBasedPairing(BLEAddress target);
String selectTargetFromScan(const char* title);
void whisperPairMenu();
bool fastpair_ecdh_key_exchange(BLEAddress target, uint8_t* shared_secret);
bool fastpair_complete_pairing(BLEAddress target, const uint8_t* shared_secret);
bool whisperPairFullExploit(BLEAddress target);
void updateScanDisplay(uint32_t foundCount, uint32_t elapsedMs, bool forceRedraw = false);