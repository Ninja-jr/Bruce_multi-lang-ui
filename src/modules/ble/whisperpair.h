#pragma once
#include <Arduino.h>
#include <NimBLEDevice.h>
#include <MenuItemInterface.h>
#include <functional>
#include <vector>

extern int loopOptions(std::vector<Option>& options, uint8_t type, const char* title, int index, bool interpreter);

bool requireSimpleConfirmation(const char* message);
void testFastPairVulnerability();
bool attemptKeyBasedPairing(NimBLEAddress target);
void whisperPairMenu();
void whisperPairFullBenchmark();
bool whisperPairFullExploit(NimBLEAddress target);