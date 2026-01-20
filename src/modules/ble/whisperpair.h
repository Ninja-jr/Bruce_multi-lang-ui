#pragma once
#include <Arduino.h>
#include <NimBLEDevice.h>

bool requireButtonHoldConfirmation(const char* message, uint32_t ms = 3000);
void testFastPairVulnerability();
bool attemptKeyBasedPairing(NimBLEAddress target);
void whisperPairMenu();
void whisperPairFullBenchmark();
bool whisperPairFullExploit(NimBLEAddress target);
