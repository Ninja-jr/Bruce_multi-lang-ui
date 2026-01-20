#pragma once
#include <NimBLEDevice.h>

bool passiveFastPairScan(uint32_t scanTime = 30);
void displayFastPairResults();
void whisperPairFullBenchmark();
bool whisperPairFullExploit(NimBLEAddress target);
