#pragma once
#include <Arduino.h>
#include <NimBLEDevice.h>
#include <functional>
#include <vector>

extern void drawMainBorderWithTitle(const char* title);
extern void padprintln(const String& text);
extern void displayMessage(const char* line1, const char* line2, const char* line3, const char* line4, uint32_t duration);
extern bool check(int button);
extern String keyboard(const char* initial, uint8_t maxLength, const char* prompt);
extern void loopOptions(const std::vector<Option>& options, MenuType type, const char* title);

bool requireButtonHoldConfirmation(const char* message, uint32_t ms = 3000);
void testFastPairVulnerability();
bool attemptKeyBasedPairing(NimBLEAddress target);
void whisperPairMenu();
void whisperPairFullBenchmark();
bool whisperPairFullExploit(NimBLEAddress target);