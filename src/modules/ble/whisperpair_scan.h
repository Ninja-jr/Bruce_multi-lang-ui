#pragma once
#include <Arduino.h>
#include <NimBLEDevice.h>

bool attemptKeyBasedPairing(NimBLEAddress target);

struct BLE_Device {
    std::string address;
    std::string name;
    int rssi;
};

void whisperPairScanMenu();