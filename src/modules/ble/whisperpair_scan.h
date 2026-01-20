#pragma once
#include <Arduino.h>
#include <NimBLEDevice.h>

struct BLE_Device {
    std::string address;
    std::string name;
    int rssi;
};

void whisperPairScanMenu();