#include "whisperpair_scan.h"
#include <globals.h>
#include "core/display.h"
#include "core/mykeyboard.h"
#include <vector>

std::vector<BLE_Device> foundDevices;
bool scanning = false;
uint32_t scanStartTime = 0;
uint32_t scanDuration = 10000;

class ScanCallbacks : public NimBLEScanCallbacks {
    void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
        BLE_Device device;
        device.address = advertisedDevice->getAddress().toString();
        device.name = advertisedDevice->getName();
        device.rssi = advertisedDevice->getRSSI();

        if(device.name.empty()) {
            device.name = "Unknown";
        }

        bool exists = false;
        for(auto& dev : foundDevices) {
            if(dev.address == device.address) {
                exists = true;
                dev.rssi = device.rssi;
                break;
            }
        }

        if(!exists) {
            foundDevices.push_back(device);
        }
    }

    void onScanEnd(NimBLEScanResults results) {
        scanning = false;
    }
};

void startBLEScan() {
    if(scanning) return;

    foundDevices.clear();
    NimBLEDevice::init("");

    NimBLEScan* pScan = NimBLEDevice::getScan();
    pScan->setScanCallbacks(new ScanCallbacks(), false);
    pScan->setActiveScan(true);
    pScan->setInterval(97);
    pScan->setWindow(37);
    pScan->setMaxResults(0);

    scanning = true;
    scanStartTime = millis();
    pScan->start(scanDuration / 1000, false);
}

void testSelectedDevice(String mac) {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("TESTING DEVICE");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);

    padprintln("Testing: " + mac);
    padprintln("");

    NimBLEAddress target(mac.c_str(), BLE_ADDR_RANDOM);

    bool vulnerable = attemptKeyBasedPairing(target);

    if(vulnerable) {
        displayMessage("VULNERABLE!", "Device is vulnerable", "", "", TFT_GREEN);
    } else {
        displayMessage("PATCHED/SAFE", "Device may be patched", "", "", TFT_YELLOW);
    }
}

void displayScanResults() {
    if(foundDevices.empty()) {
        displayMessage("NO DEVICES", "Found 0 devices", "", "", TFT_YELLOW);
        return;
    }

    int currentIndex = 0;
    bool redraw = true;

    while(true) {
        if(redraw) {
            tft.fillScreen(bruceConfig.bgColor);
            drawMainBorderWithTitle("BLE DEVICES");
            tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);

            padprintln("Found: " + String(foundDevices.size()));
            padprintln("Device " + String(currentIndex + 1) + "/" + String(foundDevices.size()));
            padprintln("");

            if(currentIndex < foundDevices.size()) {
                BLE_Device& dev = foundDevices[currentIndex];
                padprintln("Name: " + String(dev.name.c_str()));
                padprintln("MAC: " + String(dev.address.c_str()));
                padprintln("RSSI: " + String(dev.rssi) + " dBm");
            }

            padprintln("");
            padprintln("←/→: Navigate");
            padprintln("SEL: Test device");
            padprintln("ESC: Back");

            redraw = false;
        }

        delay(50);

        if(check(PrevPress)) {
            if(currentIndex > 0) {
                currentIndex--;
                redraw = true;
            }
        } else if(check(NextPress)) {
            if(currentIndex < foundDevices.size() - 1) {
                currentIndex++;
                redraw = true;
            }
        } else if(check(SelPress)) {
            if(currentIndex < foundDevices.size()) {
                String selectedMAC = String(foundDevices[currentIndex].address.c_str());
                testSelectedDevice(selectedMAC);
                redraw = true;
            }
        } else if(check(EscPress)) {
            break;
        }
    }
}

void whisperPairScanMenu() {
    startBLEScan();

    while(scanning) {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("SCANNING");
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);

        uint32_t elapsed = millis() - scanStartTime;
        uint32_t remaining = (scanDuration > elapsed) ? scanDuration - elapsed : 0;

        padprintln("Found: " + String(foundDevices.size()));
        padprintln("Time: " + String(remaining / 1000) + "s");
        padprintln("");
        padprintln("Scanning for BLE devices...");

        int progress = (elapsed * 100) / scanDuration;
        if(progress > 100) progress = 100;

        tft.fillRect(20, 140, tftWidth - 40, 10, TFT_DARKGREY);
        tft.fillRect(20, 140, ((tftWidth - 40) * progress) / 100, 10, TFT_GREEN);

        delay(100);
    }

    displayScanResults();
}