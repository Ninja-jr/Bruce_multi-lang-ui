#include "whisperpair_debug.h"
#include "whisperpair.h"
#include "fastpair_crypto.h"
#include <globals.h>
#include "core/display.h"
#include "core/mykeyboard.h"

extern FastPairCrypto crypto;

class DebugScanCallbacks : public NimBLEScanCallbacks {
public:
    std::vector<BLE_Device> devices;
    
    void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
        if(!advertisedDevice) return;
        
        std::string address = advertisedDevice->getAddress().toString();
        std::string name = advertisedDevice->getName();
        int rssi = advertisedDevice->getRSSI();
        
        if(name.empty()) name = "<no name>";
        
        Serial.printf("[DEBUG SCAN] Found: %s - %s (%d dBm)\n", 
            address.c_str(), name.c_str(), rssi);
        Serial.printf("  Address Type: %d\n", advertisedDevice->getAddressType());
        
        if(advertisedDevice->haveAppearance()) {
            Serial.printf("  Appearance: 0x%04X\n", advertisedDevice->getAppearance());
        }
        
        std::string mfgData = advertisedDevice->getManufacturerData();
        if(!mfgData.empty()) {
            Serial.printf("  Manufacturer data length: %d\n", mfgData.length());
            Serial.print("  Manufacturer data: ");
            for(size_t i = 0; i < mfgData.length() && i < 20; i++) {
                Serial.printf("%02X ", (uint8_t)mfgData[i]);
            }
            Serial.println();
            if(mfgData.length() >= 2) {
                uint16_t companyId = (mfgData[1] << 8) | mfgData[0];
                Serial.printf("  Company ID: 0x%04X\n", companyId);
                if(companyId == 0x00E0) {
                    Serial.println("  *** FASTPAIR DEVICE DETECTED ***");
                }
            }
        }
        
        NimBLEUUID serviceUUID = advertisedDevice->getServiceUUID();
        if(serviceUUID) {
            Serial.printf("  Service UUID: %s\n", serviceUUID.toString().c_str());
        }
        
        Serial.println();
        
        bool exists = false;
        for(auto& dev : devices) {
            if(dev.address == address) {
                exists = true;
                dev.rssi = rssi;
                break;
            }
        }
        
        if(!exists) {
            BLE_Device device;
            device.address = address;
            device.name = name;
            device.rssi = rssi;
            devices.push_back(device);
        }
    }
    
    void onScanEnd(NimBLEScanResults results) {
        Serial.printf("[DEBUG SCAN] Scan ended. Found %d unique devices\n", devices.size());
    }
    
    void clear() {
        devices.clear();
    }
};

void testBleScanWithSettings(int interval, int window, bool active) {
    Serial.printf("\n=== TEST SCAN: interval=%d, window=%d, active=%d ===\n", 
                  interval, window, active);
    
    DebugScanCallbacks debugCallbacks;
    debugCallbacks.clear();
    
    NimBLEDevice::deinit(true);
    delay(1000);
    
    NimBLEDevice::init("debug_scan");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    
    NimBLEScan* pScan = NimBLEDevice::getScan();
    pScan->setActiveScan(active);
    pScan->setInterval(interval);
    pScan->setWindow(window);
    pScan->setDuplicateFilter(false);
    pScan->setScanCallbacks(&debugCallbacks, false);
    
    Serial.println("Starting 5 second scan...");
    if(pScan->start(5, true)) {
        Serial.printf("Scan complete. Found %d devices:\n", debugCallbacks.devices.size());
        for(auto& dev : debugCallbacks.devices) {
            Serial.printf("  %s - %s (%d dBm)\n", 
                dev.address.c_str(), dev.name.c_str(), dev.rssi);
        }
    } else {
        Serial.println("Scan failed to start!");
    }
    
    pScan->clearResults();
    NimBLEDevice::deinit(true);
}

void runScanDebugTests() {
    Serial.println("\n=== STARTING SCAN DEBUG TESTS ===");
    
    testBleScanWithSettings(100, 50, true);
    delay(1000);
    testBleScanWithSettings(50, 30, true);
    delay(1000);
    testBleScanWithSettings(150, 75, true);
    delay(1000);
    testBleScanWithSettings(100, 50, false);
    delay(1000);
    testBleScanWithSettings(67, 33, true);
    delay(1000);
    testBleScanWithSettings(200, 100, true);
}

void printBLEInfo() {
    Serial.println("\n=== SYSTEM INFO ===");
    Serial.printf("Free Heap: %lu\n", ESP.getFreeHeap());
    Serial.printf("Free PSRAM: %lu\n", ESP.getFreePsram());
    Serial.printf("CPU Freq: %lu MHz\n", ESP.getCpuFreqMHz());
    Serial.println("===================\n");
}

void bleHardwareTest() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("BLE HARDWARE TEST");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    
    tft.setCursor(20, 60);
    tft.print("Testing NimBLE hardware...");
    
    bool nimbleWorks = false;
    
    try {
        NimBLEDevice::init("test");
        tft.setCursor(20, 80);
        tft.print("NimBLE: INIT OK");
        nimbleWorks = true;
        NimBLEDevice::deinit(true);
    } catch(...) {
        tft.setCursor(20, 80);
        tft.print("NimBLE: INIT FAILED");
    }
    
    if (nimbleWorks) {
        tft.setCursor(20, 100);
        tft.print("Status: WORKING");
    } else {
        tft.setCursor(20, 100);
        tft.print("Status: FAILED");
    }
    
    tft.setCursor(20, 140);
    tft.print("Press any key");
    while(!check(AnyKeyPress)) delay(50);
}

void testBasicBLEScanner() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("BASIC BLE TEST");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    
    tft.setCursor(20, 60);
    tft.print("Starting basic scan...");
    
    Serial.println("\n=== BASIC BLE SCANNER TEST ===");
    
    NimBLEDevice::deinit(true);
    delay(500);
    
    NimBLEDevice::init("test");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    
    NimBLEScan* scan = NimBLEDevice::getScan();
    scan->setActiveScan(true);
    scan->setInterval(50);
    scan->setWindow(30);
    scan->setDuplicateFilter(false);
    
    tft.setCursor(20, 80);
    tft.print("Scanning 5 seconds...");
    
    if (scan->start(5, true)) {
        NimBLEScanResults results = scan->getResults();
        tft.setCursor(20, 100);
        tft.print("Found: " + String(results.getCount()));
        
        Serial.printf("Found %d devices:\n", results.getCount());
        
        for(int i = 0; i < results.getCount(); i++) {
            const NimBLEAdvertisedDevice* device = results.getDevice(i);
            if (device) {
                Serial.printf("  %s - %s (RSSI: %d)\n",
                    device->getAddress().toString().c_str(),
                    device->getName().c_str(),
                    device->getRSSI());
                
                if (i < 3) {
                    tft.setCursor(20, 120 + (i * 20));
                    String addr = device->getAddress().toString().c_str();
                    if (addr.length() > 12) addr = addr.substring(0, 12);
                    tft.print(addr + " " + String(device->getRSSI()) + "dB");
                }
            }
        }
        scan->clearResults();
    } else {
        tft.setCursor(20, 100);
        tft.print("Scan failed!");
        Serial.println("Scan failed!");
    }
    
    NimBLEDevice::deinit(true);
    
    tft.setCursor(20, 200);
    tft.print("Press any key");
    while(!check(AnyKeyPress)) delay(50);
}

void testBLEScanner() {
    Serial.println("\n[DEBUG] Starting BLE scanner test...");
    
    initNimBLEIfNeeded("debug_scanner");
    
    NimBLEScan* scan = NimBLEDevice::getScan();
    if (!scan) {
        Serial.println("[DEBUG] Failed to get scanner!");
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("BLE SCANNER TEST");
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, 60);
        tft.print("Scanner init failed!");
        tft.setCursor(20, 80);
        tft.print("Press any key");
        while(!check(AnyKeyPress)) delay(50);
        return;
    }
    
    scan->setActiveScan(true);
    scan->setInterval(98);
    scan->setWindow(48);
    scan->setDuplicateFilter(false);
    
    Serial.println("[DEBUG] Scanning for 3 seconds...");
    
    tft.fillScreen(bruceConfig.bgColor);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 20);
    tft.print("BLE SCANNER TEST");
    tft.setCursor(20, 50);
    tft.print("Scanning...");
    
    if (scan->start(3, true)) {
        NimBLEScanResults results = scan->getResults();
        
        tft.fillScreen(bruceConfig.bgColor);
        tft.setCursor(20, 20);
        tft.print("BLE SCANNER TEST");
        
        if (results.getCount() > 0) {
            tft.setCursor(20, 50);
            tft.print("Found: " + String(results.getCount()));
            
            for(int i = 0; i < min(results.getCount(), 6); i++) {
                const NimBLEAdvertisedDevice* device = results.getDevice(i);
                if (device) {
                    tft.setCursor(20, 70 + (i * 20));
                    String addr = device->getAddress().toString().c_str();
                    if (addr.length() > 12) addr = addr.substring(0, 12);
                    tft.print(addr + " " + String(device->getRSSI()) + "dB");
                }
            }
        } else {
            tft.setCursor(20, 50);
            tft.print("No devices found");
        }
    } else {
        tft.fillScreen(bruceConfig.bgColor);
        tft.setCursor(20, 20);
        tft.print("BLE SCANNER TEST");
        tft.setCursor(20, 50);
        tft.print("Scan failed!");
    }
    
    tft.setCursor(20, 200);
    tft.print("Press any key");
    
    scan->clearResults();
    
    while(!check(AnyKeyPress)) delay(50);
}

void testBLEConnection() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("BLE CONNECTION TEST");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Testing BLE connection...");
    tft.setCursor(20, 80);
    tft.print("");
    tft.setCursor(20, 100);
    tft.print("NimBLE ready");
    tft.setCursor(20, 120);
    tft.print("Heap: " + String(ESP.getFreeHeap()));
    tft.setCursor(20, 140);
    tft.print("Ready for connections");
    tft.setCursor(20, 160);
    tft.print("");
    tft.setCursor(20, 180);
    tft.print("Press any key");
    while(!check(AnyKeyPress)) delay(50);
}

void memoryCheck() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("MEMORY CHECK");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Heap: " + String(ESP.getFreeHeap()) + " bytes");
    tft.setCursor(20, 80);
    tft.print("PSRAM: " + String(ESP.getFreePsram()) + " bytes");
    tft.setCursor(20, 100);
    tft.print("Max Alloc: " + String(ESP.getMaxAllocHeap()) + " bytes");
    tft.setCursor(20, 120);
    tft.print("");
    tft.setCursor(20, 140);
    tft.print("Press any key");
    while(!check(AnyKeyPress)) delay(50);
    Serial.printf("[MEMORY] Heap: %lu, PSRAM: %lu, MaxAlloc: %lu\n",
        ESP.getFreeHeap(), ESP.getFreePsram(), ESP.getMaxAllocHeap());
}

void fastpair_benchmark() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("FASTPAIR BENCHMARK");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Generating ECDH key pair... ");
    uint64_t start = esp_timer_get_time();
    uint8_t pub_key[65];
    size_t pub_len = 65;
    if(!crypto.generateKeyPair(pub_key, &pub_len)) {
        tft.println("FAILED");
        return;
    }
    uint64_t keygen_time = esp_timer_get_time() - start;
    tft.println(String(keygen_time / 1000.0) + " ms");
    tft.setCursor(20, 80);
    tft.print("Computing shared secret... ");
    start = esp_timer_get_time();
    if(!crypto.computeSharedSecret(pub_key, pub_len)) {
        tft.println("FAILED");
        return;
    }
    uint64_t secret_time = esp_timer_get_time() - start;
    tft.println(String(secret_time / 1000.0) + " ms");
    tft.setCursor(20, 100);
    tft.print("Deriving FastPair keys... ");
    start = esp_timer_get_time();
    uint8_t nonce[16] = {0};
    esp_fill_random(nonce, 16);
    if(!crypto.deriveFastPairKeys(nonce, 16)) {
        tft.println("FAILED");
        return;
    }
    uint64_t derive_time = esp_timer_get_time() - start;
    tft.println(String(derive_time / 1000.0) + " ms");
    tft.setCursor(20, 130);
    tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
    tft.print("TOTAL TIME: ");
    tft.println(String((keygen_time + secret_time + derive_time) / 1000.0) + " ms");
    tft.setCursor(20, 150);
    tft.setTextColor(TFT_YELLOW, bruceConfig.bgColor);
    tft.print("Free Heap: ");
    tft.print(ESP.getFreeHeap());
    tft.println(" bytes");
    Serial.printf("[WhisperPair] Benchmark: KeyGen=%.2fms, Secret=%.2fms, Derive=%.2fms, Total=%.2fms\n",
        keygen_time / 1000.0, secret_time / 1000.0, derive_time / 1000.0,
        (keygen_time + secret_time + derive_time) / 1000.0);
    tft.setCursor(20, 180);
    tft.print("");
    tft.setCursor(20, 200);
    tft.print("Press any key");
    while(!check(AnyKeyPress)) delay(50);
}

void whisperPairDebugMenu() {
    std::vector<Option> options;
    options.push_back({"[System Info]", []() {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("SYSTEM INFO");
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, 60);
        tft.print("Heap: " + String(ESP.getFreeHeap()) + " bytes");
        tft.setCursor(20, 80);
        tft.print("PSRAM: " + String(ESP.getFreePsram()) + " bytes");
        tft.setCursor(20, 100);
        tft.print("CPU: " + String(ESP.getCpuFreqMHz()) + " MHz");
        printBLEInfo();
        tft.setCursor(20, 140);
        tft.print("");
        tft.setCursor(20, 160);
        tft.print("Press any key");
        while(!check(AnyKeyPress)) delay(50);
    }});
    options.push_back({"[BLE Hardware Test]", []() { bleHardwareTest(); }});
    options.push_back({"[Basic BLE Test]", []() { testBasicBLEScanner(); }});
    options.push_back({"[Test BLE Scanner]", []() { testBLEScanner(); }});
    options.push_back({"[Test BLE Connection]", []() { testBLEConnection(); }});
    options.push_back({"[Memory Check]", []() { memoryCheck(); }});
    options.push_back({"[Crypto Benchmark]", []() { fastpair_benchmark(); }});
    options.push_back({"[Scan Debug Tests]", []() {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("SCAN DEBUG");
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, 60);
        tft.print("Running scan debug tests...");
        tft.setCursor(20, 80);
        tft.print("Check Serial Monitor");
        tft.setCursor(20, 100);
        tft.print("for detailed output");
        runScanDebugTests();
        tft.setCursor(20, 140);
        tft.print("Tests complete");
        tft.setCursor(20, 160);
        tft.print("Press any key");
        while(!check(AnyKeyPress)) delay(50);
    }});
    options.push_back({"[Back]", []() {}});
    loopOptions(options, MENU_TYPE_SUBMENU, "DEBUG", 0, false);
}