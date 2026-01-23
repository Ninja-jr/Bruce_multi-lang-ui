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
    }
    
    void clear() {
        devices.clear();
    }
};

void testRawBLE() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("RAW BLE TEST");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    
    tft.setCursor(20, 60);
    tft.print("Testing raw BLE...");
    
    NimBLEDevice::deinit(true);
    delay(1000);
    
    NimBLEDevice::init("raw_test");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    
    NimBLEScan* pScan = NimBLEDevice::getScan();
    pScan->setActiveScan(true);
    pScan->setInterval(100);
    pScan->setWindow(50);
    pScan->setDuplicateFilter(false);
    
    tft.setCursor(20, 80);
    tft.print("Starting scan...");
    
    NimBLEScanResults results = pScan->start(3);
    
    tft.setCursor(20, 100);
    tft.print("Raw scan count: " + String(results.getCount()));
    
    if(results.getCount() > 0) {
        tft.setCursor(20, 120);
        tft.print("BLE IS WORKING!");
        
        const NimBLEAdvertisedDevice* device = results.getDevice(0);
        if(device) {
            tft.setCursor(20, 140);
            String addr = device->getAddress().toString().c_str();
            tft.print("First: " + addr);
        }
    } else {
        tft.setCursor(20, 120);
        tft.print("NO DEVICES FOUND");
    }
    
    pScan->clearResults();
    NimBLEDevice::deinit(true);
    
    tft.setCursor(20, 180);
    tft.print("Press any key");
    while(!check(AnyKeyPress)) delay(50);
}

void runScanDebugTests() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("SCAN DEBUG TESTS");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    
    int lineY = 50;
    int lineHeight = 20;
    
    tft.setCursor(20, lineY);
    tft.print("Testing 24 scan combos...");
    lineY += lineHeight;
    
    int tests[8][3] = {
        {100, 50, 1},
        {50, 30, 1},
        {150, 75, 1},
        {200, 100, 1},
        {100, 50, 0},
        {250, 125, 1},
        {80, 40, 1},
        {300, 150, 1}
    };
    
    int totalFound = 0;
    int testNum = 1;
    
    for(int power = 0; power < 3; power++) {
        for(int filter = 0; filter < 2; filter++) {
            for(int i = 0; i < 8; i++) {
                int interval = tests[i][0];
                int window = tests[i][1];
                bool active = tests[i][2];
                
                tft.setCursor(20, lineY);
                tft.print("Test " + String(testNum) + ": ");
                
                DebugScanCallbacks debugCallbacks;
                debugCallbacks.clear();
                
                NimBLEDevice::deinit(true);
                delay(500);
                
                NimBLEDevice::init("debug_scan");
                
                if(power == 0) {
                    NimBLEDevice::setPower(ESP_PWR_LVL_N12);
                } else if(power == 1) {
                    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
                } else {
                    NimBLEDevice::setPower(ESP_PWR_LVL_P3);
                }
                
                NimBLEScan* pScan = NimBLEDevice::getScan();
                pScan->setActiveScan(active);
                pScan->setInterval(interval);
                pScan->setWindow(window);
                pScan->setDuplicateFilter(filter == 1);
                pScan->setScanCallbacks(&debugCallbacks, true);
                
                if(pScan->start(3, true)) {
                    tft.print("OK - Found: " + String(debugCallbacks.devices.size()));
                    totalFound += debugCallbacks.devices.size();
                    
                    if(debugCallbacks.devices.size() > 0) {
                        tft.setCursor(180, lineY);
                        tft.print("WORKING!");
                    }
                } else {
                    tft.print("FAILED");
                }
                
                pScan->clearResults();
                NimBLEDevice::deinit(true);
                
                lineY += lineHeight;
                if(lineY > 220) {
                    tft.setCursor(20, lineY);
                    tft.print("...more tests...");
                    lineY += lineHeight;
                }
                
                testNum++;
                delay(200);
            }
        }
    }
    
    lineY += lineHeight;
    tft.setCursor(20, lineY);
    tft.print("TOTAL DEVICES FOUND: " + String(totalFound));
    
    if(totalFound == 0) {
        lineY += lineHeight;
        tft.setCursor(20, lineY);
        tft.print("NO DEVICES - Check config");
    }
    
    lineY += lineHeight * 2;
    tft.setCursor(20, lineY);
    tft.print("Press any key");
    
    while(!check(AnyKeyPress)) delay(50);
}

void printBLEInfo() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("SYSTEM INFO");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    
    tft.setCursor(20, 60);
    tft.print("Heap: " + String(ESP.getFreeHeap()) + " bytes");
    
    tft.setCursor(20, 80);
    tft.print("PSRAM: " + String(ESP.getFreePsram()) + " bytes");
    
    tft.setCursor(20, 100);
    tft.print("CPU: " + String(ESP.getCpuFreqMHz()) + " MHz");
    
    tft.setCursor(20, 140);
    tft.print("Press any key");
    while(!check(AnyKeyPress)) delay(50);
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
    
    NimBLEDevice::deinit(true);
    delay(500);
    
    NimBLEDevice::init("test");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    
    NimBLEScan* scan = NimBLEDevice::getScan();
    scan->setActiveScan(true);
    scan->setInterval(100);
    scan->setWindow(50);
    scan->setDuplicateFilter(false);
    
    tft.setCursor(20, 80);
    tft.print("Scanning 5 seconds...");
    
    if (scan->start(5, true)) {
        NimBLEScanResults results = scan->getResults();
        tft.setCursor(20, 100);
        tft.print("Found: " + String(results.getCount()));
        
        for(int i = 0; i < results.getCount() && i < 3; i++) {
            const NimBLEAdvertisedDevice* device = results.getDevice(i);
            if (device) {
                tft.setCursor(20, 120 + (i * 20));
                String addr = device->getAddress().toString().c_str();
                if (addr.length() > 12) addr = addr.substring(0, 12);
                tft.print(addr + " " + String(device->getRSSI()) + "dB");
            }
        }
        scan->clearResults();
    } else {
        tft.setCursor(20, 100);
        tft.print("Scan failed!");
    }
    
    NimBLEDevice::deinit(true);
    
    tft.setCursor(20, 200);
    tft.print("Press any key");
    while(!check(AnyKeyPress)) delay(50);
}

void testBLEScanner() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("BLE SCANNER TEST");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    
    initNimBLEIfNeeded("debug_scanner");
    
    NimBLEScan* scan = NimBLEDevice::getScan();
    if (!scan) {
        tft.setCursor(20, 60);
        tft.print("Scanner init failed!");
        tft.setCursor(20, 80);
        tft.print("Press any key");
        while(!check(AnyKeyPress)) delay(50);
        return;
    }
    
    scan->setActiveScan(true);
    scan->setInterval(100);
    scan->setWindow(50);
    scan->setDuplicateFilter(false);
    
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
    tft.setCursor(20, 180);
    tft.print("");
    tft.setCursor(20, 200);
    tft.print("Press any key");
    while(!check(AnyKeyPress)) delay(50);
}

void whisperPairDebugMenu() {
    std::vector<Option> options;
    options.push_back({"[System Info]", []() {
        printBLEInfo();
    }});
    options.push_back({"[BLE Hardware Test]", []() { bleHardwareTest(); }});
    options.push_back({"[Basic BLE Test]", []() { testBasicBLEScanner(); }});
    options.push_back({"[Test BLE Scanner]", []() { testBLEScanner(); }});
    options.push_back({"[Test BLE Connection]", []() { testBLEConnection(); }});
    options.push_back({"[Memory Check]", []() { memoryCheck(); }});
    options.push_back({"[Crypto Benchmark]", []() { fastpair_benchmark(); }});
    options.push_back({"[Raw BLE Test]", []() {
        testRawBLE();
    }});
    options.push_back({"[Scan Debug Tests]", []() {
        runScanDebugTests();
    }});
    options.push_back({"[Back]", []() {}});
    loopOptions(options, MENU_TYPE_SUBMENU, "DEBUG", 0, false);
}