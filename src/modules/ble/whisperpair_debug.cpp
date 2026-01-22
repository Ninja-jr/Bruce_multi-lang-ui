#include "whisperpair_debug.h"
#include "whisperpair.h"
#include "fastpair_crypto.h"
#include <globals.h>
#include "core/display.h"
#include "core/mykeyboard.h"

FastPairCrypto crypto;

void printBLEInfo() {
    Serial.println("\n=== SYSTEM INFO ===");
    Serial.printf("Free Heap: %lu\n", ESP.getFreeHeap());
    Serial.printf("Free PSRAM: %lu\n", ESP.getFreePsram());
    Serial.printf("CPU Freq: %lu MHz\n", ESP.getCpuFreqMHz());
    Serial.println("===================\n");
}

void testBLEScanner() {
    Serial.println("\n[DEBUG] Starting BLE scanner test...");
    NimBLEScan* scan = NimBLEDevice::getScan();
    scan->setActiveScan(true);
    scan->setInterval(160);
    scan->setWindow(80);
    scan->setDuplicateFilter(true);
    Serial.println("[DEBUG] Scanning for 5 seconds...");
    
    if (scan->start(5, false)) {
        NimBLEScanResults results = scan->getResults();
        Serial.printf("[DEBUG] Found %d devices:\n", results.getCount());
        
        for(int i = 0; i < results.getCount(); i++) {
            const NimBLEAdvertisedDevice* device = results.getDevice(i);
            if (device) {
                Serial.printf("  %d: %s - %s (RSSI: %d)\n", i,
                    device->getAddress().toString().c_str(),
                    device->getName().c_str(),
                    device->getRSSI());
            }
        }
        
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("BLE SCANNER TEST");
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        padprintln("Devices found: " + String(results.getCount()));
        padprintln("");
        
        for(int i = 0; i < min(results.getCount(), 5); i++) {
            const NimBLEAdvertisedDevice* device = results.getDevice(i);
            if (device) {
                String line = String(device->getAddress().toString().c_str()) + 
                             " (" + String(device->getRSSI()) + "dBm)";
                padprintln(line);
            }
        }
        
        if(results.getCount() == 0) padprintln("NO DEVICES FOUND!");
        padprintln("");
        padprintln("Press any key");
        
        scan->clearResults();
    } else {
        Serial.println("[DEBUG] Scan failed to start!");
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("BLE SCANNER TEST");
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        padprintln("Scan failed to start!");
        padprintln("");
        padprintln("Press any key");
    }
    
    while(!check(AnyKeyPress)) delay(50);
}

void testBLEConnection() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("BLE CONNECTION TEST");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    padprintln("Testing BLE connection...");
    padprintln("");
    padprintln("NimBLE ready");
    padprintln("Heap: " + String(ESP.getFreeHeap()));
    padprintln("Ready for connections");
    padprintln("");
    padprintln("Press any key");
    while(!check(AnyKeyPress)) delay(50);
}

void memoryCheck() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("MEMORY CHECK");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    padprintln("Heap: " + String(ESP.getFreeHeap()) + " bytes");
    padprintln("PSRAM: " + String(ESP.getFreePsram()) + " bytes");
    padprintln("Max Alloc: " + String(ESP.getMaxAllocHeap()) + " bytes");
    padprintln("");
    padprintln("Press any key");
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
    padprintln("");
    padprintln("Press any key");
    while(!check(AnyKeyPress)) delay(50);
}

void whisperPairDebugMenu() {
    std::vector<Option> options;
    options.push_back({"[ℹ️] System Info", []() {
        tft.fillScreen(bruceConfig.bgColor);
        drawMainBorderWithTitle("SYSTEM INFO");
        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        padprintln("Heap: " + String(ESP.getFreeHeap()) + " bytes");
        padprintln("PSRAM: " + String(ESP.getFreePsram()) + " bytes");
        padprintln("CPU: " + String(ESP.getCpuFreqMHz()) + " MHz");
        printBLEInfo();
        padprintln("");
        padprintln("Press any key");
        while(!check(AnyKeyPress)) delay(50);
    }});
    options.push_back({"[🔍] Test BLE Scanner", []() { testBLEScanner(); }});
    options.push_back({"[🔗] Test BLE Connection", []() { testBLEConnection(); }});
    options.push_back({"[💾] Memory Check", []() { memoryCheck(); }});
    options.push_back({"[📊] Crypto Benchmark", []() { fastpair_benchmark(); }});
    options.push_back({"Back", []() {}});
    loopOptions(options, MENU_TYPE_SUBMENU, "DEBUG", 0, false);
}