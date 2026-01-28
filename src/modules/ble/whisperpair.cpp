String selectTargetFromScan(const char* title) {
    scannerData.clear();
    
    tft.fillScreen(bruceConfig.bgColor);
    tft.drawRect(5, 5, tftWidth - 10, tftHeight - 10, TFT_WHITE);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setTextSize(2);
    tft.setCursor((tftWidth - strlen(title) * 12) / 2, 15);
    tft.print(title);
    tft.setTextSize(1);
    
    tft.fillRect(20, 60, tftWidth - 40, 40, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Phase 1/2: Quick scan...");

    bool wasInitialized = isBLEInitialized();
    if(wasInitialized) {
        if(NimBLEDevice::getScan() && NimBLEDevice::getScan()->isScanning()) {
            NimBLEDevice::getScan()->stop();
            delay(300);
        }
        NimBLEDevice::deinit(true);
        delay(800);
    }

    NimBLEDevice::init("Bruce-Scanner");
    NimBLEDevice::setPower(ESP_PWR_LVL_P9);
    NimBLEDevice::setSecurityAuth(false, false, false);
    delay(500);

    NimBLEScan* pBLEScan = NimBLEDevice::getScan();
    if(!pBLEScan) {
        showErrorMessage("Failed to create scanner");
        NimBLEDevice::deinit(true);
        return "";
    }

    pBLEScan->clearResults();
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(70);
    pBLEScan->setWindow(35);
    pBLEScan->setDuplicateFilter(false);
    pBLEScan->setMaxResults(0);

    class ScanCallback : public NimBLEScanCallbacks {
        void onResult(NimBLEAdvertisedDevice* advertisedDevice) {
            String name = String(advertisedDevice->getName().c_str());
            String address = String(advertisedDevice->getAddress().toString().c_str());
            int rssi = advertisedDevice->getRSSI();
            
            if(name.isEmpty() || name == "(null)") {
                name = "Unknown";
            }
            
            bool fastPair = false;
            if(advertisedDevice->haveManufacturerData()) {
                std::string mfg = advertisedDevice->getManufacturerData();
                if(mfg.length() >= 2) {
                    uint16_t mfg_id = (mfg[1] << 8) | mfg[0];
                    if(mfg_id == 0x00E0 || mfg_id == 0x2C00) {
                        fastPair = true;
                    }
                }
            }
            
            scannerData.addDevice(name, address, rssi, fastPair);
        }
    };

    static ScanCallback scanCallback;
    pBLEScan->setScanCallbacks(&scanCallback, false);

    tft.setCursor(20, 100);
    tft.print("Found: 0 devices");

    unsigned long phase1Start = millis();
    pBLEScan->start(5, false);
    
    while(millis() - phase1Start < 6000) {
        if(check(EscPress)) {
            pBLEScan->stop();
            break;
        }
        delay(50);
    }

    pBLEScan->stop();
    delay(100);
    
    size_t phase1Count = scannerData.size();
    tft.fillRect(20, 60, tftWidth - 40, 40, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Phase 2/2: Deep scan...");
    tft.setCursor(20, 100);
    tft.print("Found: ");
    tft.print(phase1Count);
    tft.print(" devices");

    pBLEScan->setScanCallbacks(nullptr, false);
    pBLEScan->clearResults();

    unsigned long phase2Start = millis();
    NimBLEScanResults blockingResults = pBLEScan->start(10, true);
    
    for(int i = 0; i < blockingResults.getCount(); i++) {
        NimBLEAdvertisedDevice* device = blockingResults.getDevice(i);
        if(!device) continue;
        
        String name = String(device->getName().c_str());
        String address = String(device->getAddress().toString().c_str());
        int rssi = device->getRSSI();
        
        if(name.isEmpty() || name == "(null)") {
            name = "Unknown";
        }
        
        bool fastPair = false;
        if(device->haveManufacturerData()) {
            std::string mfg = device->getManufacturerData();
            if(mfg.length() >= 2) {
                uint16_t mfg_id = (mfg[1] << 8) | mfg[0];
                if(mfg_id == 0x00E0 || mfg_id == 0x2C00) {
                    fastPair = true;
                }
            }
        }
        
        scannerData.addDevice(name, address, rssi, fastPair);
    }

    pBLEScan->stop();
    pBLEScan->clearResults();
    NimBLEDevice::deinit(true);
    delay(300);

    size_t deviceCount = scannerData.size();
    if(deviceCount == 0) {
        showWarningMessage("NO DEVICES FOUND");
        delay(1500);
        return "";
    }

    if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
        for(size_t i = 0; i < scannerData.deviceAddresses.size() - 1; i++) {
            for(size_t j = i + 1; j < scannerData.deviceAddresses.size(); j++) {
                if(scannerData.deviceFastPair[j] && !scannerData.deviceFastPair[i]) {
                    std::swap(scannerData.deviceNames[i], scannerData.deviceNames[j]);
                    std::swap(scannerData.deviceAddresses[i], scannerData.deviceAddresses[j]);
                    std::swap(scannerData.deviceRssi[i], scannerData.deviceRssi[j]);
                    std::swap(scannerData.deviceFastPair[i], scannerData.deviceFastPair[j]);
                } else if(scannerData.deviceFastPair[j] == scannerData.deviceFastPair[i] && 
                          scannerData.deviceRssi[j] > scannerData.deviceRssi[i]) {
                    std::swap(scannerData.deviceNames[i], scannerData.deviceNames[j]);
                    std::swap(scannerData.deviceAddresses[i], scannerData.deviceAddresses[j]);
                    std::swap(scannerData.deviceRssi[i], scannerData.deviceRssi[j]);
                    std::swap(scannerData.deviceFastPair[i], scannerData.deviceFastPair[j]);
                }
            }
        }
        xSemaphoreGive(scannerData.mutex);
    }

    int maxDevices = std::min((int)deviceCount, 6);
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
            String displayName;
            String address;
            int rssi = 0;
            bool fastPair = false;
            
            if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
                if(i < scannerData.deviceNames.size()) {
                    displayName = scannerData.deviceNames[i];
                    address = scannerData.deviceAddresses[i];
                    rssi = scannerData.deviceRssi[i];
                    fastPair = scannerData.deviceFastPair[i];
                }
                xSemaphoreGive(scannerData.mutex);
            }
            
            if(displayName.isEmpty()) continue;
            
            String displayText = displayName;
            if(displayText.length() > 18) {
                displayText = displayText.substring(0, 15) + "...";
            }
            displayText += " (" + String(rssi) + "dB)";
            if(fastPair) displayText += " [FP]";

            int itemY = yPos + (i * 24);
            if(itemY + 24 > tftHeight - 45) {
                break;
            }

            if(i == selectedIdx) {
                tft.fillRect(20, itemY, tftWidth - 40, 22, TFT_WHITE);
                tft.setTextColor(TFT_BLACK, TFT_WHITE);
            } else {
                tft.fillRect(20, itemY, tftWidth - 40, 22, bruceConfig.bgColor);
                tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
            }

            tft.setCursor(25, itemY + 6);
            tft.print(displayText);
        }

        tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
        tft.setCursor(20, tftHeight - 35);
        tft.print("SEL: Connect  PREV/NEXT: Select  ESC: Back");

        unsigned long inputWaitStart = millis();
        bool gotInput = false;

        while(!gotInput) {
            if(check(EscPress)) {
                exitLoop = true;
                gotInput = true;
            }
            else if(check(PrevPress)) {
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
                tft.fillRect(20, tftHeight - 60, tftWidth - 40, 30, bruceConfig.bgColor);
                tft.setCursor(20, tftHeight - 60);
                tft.print("Connecting...");
                delay(500);
                
                String selectedMAC = "";
                uint8_t selectedAddrType = BLE_ADDR_PUBLIC;
                
                if(xSemaphoreTake(scannerData.mutex, portMAX_DELAY)) {
                    if(selectedIdx < scannerData.deviceAddresses.size()) {
                        selectedMAC = scannerData.deviceAddresses[selectedIdx];
                    }
                    xSemaphoreGive(scannerData.mutex);
                }
                
                if(!selectedMAC.isEmpty()) {
                    exitLoop = true;
                    gotInput = true;
                    
                    scannerData.clear();
                    return selectedMAC + ":" + String(selectedAddrType);
                }
            }
            if(!gotInput) delay(50);
        }
    }

    scannerData.clear();
    return "";
}