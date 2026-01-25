String selectTargetFromScan(const char* title) {
    std::vector<Option> deviceOptions;
    String selectedMAC = "";
    uint8_t selectedAddrType = BLE_ADDR_PUBLIC;
    
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle(title);
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    
    tft.fillRect(20, 60, tftWidth - 40, 40, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("Initializing BLE...");
    
    if (!NimBLEDevice::getInitialized()) {
        NimBLEDevice::init("Bruce-Scanner");
    }
    
    NimBLEScan* pBLEScan = NimBLEDevice::getScan();
    
    tft.fillRect(20, 60, tftWidth - 40, 40, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    
    if (!pBLEScan) {
        tft.setTextColor(TFT_RED, bruceConfig.bgColor);
        tft.print("BLE INIT FAIL");
        showAdaptiveMessage("Scanner init failed", "OK", "", "", TFT_RED);
        return "";
    }
    
    tft.setTextColor(TFT_GREEN, bruceConfig.bgColor);
    tft.print("BLE INIT OK");
    delay(1000);
    
    pBLEScan->clearResults();
    pBLEScan->setActiveScan(true);
    pBLEScan->setInterval(100);
    pBLEScan->setWindow(99);
    pBLEScan->setDuplicateFilter(true);