void showAttackProgress(const char* message, uint16_t color) {
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