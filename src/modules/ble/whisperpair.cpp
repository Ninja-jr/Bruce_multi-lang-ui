void whisperPairMenu() {
    std::vector<Option> options;
    returnToMenu = false;
    
    // REMOVE this: initializeBLEOnce("Bruce-WP");
    // Let each function handle its own BLE init/deinit
    
    options.push_back({"[FastPair Exploit]", []() {
        String targetInfo = selectTargetFromScan("EXPLOIT TARGET");
        if(targetInfo.isEmpty()) return;
        NimBLEAddress target = parseAddress(targetInfo);
        if(requireSimpleConfirmation("Run FastPair exploit?")) {
            if(fastPairExploit(target)) {
                showSuccessMessage("EXPLOIT MAY HAVE WORKED!");
            } else {
                showErrorMessage("Exploit failed");
            }
        }
    }});
    
    // ... other menu items (all same as before) ...
}