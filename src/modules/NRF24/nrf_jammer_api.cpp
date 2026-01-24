#include "nrf_jammer_api.h"
#include "nrf_jammer.h"
#include "core/display.h"
#include <RF24.h>

static bool nrf24Initialized = false;
static bool jammingActive = false;
static int currentJamMode = 0;
static unsigned long lastChannelHop = 0;
static int currentChannelIndex = 0;

static byte bleAdvChannels[] = {37, 38, 39};

static byte bleAllChannels[] = {
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
    34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65,
    66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80
};

bool isNRF24Available() {
    if (!nrf24Initialized) {
        NRF24_MODE mode = nrf_setMode();
        if (nrf_start(mode)) {
            if (CHECK_NRF_SPI(mode)) {
                NRFradio.setPALevel(RF24_PA_MAX);
                NRFradio.setAddressWidth(3);
                NRFradio.setPayloadSize(2);
                if (!NRFradio.setDataRate(RF24_2MBPS)) {
                }
            }
            nrf24Initialized = true;
        }
    }
    return nrf24Initialized;
}

void setJammerMode(int modeIndex) {
    if (modeIndex >= 0 && modeIndex <= 8) {
        currentJamMode = modeIndex;
        currentChannelIndex = 0;
    }
}

int getCurrentJammerMode() {
    return currentJamMode;
}

byte* getChannelsForMode(int mode) {
    switch(mode) {
        case 0: return bleAdvChannels;
        case 1: return bleAllChannels;
        case 2: return bleAdvChannels;
        case 3: return bleAllChannels;
        default: return bleAdvChannels;
    }
}

int getChannelCountForMode(int mode) {
    switch(mode) {
        case 0: return sizeof(bleAdvChannels);
        case 1: return sizeof(bleAllChannels);
        case 2: return sizeof(bleAdvChannels);
        case 3: return sizeof(bleAllChannels);
        default: return sizeof(bleAdvChannels);
    }
}

void startJammer() {
    if (!isNRF24Available()) {
        return;
    }

    NRF24_MODE mode = nrf_setMode();

    if (CHECK_NRF_SPI(mode)) {
        byte* channels = getChannelsForMode(currentJamMode);
        int channelCount = getChannelCountForMode(currentJamMode);
        
        NRFradio.startConstCarrier(RF24_PA_MAX, channels[0]);
        jammingActive = true;
        lastChannelHop = millis();
        currentChannelIndex = 0;
    }
}

void updateJammerChannel() {
    if (!jammingActive) return;
    
    if (millis() - lastChannelHop > 100) {
        byte* channels = getChannelsForMode(currentJamMode);
        int channelCount = getChannelCountForMode(currentJamMode);
        
        currentChannelIndex = (currentChannelIndex + 1) % channelCount;
        NRFradio.setChannel(channels[currentChannelIndex]);
        
        lastChannelHop = millis();
    }
}

void stopJammer() {
    if (!jammingActive) return;

    NRF24_MODE mode = nrf_setMode();

    if (CHECK_NRF_SPI(mode)) {
        NRFradio.stopConstCarrier();
        jammingActive = false;
        currentChannelIndex = 0;
    }
}