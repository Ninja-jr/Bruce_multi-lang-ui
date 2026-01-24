#include "nrf_jammer_api.h"
#include "nrf_jammer.h"
#include "core/display.h"
#include <RF24.h>

static bool nrf24Initialized = false;
static bool jammingActive = false;

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

void startJammer() {
    if (!isNRF24Available()) {
        return;
    }
    
    NRF24_MODE mode = nrf_setMode();
    
    if (CHECK_NRF_SPI(mode)) {
        NRFradio.startConstCarrier(RF24_PA_MAX, 37);
        jammingActive = true;
    }
}

void stopJammer() {
    if (!jammingActive) return;
    
    NRF24_MODE mode = nrf_setMode();
    
    if (CHECK_NRF_SPI(mode)) {
        NRFradio.stopConstCarrier();
        jammingActive = false;
    }
}