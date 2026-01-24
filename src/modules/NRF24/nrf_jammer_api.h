#ifndef __NRF_JAMMER_API_H
#define __NRF_JAMMER_API_H

#include "modules/NRF24/nrf_common.h"

bool isNRF24Available();
void startJammer();
void stopJammer();

#endif