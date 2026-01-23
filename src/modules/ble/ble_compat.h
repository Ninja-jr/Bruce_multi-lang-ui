#pragma once

#ifdef CONFIG_BT_NIMBLE_ENABLED
    #include <NimBLEDevice.h>
    #include <NimBLEServer.h>
    #include <NimBLEUtils.h>
    #include <NimBLEAdvertisedDevice.h>
    #include <NimBLEBeacon.h>
    #include <NimBLEScan.h>
    
    #ifndef BLEDevice
        #define BLEDevice NimBLEDevice
    #endif
    
    #ifndef BLEScan
        #define BLEScan NimBLEScan
    #endif
    
    #ifndef BLEAdvertisedDevice
        #define BLEAdvertisedDevice NimBLEAdvertisedDevice
    #endif
#else
    #include <BLEDevice.h>
    #include <BLEServer.h>
    #include <BLEUtils.h>
    #include <BLEAdvertisedDevice.h>
    #include <BLEBeacon.h>
    #include <BLEScan.h>
#endif