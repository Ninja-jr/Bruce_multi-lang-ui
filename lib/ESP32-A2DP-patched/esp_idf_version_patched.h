#pragma once
#define ESP_IDF_VERSION_MAJOR   4
#define ESP_IDF_VERSION_MINOR   3
#define ESP_IDF_VERSION_PATCH   7
#define ESP_IDF_VERSION_VAL(major, minor, patch) ((major << 16) | (minor << 8) | (patch))
#define ESP_IDF_VERSION  ESP_IDF_VERSION_VAL(ESP_IDF_VERSION_MAJOR, ESP_IDF_VERSION_MINOR, ESP_IDF_VERSION_PATCH)
