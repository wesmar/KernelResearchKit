#pragma once

#include <Windows.h>
#include <vector>
#include <cstdint>

namespace ResourceInstaller {
    // XOR key for driver encryption
    constexpr BYTE XOR_KEY[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    constexpr size_t XOR_KEY_LEN = sizeof(XOR_KEY);
    
    // Extract and decrypt driver from resource
    std::vector<BYTE> ExtractAndDecryptDriver(HINSTANCE hInstance, int resourceId);
    
    // Install driver from embedded resource
    bool InstallDriverFromResource();
    
    // Check if RTCore64.sys exists in System32\drivers
    bool IsDriverInstalled();
}
