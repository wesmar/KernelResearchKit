#pragma once

#include <Windows.h>
#include <cstdint>
#include <optional>
#include <string>

// Manages system configuration including registry state and INI files
namespace ConfigManager {
    // Returns path to drivers.ini in Windows directory
    std::wstring GetDriversIniPath();
    
    // Returns path to RTCore64.sys driver
    std::wstring GetDriverPath();
    
    // Updates drivers.ini with current offsets for external tools
    bool UpdateDriversIni(uint64_t seCiCallbacks, uint64_t safeFunction);
    
    // Saves offsets to registry history for reference
    bool SaveOffsetsToRegistry(uint64_t seCiCallbacks, uint64_t safeFunction, const std::wstring& buildInfo);
    
    // Saves original callback address before patching
    bool SaveOriginalCallbackToRegistry(uint64_t callback);
    
    // Loads original callback address from registry
    std::optional<uint64_t> LoadOriginalCallbackFromRegistry();
    
    // Clears patch state from registry after restore
    bool ClearPatchStateFromRegistry();
    
    // Checks if Memory Integrity (HVCI) is enabled and offers to disable it
    bool CheckAndDisableMemoryIntegrity();
}