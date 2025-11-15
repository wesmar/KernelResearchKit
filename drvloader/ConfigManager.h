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
    
    // Creates mini-PDB file with extracted offsets (96 bytes)
    bool CreateMiniPdb(uint64_t seCiCallbacks, uint64_t safeFunction, const std::wstring& outputPath);
    
    // Loads offsets from mini-PDB file
    bool LoadOffsetsFromMiniPdb(const std::wstring& mpdbPath, uint64_t* outSeCi, uint64_t* outSafe);
    
    // Creates mini-PDB in Windows symbols directory with proper GUID structure
    bool CreateWindowsMiniPdb(uint64_t seCiCallbacks, uint64_t safeFunction);
    
    // Loads offsets from Windows mini-PDB (automatic location detection)
    bool LoadOffsetsFromWindowsMiniPdb(uint64_t* outSeCi, uint64_t* outSafe);
    
    // Gets Windows build number from ntoskrnl.exe version info
    std::wstring GetWindowsBuildNumber();
}