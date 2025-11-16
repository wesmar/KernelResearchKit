#pragma once

#include <Windows.h>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

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
    
    // Driver load history management
    struct DriverHistoryEntry {
        std::wstring timestamp;
        std::wstring timestampRaw;  // For sorting (YYYYMMDD_HHMMSS)
        std::wstring driverPath;
        std::wstring serviceName;
        DWORD startType;
        bool success;
    };
    
    // Saves driver load operation to history (max 8 entries)
    bool SaveDriverLoadHistory(const std::wstring& driverPath, const std::wstring& serviceName,
                               DWORD startType, bool success);
    
    // Retrieves list of last loaded drivers (sorted by date, newest first)
    std::vector<DriverHistoryEntry> GetDriverLoadHistory();
    
    // Clears all driver load history from registry
    bool ClearDriverLoadHistory();
    
    // Extracts service name from driver path (removes .sys extension)
    std::wstring ExtractServiceName(const std::wstring& driverPath);
    
    // Normalizes driver path (adds System32\drivers\ if needed, adds .sys extension)
    std::wstring NormalizeDriverPath(const std::wstring& input);
}