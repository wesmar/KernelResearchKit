#pragma once

#include <Windows.h>
#include <cstdint>
#include <optional>

struct DrvLoader {
    HANDLE hDriver{ INVALID_HANDLE_VALUE };
    std::optional<uint64_t> originalCallback;
    
    bool Initialize();
    void Cleanup();
    bool WriteMemory32(uint64_t address, uint32_t value);
    bool WriteMemory64(uint64_t address, uint64_t value);
    std::optional<uint32_t> ReadMemory32(uint64_t address);
    std::optional<uint64_t> ReadMemory64(uint64_t address);
    bool CheckDSEStatus(bool& isPatched);
    bool BypassDSE();
    bool RestoreDSE();
    
private:
    std::optional<uint64_t> GetNtoskrnlBase();
    bool SaveOriginalCallback(uint64_t callback);
    std::optional<uint64_t> LoadOriginalCallback();
    bool DeleteStateFile();
    bool InstallAndStartDriver();
    bool StopAndRemoveDriver();
    bool CheckDriverFileExists();
};