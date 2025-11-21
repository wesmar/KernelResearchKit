#pragma once

#include <Windows.h>
#include <cstdint>
#include <optional>
#include "SymbolDownloader.h"

constexpr DWORD RTC_IOCTL_MEMORY_READ = 0x80002048;
constexpr DWORD RTC_IOCTL_MEMORY_WRITE = 0x8000204C;

struct alignas(8) RTC_MEMORY_READ {
    BYTE Pad0[8];
    uint64_t Address;
    BYTE Pad1[8];
    uint32_t Size;
    uint32_t Value;
    BYTE Pad3[16];
};

struct alignas(8) RTC_MEMORY_WRITE {
    BYTE Pad0[8];
    uint64_t Address;
    BYTE Pad1[8];
    uint32_t Size;
    uint32_t Value;
    BYTE Pad3[16];
};

class DrvLoader {
public:
    HANDLE hDriver{ INVALID_HANDLE_VALUE };
    std::optional<uint64_t> originalCallback;
    SymbolDownloader symbolDownloader;

    // Resolves necessary kernel symbol offsets
    bool GetSymbolOffsets(uint64_t* seCiCallbacks, uint64_t* safeFunction);
    
    // Initializes the loader and checks registry state
    bool Initialize();
    
    // Releases resources and handles
    void Cleanup();
    
    // Kernel memory operations
    bool WriteMemory32(uint64_t address, uint32_t value);
    bool WriteMemory64(uint64_t address, uint64_t value);
    std::optional<uint32_t> ReadMemory32(uint64_t address);
    std::optional<uint64_t> ReadMemory64(uint64_t address);
    
    // DSE Status and Manipulation
    bool CheckDSEStatus(bool& isPatched);
    bool BypassDSE();
    bool RestoreDSE();
    
    // Driver Management
    bool LoadDriver(const std::wstring& driverPath, DWORD startType = SERVICE_DEMAND_START, const std::wstring& dependencies = L"");
    bool ReloadDriver(const std::wstring& driverPath);
    bool StopDriver(const std::wstring& serviceNameOrPath);   // New: Stops service without deleting
    bool RemoveDriver(const std::wstring& serviceNameOrPath); // Renamed from UnloadDriver: Stops and deletes
    
private:
    std::optional<uint64_t> GetNtoskrnlBase();
    std::optional<uint64_t> GetKernelSymbolOffset(const std::wstring& symbolName);
    
    // Internal helpers for RTCore64 handling
    bool InstallAndStartDriver();
    bool StopAndRemoveDriver();
    bool CheckDriverFileExists();
    
    // Internal DSE helpers
    bool TryLoadOffsetsFromCache(uint64_t* seCiCallbacks, uint64_t* safeFunction);
    bool BypassDSEInternal();
    bool RestoreDSEInternal();
};