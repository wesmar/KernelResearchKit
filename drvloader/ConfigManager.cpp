#include "ConfigManager.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <winreg.h>

namespace ConfigManager {

std::wstring GetDriversIniPath() {
    WCHAR systemRoot[MAX_PATH];
    DWORD len = GetEnvironmentVariableW(L"SystemRoot", systemRoot, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        GetWindowsDirectoryW(systemRoot, MAX_PATH);
    }
    return std::wstring(systemRoot) + L"\\drivers.ini";
}

std::wstring GetDriverPath() {
    WCHAR systemRoot[MAX_PATH];
    DWORD len = GetEnvironmentVariableW(L"SystemRoot", systemRoot, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        GetWindowsDirectoryW(systemRoot, MAX_PATH);
    }
    return std::wstring(systemRoot) + L"\\System32\\drivers\\RTCore64.sys";
}

bool UpdateDriversIni(uint64_t seCiCallbacks, uint64_t safeFunction) {
    std::wstring filePath = GetDriversIniPath();
    
    if (GetFileAttributesW(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcout << L"[*] drivers.ini not found - skipping file update\n";
        return false;
    }
    
    std::wcout << L"[*] Updating drivers.ini with current offsets...\n";
    
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] Failed to open drivers.ini for reading\n";
        return false;
    }
    
    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return false;
    }
    
    std::vector<BYTE> buffer(fileSize);
    DWORD bytesRead = 0;
    
    if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr)) {
        CloseHandle(hFile);
        std::wcout << L"[-] Failed to read drivers.ini\n";
        return false;
    }
    
    CloseHandle(hFile);
    
    // Convert bytes to wstring (skip BOM if present)
    std::wstring content;
    if (fileSize >= 2 && buffer[0] == 0xFF && buffer[1] == 0xFE) {
        content = std::wstring((wchar_t*)(buffer.data() + 2), (fileSize - 2) / sizeof(wchar_t));
    }
    else {
        content = std::wstring((wchar_t*)buffer.data(), fileSize / sizeof(wchar_t));
    }

    // Find [Config] section
    size_t configPos = content.find(L"[Config]");
    if (configPos == std::wstring::npos) {
        std::wcout << L"[-] [Config] section not found\n";
        return false;
    }

    // Find IoControlCode_Write line as our anchor point
    size_t anchorPos = content.find(L"IoControlCode_Write=", configPos);
    if (anchorPos == std::wstring::npos) {
        std::wcout << L"[-] IoControlCode_Write not found in [Config] section\n";
        return false;
    }

    // Find the end of the anchor line
    size_t anchorLineEnd = content.find(L'\n', anchorPos);
    if (anchorLineEnd == std::wstring::npos) {
        anchorLineEnd = content.length();
    }

    // Insert position is right after the anchor line
    size_t insertPosition = anchorLineEnd;

    // Prepare expected values
    std::wstringstream expectedSeCi;
    expectedSeCi << L"Offset_SeCiCallbacks=0x" << std::hex << std::uppercase << seCiCallbacks;

    std::wstringstream expectedSafe;
    expectedSafe << L"Offset_SafeFunction=0x" << std::hex << std::uppercase << safeFunction;

    // Check if current values are already correct
    bool seCiNeedsUpdate = true;
    bool safeNeedsUpdate = true;

    // Find section boundaries for checking existing values
    size_t nextSection = content.find(L"\n[", configPos + 1);
    size_t sectionEnd = (nextSection != std::wstring::npos) ? nextSection : content.length();

    size_t seCiPos = content.find(L"Offset_SeCiCallbacks=", configPos);
    if (seCiPos != std::wstring::npos && seCiPos < sectionEnd) {
        size_t lineEnd = content.find(L'\n', seCiPos);
        if (lineEnd == std::wstring::npos) lineEnd = content.length();
        std::wstring currentLine = content.substr(seCiPos, lineEnd - seCiPos);
        if (currentLine == expectedSeCi.str()) {
            seCiNeedsUpdate = false;
        }
    }

    size_t safePos = content.find(L"Offset_SafeFunction=", configPos);
    if (safePos != std::wstring::npos && safePos < sectionEnd) {
        size_t lineEnd = content.find(L'\n', safePos);
        if (lineEnd == std::wstring::npos) lineEnd = content.length();
        std::wstring currentLine = content.substr(safePos, lineEnd - safePos);
        if (currentLine == expectedSafe.str()) {
            safeNeedsUpdate = false;
        }
    }

    // If both values are already correct, skip writing
    if (!seCiNeedsUpdate && !safeNeedsUpdate) {
        std::wcout << L"[+] drivers.ini already has correct offsets - no update needed\n";
        return true;
    }

    // Update existing lines or add new ones
    if (seCiNeedsUpdate) {
        if (seCiPos != std::wstring::npos && seCiPos < sectionEnd) {
            // Update existing line
            size_t lineEnd = content.find(L'\n', seCiPos);
            if (lineEnd == std::wstring::npos) lineEnd = content.length();
            content.replace(seCiPos, lineEnd - seCiPos, expectedSeCi.str());
        } else {
            // Add new line after IoControlCode_Write
            std::wstring newLine = L"\n" + expectedSeCi.str();
            content.insert(insertPosition, newLine);
            insertPosition += newLine.length(); // Update insert position for next line
        }
    }

    if (safeNeedsUpdate) {
        // Re-find after potential modifications
        safePos = content.find(L"Offset_SafeFunction=", configPos);
        if (safePos != std::wstring::npos && safePos < sectionEnd) {
            // Update existing line
            size_t lineEnd = content.find(L'\n', safePos);
            if (lineEnd == std::wstring::npos) lineEnd = content.length();
            content.replace(safePos, lineEnd - safePos, expectedSafe.str());
        } else {
            // Add new line after IoControlCode_Write (or after previously added line)
            std::wstring newLine = L"\n" + expectedSafe.str();
            content.insert(insertPosition, newLine);
        }
    }

    // Write back with UTF-16 LE BOM
    hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] Failed to open drivers.ini for writing (run as Administrator)\n";
        return false;
    }
    
    BYTE bom[2] = { 0xFF, 0xFE };
    DWORD bytesWritten = 0;
    WriteFile(hFile, bom, 2, &bytesWritten, nullptr);
    
    DWORD contentSize = (DWORD)(content.length() * sizeof(wchar_t));
    if (!WriteFile(hFile, content.c_str(), contentSize, &bytesWritten, nullptr)) {
        CloseHandle(hFile);
        std::wcout << L"[-] Failed to write to drivers.ini\n";
        return false;
    }
    
    CloseHandle(hFile);
    
    std::wcout << L"[+] Updated drivers.ini:\n";
    std::wcout << L"    Offset_SeCiCallbacks=0x" << std::hex << std::uppercase << seCiCallbacks << L"\n";
    std::wcout << L"    Offset_SafeFunction=0x" << std::uppercase << safeFunction << std::dec << L"\n";
    
    return true;
}

bool SaveOffsetsToRegistry(uint64_t seCiCallbacks, uint64_t safeFunction, const std::wstring& buildInfo) {
    HKEY hKey;
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timestamp[32];
    swprintf_s(timestamp, L"%04d%02d%02d_%02d%02d%02d", 
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    std::wstring historyPath = L"Software\\drvloader\\History\\";
    historyPath += timestamp;
    
    LSTATUS result = RegCreateKeyExW(HKEY_CURRENT_USER, historyPath.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    
    if (result != ERROR_SUCCESS) {
        std::wcout << L"[-] Failed to create registry key (error: " << result << L")\n";
        return false;
    }
    
    wchar_t timestampStr[64];
    swprintf_s(timestampStr, L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    RegSetValueExW(hKey, L"Timestamp", 0, REG_SZ, (BYTE*)timestampStr, 
        (DWORD)((wcslen(timestampStr) + 1) * sizeof(wchar_t)));
    
    DWORD seCiDword = (DWORD)seCiCallbacks;
    RegSetValueExW(hKey, L"SeCiCallbacks", 0, REG_DWORD, (BYTE*)&seCiDword, sizeof(DWORD));
    
    DWORD safeDword = (DWORD)safeFunction;
    RegSetValueExW(hKey, L"SafeFunction", 0, REG_DWORD, (BYTE*)&safeDword, sizeof(DWORD));
    
    RegSetValueExW(hKey, L"BuildInfo", 0, REG_SZ, (BYTE*)buildInfo.c_str(),
        (DWORD)((buildInfo.length() + 1) * sizeof(wchar_t)));
    
    RegCloseKey(hKey);
    
    std::wcout << L"[+] Saved offsets to registry: HKCU\\Software\\drvloader\\History\\" << timestamp << L"\n";
    
    // Keep only the last 8 history entries
    HKEY hHistoryKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\History", 0, 
        KEY_READ | KEY_WRITE, &hHistoryKey) == ERROR_SUCCESS) {
        
        std::vector<std::wstring> entries;
        wchar_t subKeyName[256];
        DWORD index = 0;
        
        while (RegEnumKeyW(hHistoryKey, index++, subKeyName, 256) == ERROR_SUCCESS) {
            entries.push_back(subKeyName);
        }
        
        if (entries.size() > 8) {
            std::sort(entries.begin(), entries.end());
            for (size_t i = 0; i < entries.size() - 8; i++) {
                RegDeleteTreeW(hHistoryKey, entries[i].c_str());
            }
        }
        
        RegCloseKey(hHistoryKey);
    }
    
    return true;
}

bool SaveOriginalCallbackToRegistry(uint64_t callback) {
    HKEY hKey;
    
    LSTATUS result = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\LatestState", 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    
    if (result != ERROR_SUCCESS) {
        std::wcout << L"[-] Failed to create LatestState registry key\n";
        return false;
    }
    
    RegSetValueExW(hKey, L"OriginalCallback", 0, REG_QWORD, (BYTE*)&callback, sizeof(uint64_t));
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timestampStr[64];
    swprintf_s(timestampStr, L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    RegSetValueExW(hKey, L"PatchTimestamp", 0, REG_SZ, (BYTE*)timestampStr,
        (DWORD)((wcslen(timestampStr) + 1) * sizeof(wchar_t)));
    
    DWORD isPatched = 1;
    RegSetValueExW(hKey, L"IsPatched", 0, REG_DWORD, (BYTE*)&isPatched, sizeof(DWORD));
    
    RegCloseKey(hKey);
    
    std::wcout << L"[+] Saved original callback to registry: 0x" << std::hex << std::uppercase 
               << callback << std::dec << L"\n";
    
    return true;
}

std::optional<uint64_t> LoadOriginalCallbackFromRegistry() {
    HKEY hKey;
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\LatestState", 0, 
        KEY_READ, &hKey) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    
    uint64_t callback = 0;
    DWORD dataSize = sizeof(uint64_t);
    
    if (RegQueryValueExW(hKey, L"OriginalCallback", nullptr, nullptr, 
        (BYTE*)&callback, &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return std::nullopt;
    }
    
    RegCloseKey(hKey);
    
    std::wcout << L"[+] Loaded OriginalCallback from registry: 0x" << std::hex << std::uppercase 
               << callback << std::dec << L"\n";
    
    return callback;
}

bool ClearPatchStateFromRegistry() {
    HKEY hKey;
    
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\LatestState", 0,
        KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return false;
    }
    
    RegDeleteValueW(hKey, L"OriginalCallback");
    RegDeleteValueW(hKey, L"PatchTimestamp");
    
    DWORD isPatched = 0;
    RegSetValueExW(hKey, L"IsPatched", 0, REG_DWORD, (BYTE*)&isPatched, sizeof(DWORD));
    
    RegCloseKey(hKey);
    
    std::wcout << L"[+] Cleared patch state from registry\n";
    return true;
}

bool CheckAndDisableMemoryIntegrity() {
    HKEY hKey;
    LSTATUS result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
        L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        0, KEY_READ | KEY_WRITE, &hKey);
    
    if (result != ERROR_SUCCESS) {
        return true;
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
        std::wcin.clear();
        std::wcin.ignore((std::numeric_limits<std::streamsize>::max)(), L'\n');
        
        if (choice == L'Y' || choice == L'y') {
            enabled = 0;
            RegSetValueExW(hKey, L"Enabled", 0, REG_DWORD, (const BYTE*)&enabled, sizeof(enabled));
            RegDeleteValueW(hKey, L"WasEnabledBy");
            
            std::wcout << L"[+] Memory Integrity disabled. System will reboot to apply changes.\n";
            std::wcout << L"[+] Press any key to continue with reboot...";
            std::wcout.flush();
            FlushConsoleInputBuffer(GetStdHandle(STD_INPUT_HANDLE));
            _getwch();
            std::wcout << L"\n";
            
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

} // namespace ConfigManager