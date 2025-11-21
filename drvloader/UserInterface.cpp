#include "UserInterface.h"
#include "DrvCore.h"
#include "ConfigManager.h"
#include <iostream>
#include <limits>
#include <conio.h>
#include <vector>
#include <algorithm>

#pragma comment(lib, "version.lib")

namespace UI {

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

void ClearInputBuffer() {
    std::wcin.clear();
    std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), L'\n');
}

void WaitForAnyKey(const std::wstring& message) {
    std::wcout << message;
    std::wcout.flush();
    FlushConsoleInputBuffer(GetStdHandle(STD_INPUT_HANDLE));
    _getwch();
    std::wcout << L"\n";
}

// ============================================================================
// OFFSET INFO & SAVING
// ============================================================================

void DisplayOffsetInfo(DrvLoader& loader, bool waitForKey) {
    std::wcout << L"\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"          OFFSET INFORMATION FOR EXTERNAL TOOLS\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"\n";
    
    // 1. Get symbol offsets
    uint64_t seCiCallbacks, safeFunction;
    if (!loader.GetSymbolOffsets(&seCiCallbacks, &safeFunction)) {
        std::wcout << L"[-] Failed to get symbol offsets\n";
        if (waitForKey) WaitForAnyKey(L"\nPress any key to return to menu...");
        return;
    }
    
    // 2. Load cached offsets to verify correct paths (optional verification step)
    uint64_t seCiCallbacksOffset, safeFunctionOffset;
    if (!ConfigManager::LoadOffsetsFromWindowsMiniPdb(&seCiCallbacksOffset, &safeFunctionOffset)) {
        seCiCallbacksOffset = seCiCallbacks;
        safeFunctionOffset = safeFunction;
    }
    
    // 3. Display in legacy INI style
    std::wcout << L"[Config] section in drivers.ini:\n";
    std::wcout << L"....................................\n";
    
    std::wcout << L"Offset_SeCiCallbacks=0x" << std::hex << std::uppercase << seCiCallbacksOffset << std::dec << L"\n";
    std::wcout << L"Offset_Callback=0x20\n";
    std::wcout << L"Offset_SafeFunction=0x" << std::hex << std::uppercase << safeFunctionOffset << std::dec << L"\n";
    
    std::wcout << L"....................................\n\n";
    
    // 4. Save to files and registry
    bool driversIniUpdated = ConfigManager::UpdateDriversIni(seCiCallbacksOffset, safeFunctionOffset);
    
    std::wstring buildInfo = ConfigManager::GetWindowsBuildNumber();
    bool registrySaved = ConfigManager::SaveOffsetsToRegistry(seCiCallbacksOffset, safeFunctionOffset, buildInfo);
    
    std::wcout << L"\n[*] Save status:\n";
    if (driversIniUpdated) {
        std::wcout << L"    [+] Saved to C:\\Windows\\drivers.ini\n";
    } else {
        std::wcout << L"    [-] drivers.ini not found (create it manually or check permissions)\n";
    }
    
    if (registrySaved) {
        std::wcout << L"    [+] Saved to HKCU\\Software\\drvloader\n";
    }
    
    std::wcout << L"    [+] Saved to C:\\Windows\\symbols\\ntkrnlmp.pdb\\{GUID}\\ntkrnlmp.mpdb\n";
    std::wcout << L"    [!] BootBypass will auto-detect this file\n";
    
    std::wcout << L"\n";
    std::wcout << L"Note: These offsets are specific to your current ntoskrnl.exe build.\n";
    std::wcout << L"After Windows updates, regenerate these values.\n";
    
    // Control flow: pause only if requested (Interactive vs CLI)
    if (waitForKey) {
        WaitForAnyKey(L"\nPress any key to return to menu...");
    }
}

// ============================================================================
// MAIN MENU
// ============================================================================

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
    
    std::wcout << L"[2] Load unsigned driver (auto DSE patch/unpatch)\n";
    std::wcout << L"[3] Show and save offset information for external tools\n";
    std::wcout << L"[4] Exit\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"\nSelect option: ";
}

// ============================================================================
// HISTORY DISPLAY
// ============================================================================

void DisplayDriverHistory() {
    std::wcout << L"\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"                   DRIVER LOAD HISTORY\n";
    std::wcout << L"=========================================================\n";
    
    auto history = ConfigManager::GetDriverLoadHistory();
    
    if (history.empty()) {
        std::wcout << L"No driver load history found.\n";
        WaitForAnyKey(L"\nPress any key to return...");
        return;
    }
    
    for (size_t i = 0; i < history.size(); i++) {
        const auto& entry = history[i];
        std::wcout << L"[" << (i + 1) << L"] " << entry.serviceName << L"\n";
        std::wcout << L"    Path: " << entry.driverPath << L"\n";
        std::wcout << L"    Time: " << entry.timestamp << L"\n";
        std::wcout << L"    Result: " << (entry.success ? L"SUCCESS" : L"FAILED") << L"\n\n";
    }
    
    WaitForAnyKey(L"Press any key to return...");
}

// ============================================================================
// INPUT HELPERS
// ============================================================================

std::wstring PromptForDriverPath() {
    std::wcout << L"\n";
    std::wcout << L"Enter driver path (e.g., 'kvckbd' or 'C:\\test.sys'):\n";
    std::wcout << L"Path: ";
    
    std::wstring input;
    std::getline(std::wcin, input);
    
    input.erase(0, input.find_first_not_of(L" \t"));
    input.erase(input.find_last_not_of(L" \t") + 1);
    
    return input;
}

DWORD PromptForStartType() {
    std::wcout << L"\nSelect StartType:\n";
    std::wcout << L"  [0] BOOT\n";
    std::wcout << L"  [1] SYSTEM\n";
    std::wcout << L"  [2] AUTO\n";
    std::wcout << L"  [3] DEMAND (default)\n";
    std::wcout << L"Choice [0-4]: ";
    
    std::wstring input;
    std::getline(std::wcin, input);
    
    if (input.empty()) return SERVICE_DEMAND_START;
    
    int choice = _wtoi(input.c_str());
    if (choice < 0 || choice > 4) return SERVICE_DEMAND_START;
    
    return static_cast<DWORD>(choice);
}

// ============================================================================
// DRIVER OPERATIONS SUBMENU
// ============================================================================

void DisplayLoadDriverMenu(DrvLoader& loader, bool fromCLI) {
    while (true) {
        std::wcout << L"\n";
        std::wcout << L"=========================================================\n";
        std::wcout << L"                  LOAD / MANAGE DRIVER\n";
        std::wcout << L"=========================================================\n";
        std::wcout << L"\n";
        
        // Display recent history
        auto history = ConfigManager::GetDriverLoadHistory();
        if (!history.empty()) {
            std::wcout << L"Recent drivers:\n";
            for (size_t i = 0; i < history.size() && i < 5; i++) {
                std::wcout << L"[" << (i + 1) << L"] " << history[i].serviceName << L" (" 
                           << (history[i].success ? L"OK" : L"FAIL") << L")\n";
            }
            std::wcout << L"---------------------------------------------------------\n";
        }
        
        std::wcout << L"[L] Load new driver\n";
        std::wcout << L"[R] Reload driver (Stop -> Patch -> Start -> Restore)\n";
        std::wcout << L"[S] Stop driver (Stop service only)\n";
        std::wcout << L"[U] Remove driver (Stop service and delete)\n";
        std::wcout << L"[H] Show full history\n";
        std::wcout << L"[C] Clear history\n";
        
        if (!fromCLI) {
            std::wcout << L"[B] Return to main menu\n";
        }
        
        std::wcout << L"=========================================================\n";
        std::wcout << L"\nSelect option: ";
        
        std::wstring input;
        std::getline(std::wcin, input);
        
        input.erase(0, input.find_first_not_of(L" \t"));
        input.erase(input.find_last_not_of(L" \t") + 1);
        
        if (input.empty()) continue;
        
        std::wstring cmd = input;
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::towupper);
        
        // Handle Commands
        if (cmd == L"B" && !fromCLI) {
            return;
        }
        else if (cmd == L"H") {
            DisplayDriverHistory();
        }
        else if (cmd == L"C") {
            ConfigManager::ClearDriverLoadHistory();
            std::wcout << L"[+] History cleared\n";
        }
        else if (cmd == L"L") {
            std::wstring path = PromptForDriverPath();
            if (!path.empty()) {
                DWORD type = PromptForStartType();
                bool success = loader.LoadDriver(path, type);
                std::wcout << (success ? L"\n[SUCCESS] Driver loaded!\n" : L"\n[FAILED] Operation failed\n");
                WaitForAnyKey(L"Press any key...");
            }
        }
        else if (cmd == L"R") {
            std::wstring path = PromptForDriverPath();
            if (!path.empty()) {
                bool success = loader.ReloadDriver(path);
                std::wcout << (success ? L"\n[SUCCESS] Driver reloaded!\n" : L"\n[FAILED] Operation failed\n");
                WaitForAnyKey(L"Press any key...");
            }
        }
        else if (cmd == L"S") {
            std::wcout << L"\nEnter service name to stop: ";
            std::wstring name;
            std::getline(std::wcin, name);
            if (!name.empty()) {
                bool success = loader.StopDriver(name);
                std::wcout << (success ? L"\n[SUCCESS] Driver stopped!\n" : L"\n[FAILED] Operation failed\n");
                WaitForAnyKey(L"Press any key...");
            }
        }
        else if (cmd == L"U") {
            std::wcout << L"\nEnter service name to remove: ";
            std::wstring name;
            std::getline(std::wcin, name);
            if (!name.empty()) {
                bool success = loader.RemoveDriver(name);
                std::wcout << (success ? L"\n[SUCCESS] Driver removed!\n" : L"\n[FAILED] Operation failed\n");
                WaitForAnyKey(L"Press any key...");
            }
        }
        else {
            // Try loading from history by number
            int choice = _wtoi(input.c_str());
            if (choice > 0 && choice <= static_cast<int>(history.size())) {
                const auto& entry = history[choice - 1];
                std::wcout << L"\n[*] Loading from history: " << entry.serviceName << L"\n";
                bool success = loader.LoadDriver(entry.driverPath, entry.startType);
                std::wcout << (success ? L"\n[SUCCESS] Driver loaded!\n" : L"\n[FAILED] Operation failed\n");
                WaitForAnyKey(L"Press any key...");
            }
        }
    }
}

} // namespace UI