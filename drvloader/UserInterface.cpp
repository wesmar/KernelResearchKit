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

void DisplayOffsetInfo(DrvLoader& loader) {
    std::wcout << L"\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"          OFFSET INFORMATION FOR EXTERNAL TOOLS\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"\n";
    
    // Get offsets without driver installation (uses cache or downloads PDB)
    uint64_t seCiCallbacks, safeFunction;
    if (!loader.GetSymbolOffsets(&seCiCallbacks, &safeFunction)) {
        std::wcout << L"[-] Failed to get symbol offsets\n";
        WaitForAnyKey(L"\nPress any key to return to menu...");
        return;
    }
    
    // Load the offsets to display them
    uint64_t seCiCallbacksOffset, safeFunctionOffset;
    if (!ConfigManager::LoadOffsetsFromWindowsMiniPdb(&seCiCallbacksOffset, &safeFunctionOffset)) {
        std::wcout << L"[-] Failed to load offsets\n";
        WaitForAnyKey(L"\nPress any key to return to menu...");
        return;
    }
    
    std::wcout << L"[Config] section in drivers.ini:\n";
    std::wcout << L"....................................\n";
    
    std::wcout << L"Offset_SeCiCallbacks=0x" << std::hex << std::uppercase << seCiCallbacksOffset << std::dec << L"\n";
    std::wcout << L"Offset_Callback=0x20\n";
    std::wcout << L"Offset_SafeFunction=0x" << std::hex << std::uppercase << safeFunctionOffset << std::dec << L"\n";
    
    std::wcout << L"....................................\n\n";
    
    // Save to drivers.ini and registry
    bool driversIniUpdated = ConfigManager::UpdateDriversIni(seCiCallbacksOffset, safeFunctionOffset);
    
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
    
    bool registrySaved = ConfigManager::SaveOffsetsToRegistry(seCiCallbacksOffset, safeFunctionOffset, buildInfo);
    
    std::wcout << L"\n[*] Save status:\n";
    if (driversIniUpdated) {
        std::wcout << L"    [+] Saved to C:\\Windows\\drivers.ini\n";
    } else {
        std::wcout << L"    [-] drivers.ini not found\n";
    }
    
    if (registrySaved) {
        std::wcout << L"    [+] Saved to HKCU\\Software\\drvloader\n";
    }
    
    std::wcout << L"    [+] Saved to C:\\Windows\\symbols\\ntkrnlmp.pdb\\{GUID}\\ntkrnlmp.mpdb\n";
    std::wcout << L"    [!] BootBypass will auto-detect this file\n";
    
    std::wcout << L"\n";
    std::wcout << L"Note: These offsets are specific to your current ntoskrnl.exe build.\n";
    std::wcout << L"After Windows updates, regenerate these values.\n";
    
    WaitForAnyKey(L"\nPress any key to return to menu...");
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
    
    std::wcout << L"[2] Load unsigned driver (auto DSE patch/unpatch)\n";
    std::wcout << L"[3] Show and save offset information for external tools\n";
    std::wcout << L"[4] Exit\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"\nSelect option: ";
}

// ============================================================================
// DRIVER HISTORY DISPLAY
// ============================================================================

void DisplayDriverHistory() {
    std::wcout << L"\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"                   DRIVER LOAD HISTORY\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"\n";
    
    auto history = ConfigManager::GetDriverLoadHistory();
    
    if (history.empty()) {
        std::wcout << L"No driver load history found.\n";
        WaitForAnyKey(L"\nPress any key to return...");
        return;
    }
    
    // StartType lookup table
    const wchar_t* startTypeNames[] = {
        L"BOOT", L"SYSTEM", L"AUTO", L"DEMAND", L"DISABLED"
    };
    
    for (size_t i = 0; i < history.size(); i++) {
        const auto& entry = history[i];
        
        std::wcout << L"[" << (i + 1) << L"] " << entry.serviceName << L"\n";
        std::wcout << L"    Path: " << entry.driverPath << L"\n";
        std::wcout << L"    Time: " << entry.timestamp << L"\n";
        std::wcout << L"    StartType: " << entry.startType << L" (";
        
        if (entry.startType <= 4) {
            std::wcout << startTypeNames[entry.startType];
        } else {
            std::wcout << L"UNKNOWN";
        }
        
        std::wcout << L")\n";
        std::wcout << L"    Result: " << (entry.success ? L"SUCCESS" : L"FAILED") << L"\n";
        std::wcout << L"\n";
    }
    
    std::wcout << L"Total entries: " << history.size() << L"/8\n";
    
    WaitForAnyKey(L"\nPress any key to return...");
}

// ============================================================================
// USER INPUT PROMPTS
// ============================================================================

std::wstring PromptForDriverPath() {
    std::wcout << L"\n";
    std::wcout << L"Enter driver path:\n";
    std::wcout << L"  Examples:\n";
    std::wcout << L"    kvckbd           -> C:\\Windows\\System32\\drivers\\kvckbd.sys\n";
    std::wcout << L"    kvckbd.sys       -> C:\\Windows\\System32\\drivers\\kvckbd.sys\n";
    std::wcout << L"    C:\\test.sys      -> C:\\test.sys\n";
    std::wcout << L"\n";
    std::wcout << L"Path: ";
    
    std::wstring input;
    std::getline(std::wcin, input);
    
    // Trim whitespace
    input.erase(0, input.find_first_not_of(L" \t"));
    input.erase(input.find_last_not_of(L" \t") + 1);
    
    return input;
}

DWORD PromptForStartType() {
    std::wcout << L"\n";
    std::wcout << L"Select StartType:\n";
    std::wcout << L"  [0] BOOT      - Load during boot\n";
    std::wcout << L"  [1] SYSTEM    - Load by IO Manager\n";
    std::wcout << L"  [2] AUTO      - Load by Service Control Manager\n";
    std::wcout << L"  [3] DEMAND    - Manual start (default, recommended)\n";
    std::wcout << L"  [4] DISABLED  - Driver disabled\n";
    std::wcout << L"\n";
    std::wcout << L"Choice [0-4, default 3]: ";
    
    std::wstring input;
    std::getline(std::wcin, input);
    
    // Default to DEMAND (3) if empty or invalid
    if (input.empty()) {
        return SERVICE_DEMAND_START;
    }
    
    int choice = _wtoi(input.c_str());
    if (choice < 0 || choice > 4) {
        std::wcout << L"[!] Invalid choice, using default (3 - DEMAND)\n";
        return SERVICE_DEMAND_START;
    }
    
    return static_cast<DWORD>(choice);
}

// ============================================================================
// LOAD DRIVER SUBMENU
// ============================================================================

void DisplayLoadDriverMenu(DrvLoader& loader, bool fromCLI) {
    while (true) {
        std::wcout << L"\n";
        std::wcout << L"=========================================================\n";
        std::wcout << L"                  LOAD UNSIGNED DRIVER\n";
        std::wcout << L"=========================================================\n";
        std::wcout << L"\n";
        
        // Display recent history
        auto history = ConfigManager::GetDriverLoadHistory();
        
        if (!history.empty()) {
            std::wcout << L"Recent drivers (last " << history.size() << L"):\n";
            std::wcout << L"---------------------------------------------------------\n";
            
            for (size_t i = 0; i < history.size() && i < 8; i++) {
                const auto& entry = history[i];
                
                std::wcout << L"[" << (i + 1) << L"] " << entry.serviceName;
                std::wcout << L" (" << entry.timestamp << L")";
                std::wcout << L" [" << (entry.success ? L"SUCCESS" : L"FAILED") << L"]\n";
            }
            
            std::wcout << L"\n";
        }
        
        std::wcout << L"Options:\n";
        std::wcout << L"---------------------------------------------------------\n";
        
        if (!history.empty()) {
            std::wcout << L"[1-" << history.size() << L"] Load driver from history\n";
        }
        
        std::wcout << L"[L] Load new driver\n";
        std::wcout << L"[U] Unload driver (stop and remove service)\n";
        std::wcout << L"[H] Show full history\n";
        std::wcout << L"[C] Clear history\n";
        
        // Only show "Return to main menu" if not launched from CLI
        if (!fromCLI) {
            std::wcout << L"[R] Return to main menu\n";
        }
        
        std::wcout << L"[X] Exit program\n";
        std::wcout << L"=========================================================\n";
        std::wcout << L"\nSelect option: ";
        
        std::wstring input;
        std::getline(std::wcin, input);
        
        // Trim whitespace
        input.erase(0, input.find_first_not_of(L" \t"));
        input.erase(input.find_last_not_of(L" \t") + 1);
        
        if (input.empty()) {
            continue;
        }
        
        // Convert to uppercase for command comparison
        std::wstring cmd = input;
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::towupper);
        
		// Handle commands
		if (cmd == L"R" && !fromCLI) {
			return;
		}
		else if (cmd == L"X") {
			std::wcout << L"\nExiting...\n";
			exit(0);
		}
		else if (cmd == L"H") {
			DisplayDriverHistory();
		}
		else if (cmd == L"C") {
			std::wcout << L"\n[!] Are you sure you want to clear all history? (Y/N): ";
			wchar_t confirm;
			std::wcin >> confirm;
			ClearInputBuffer();
			
			if (confirm == L'Y' || confirm == L'y') {
				ConfigManager::ClearDriverLoadHistory();
				std::wcout << L"[+] History cleared\n";
			}
			
			WaitForAnyKey(L"\nPress any key to continue...");
		}
		else if (cmd == L"L") {
            // Load new driver
            std::wstring driverPath = PromptForDriverPath();
            
            if (driverPath.empty()) {
                std::wcout << L"[-] No driver path specified\n";
                WaitForAnyKey(L"\nPress any key to continue...");
                continue;
            }
            
            DWORD startType = PromptForStartType();
            
            std::wcout << L"\n";
            bool success = loader.LoadDriver(driverPath, startType);
            
            if (success) {
                std::wcout << L"\n[SUCCESS] Driver loaded successfully!\n";
            } else {
                std::wcout << L"\n[FAILED] Driver load unsuccessful\n";
            }
            
            WaitForAnyKey(L"\nPress any key to continue...");
        }
        else if (cmd == L"U") {
            // Unload driver
            std::wcout << L"\nEnter service name to unload: ";
            std::wstring serviceName;
            std::getline(std::wcin, serviceName);
            
            if (serviceName.empty()) {
                std::wcout << L"[-] No service name specified\n";
                WaitForAnyKey(L"\nPress any key to continue...");
                continue;
            }
            
            std::wcout << L"\n";
            bool success = loader.UnloadDriver(serviceName);
            
            if (success) {
                std::wcout << L"\n[SUCCESS] Driver unloaded successfully!\n";
            } else {
                std::wcout << L"\n[FAILED] Driver unload unsuccessful\n";
            }
            
            WaitForAnyKey(L"\nPress any key to continue...");
        }
        else {
            // Try to parse as number (history selection)
            int choice = _wtoi(input.c_str());
            
            if (choice > 0 && choice <= static_cast<int>(history.size())) {
                // Load from history
                const auto& entry = history[choice - 1];
                
                std::wcout << L"\n[*] Loading from history:\n";
                std::wcout << L"    Driver: " << entry.serviceName << L"\n";
                std::wcout << L"    Path: " << entry.driverPath << L"\n";
                std::wcout << L"    StartType: " << entry.startType << L"\n";
                std::wcout << L"\n";
                
                bool success = loader.LoadDriver(entry.driverPath, entry.startType);
                
                if (success) {
                    std::wcout << L"\n[SUCCESS] Driver loaded successfully!\n";
                } else {
                    std::wcout << L"\n[FAILED] Driver load unsuccessful\n";
                }
                
                WaitForAnyKey(L"\nPress any key to continue...");
            }
            else {
                std::wcout << L"\n[ERROR] Invalid option selected.\n";
                WaitForAnyKey(L"\nPress any key to continue...");
            }
        }
    }
}

} // namespace UI