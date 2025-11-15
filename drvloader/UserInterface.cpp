#include "UserInterface.h"
#include "DrvCore.h"
#include "ConfigManager.h"
#include <iostream>
#include <limits>
#include <conio.h>
#include <vector>

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

void UI::DisplayOffsetInfo(DrvLoader& loader) {
    std::wcout << L"\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"          OFFSET INFORMATION FOR EXTERNAL TOOLS\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"\n";
    
	// USE THE NEW METHOD - NO DRIVER NEEDED!
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
    
    std::wcout << L"[2] Show and save offset information for external tools\n";
    std::wcout << L"[3] Exit\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"\nSelect option: ";
}

} // namespace UI
