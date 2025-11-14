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

void DisplayOffsetInfo(DrvLoader& loader) {
    std::wcout << L"\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"          OFFSET INFORMATION FOR EXTERNAL TOOLS\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"\n";
    std::wcout << L"If you are using native/system level tools (e.g., BootBypass)\n";
    std::wcout << L"that require manual offset configuration in drivers.ini,\n";
    std::wcout << L"use the following values for your current Windows build:\n";
    std::wcout << L"\n";
    
    WCHAR systemRoot[MAX_PATH];
    GetSystemDirectoryW(systemRoot, MAX_PATH);
    std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";
    
    auto seCiCallbacksOffset = loader.symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"SeCiCallbacks");
    auto zwFlushOffset = loader.symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"ZwFlushInstructionCache");
    
    if (seCiCallbacksOffset && zwFlushOffset) {
        std::wcout << L"[Patch1] section in drivers.ini:\n";
        std::wcout << L"....................................\n";
        
        std::wcout << L"Offset_SeCiCallbacks=0x" << std::hex << std::uppercase << *seCiCallbacksOffset << std::dec << L"\n";
        std::wcout << L"Offset_Callback=0x20\n";
        std::wcout << L"Offset_SafeFunction=0x" << std::hex << std::uppercase << *zwFlushOffset << std::dec << L"\n";
        
        std::wcout << L"....................................\n\n";
        
        bool driversIniUpdated = ConfigManager::UpdateDriversIni(*seCiCallbacksOffset, *zwFlushOffset);
        
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
        
        bool registrySaved = ConfigManager::SaveOffsetsToRegistry(*seCiCallbacksOffset, *zwFlushOffset, buildInfo);
        
        std::wcout << L"\n[*] Save status:\n";
        if (driversIniUpdated) {
            std::wcout << L"    [+] Saved to C:\\Windows\\drivers.ini\n";
        } else {
            std::wcout << L"    [-] drivers.ini not found\n";
        }
        
        if (registrySaved) {
            std::wcout << L"    [+] Saved to HKCU\\Software\\drvloader\n";
        }
    } else {
        std::wcout << L"[-] Failed to retrieve offsets. Ensure symbols are downloaded.\n";
    }
    
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
    
    std::wcout << L"[2] Show offset information for external tools\n";
    std::wcout << L"[3] Exit\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"\nSelect option: ";
}

} // namespace UI
