#include "UserInterface.h"
#include "DrvCore.h"
#include "ConfigManager.h"
#include <iostream>
#include <algorithm>

// Forward declarations for CLI handlers
int HandleBypassCommand(DrvLoader& loader);
int HandleRestoreCommand(DrvLoader& loader);
int HandleStatusCommand(DrvLoader& loader);
int HandleLoadCommand(DrvLoader& loader, int argc, wchar_t* argv[]);
int HandleUnloadCommand(DrvLoader& loader, int argc, wchar_t* argv[]);
int HandleHistoryCommand();
int HandleOffsetsCommand(DrvLoader& loader);
void ShowHelp();

int wmain(int argc, wchar_t* argv[]) {
    UI::DisplayBanner();

    if (!ConfigManager::CheckAndDisableMemoryIntegrity()) {
        std::wcout << L"[-] Failed to check Memory Integrity status\n";
        return 1;
    }

    DrvLoader loader;

    if (!loader.Initialize()) {
        std::wcout << L"\n[FAILED] Could not initialize loader\n";
        UI::WaitForAnyKey(L"\nPress any key to exit...");
        return 1;
    }

    // CLI mode
    if (argc > 1) {
        std::wstring cmd = argv[1];
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::towlower);
        
        if (cmd == L"bypass") {
            return HandleBypassCommand(loader);
        }
        else if (cmd == L"restore") {
            return HandleRestoreCommand(loader);
        }
        else if (cmd == L"status") {
            return HandleStatusCommand(loader);
        }
        else if (cmd == L"ld") {
            return HandleLoadCommand(loader, argc, argv);
        }
        else if (cmd == L"ud") {
            return HandleUnloadCommand(loader, argc, argv);
        }
        else if (cmd == L"history") {
            return HandleHistoryCommand();
        }
        else if (cmd == L"offsets") {
            return HandleOffsetsCommand(loader);
        }
        else if (cmd == L"help" || cmd == L"/?") {
            ShowHelp();
            return 0;
        }
        else {
            std::wcout << L"[-] Unknown command: " << argv[1] << L"\n\n";
            ShowHelp();
            return 1;
        }
    }

    // Interactive mode
    std::wcout << L"DSE Bypass Tool - Universal (Dynamic PDB Symbol Loading)\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"Technique: SeCiCallbacks CiValidateImageHeader replacement\n";
    std::wcout << L"Vulnerable driver: RTCore64 (stored in binary resources)\n";
    std::wcout << L"Symbol resolution: Microsoft Symbol Server (automatic)\n";

    bool isPatched = false;
    if (!loader.CheckDSEStatus(isPatched)) {
        std::wcout << L"\n[FAILED] Could not determine DSE status\n";
        UI::WaitForAnyKey(L"\nPress any key to exit...");
        return 1;
    }

    while (true) {
        UI::DisplayMenu(isPatched);

        int choice = 0;
        std::wcin >> choice;
        UI::ClearInputBuffer();

        bool success = false;

        if (choice == 1) {
            if (isPatched) {
                success = loader.RestoreDSE();
                if (success) {
                    std::wcout << L"\n[SUCCESS] DSE has been restored. Driver signature enforcement is active.\n";
                    isPatched = false;
                }
                else {
                    std::wcout << L"\n[FAILED] DSE restoration was unsuccessful.\n";
                }
            }
            else {
                success = loader.BypassDSE();
                if (success) {
                    std::wcout << L"\n[SUCCESS] DSE has been bypassed. You can now load unsigned drivers.\n";
                    isPatched = true;
                }
                else {
                    std::wcout << L"\n[FAILED] DSE bypass was unsuccessful.\n";
                }
            }

            UI::WaitForAnyKey(L"\nPress any key to return to menu...");

        }
        else if (choice == 2) {
            UI::DisplayLoadDriverMenu(loader);

        }
        else if (choice == 3) {
            UI::DisplayOffsetInfo(loader);

        }
        else if (choice == 4) {
            std::wcout << L"\nExiting...\n";
            break;

        }
        else {
            std::wcout << L"\n[ERROR] Invalid option selected.\n";
            UI::WaitForAnyKey(L"\nPress any key to return to menu...");
        }
    }

    return 0;
}

// ============================================================================
// CLI COMMAND HANDLERS
// ============================================================================

int HandleBypassCommand(DrvLoader& loader) {
    bool success = loader.BypassDSE();
    if (success) {
        std::wcout << L"\n[SUCCESS] DSE bypassed\n";
        return 0;
    }
    std::wcout << L"\n[FAILED] DSE bypass unsuccessful\n";
    return 1;
}

int HandleRestoreCommand(DrvLoader& loader) {
    bool success = loader.RestoreDSE();
    if (success) {
        std::wcout << L"\n[SUCCESS] DSE restored\n";
        return 0;
    }
    std::wcout << L"\n[FAILED] DSE restore unsuccessful\n";
    return 1;
}

int HandleStatusCommand(DrvLoader& loader) {
    bool isPatched = false;
    if (loader.CheckDSEStatus(isPatched)) {
        std::wcout << L"\n[INFO] DSE Status: " << (isPatched ? L"PATCHED (disabled)" : L"ACTIVE (enabled)") << L"\n";
        return 0;
    }
    std::wcout << L"\n[FAILED] Could not determine DSE status\n";
    return 1;
}

int HandleLoadCommand(DrvLoader& loader, int argc, wchar_t* argv[]) {
    // No driver specified → open interactive menu
    if (argc == 2) {
        std::wcout << L"\n";
        UI::DisplayLoadDriverMenu(loader, true);
        return 0;
    }
    
    // Quick load mode
    std::wstring driverPath = argv[2];
    DWORD startType = SERVICE_DEMAND_START;
    
    // Parse optional -s <startType> parameter
    if (argc >= 5) {
        std::wstring flag = argv[3];
        std::transform(flag.begin(), flag.end(), flag.begin(), ::towlower);
        if (flag == L"-s") {
            startType = _wtoi(argv[4]);
            if (startType > 4) {
                std::wcout << L"[-] Invalid StartType (must be 0-4)\n";
                return 1;
            }
        }
    }
    
    bool success = loader.LoadDriver(driverPath, startType);
    if (success) {
        std::wcout << L"\n[SUCCESS] Driver loaded\n";
        return 0;
    }
    std::wcout << L"\n[FAILED] Driver load unsuccessful\n";
    return 1;
}

int HandleUnloadCommand(DrvLoader& loader, int argc, wchar_t* argv[]) {
    if (argc < 3) {
        std::wcout << L"[-] Missing driver name\n";
        std::wcout << L"Usage: drvloader ud <driver>\n";
        return 1;
    }
    
    std::wstring serviceName = argv[2];
    bool success = loader.UnloadDriver(serviceName);
    if (success) {
        std::wcout << L"\n[SUCCESS] Driver unloaded\n";
        return 0;
    }
    std::wcout << L"\n[FAILED] Driver unload unsuccessful\n";
    return 1;
}

int HandleHistoryCommand() {
    UI::DisplayDriverHistory();
    return 0;
}

int HandleOffsetsCommand(DrvLoader& loader) {
    UI::DisplayOffsetInfo(loader);
    return 0;
}

void ShowHelp() {
    std::wcout << L"\n";
    std::wcout << L"DSE Bypass Tool - Command Line Interface\n";
    std::wcout << L"=========================================\n";
    std::wcout << L"\n";
    std::wcout << L"Usage: drvloader [command] [options]\n";
    std::wcout << L"\n";
    std::wcout << L"Commands:\n";
    std::wcout << L"  (no args)              Run in interactive mode\n";
    std::wcout << L"  bypass                 Patch DSE (disable driver signature enforcement)\n";
    std::wcout << L"  restore                Restore DSE (re-enable driver signature enforcement)\n";
    std::wcout << L"  status                 Check current DSE status\n";
    std::wcout << L"  ld                     Open interactive Load Driver menu\n";
    std::wcout << L"  ld <driver>            Quick load driver from System32\\drivers\n";
    std::wcout << L"  ld <path>              Quick load driver from full path\n";
    std::wcout << L"  ld <driver> -s <0-4>   Load driver with specific StartType\n";
    std::wcout << L"  ud <driver>            Unload driver (stop and remove service)\n";
    std::wcout << L"  history                Show driver load history\n";
    std::wcout << L"  offsets                Show and save offset information\n";
    std::wcout << L"  help, /?               Show this help message\n";
    std::wcout << L"\n";
    std::wcout << L"Examples:\n";
    std::wcout << L"  drvloader ld kvckbd             Load kvckbd.sys from System32\\drivers\n";
    std::wcout << L"  drvloader ld kvckbd.sys         Same as above\n";
    std::wcout << L"  drvloader ld kvckbd -s 2        Load with AUTO start type\n";
    std::wcout << L"  drvloader ld C:\\test.sys        Load from custom path\n";
    std::wcout << L"  drvloader ud kvckbd             Unload kvckbd driver\n";
    std::wcout << L"  drvloader status                Check if DSE is patched\n";
    std::wcout << L"\n";
    std::wcout << L"StartType values:\n";
    std::wcout << L"  0 = BOOT      Load during boot\n";
    std::wcout << L"  1 = SYSTEM    Load by IO Manager\n";
    std::wcout << L"  2 = AUTO      Load by Service Control Manager\n";
    std::wcout << L"  3 = DEMAND    Manual start (default)\n";
    std::wcout << L"  4 = DISABLED  Driver disabled\n";
    std::wcout << L"\n";
}