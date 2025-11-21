#include "UserInterface.h"
#include "DrvCore.h"
#include "ConfigManager.h"
#include <iostream>
#include <algorithm>

// CLI Handlers
int HandleBypassCommand(DrvLoader& loader);
int HandleRestoreCommand(DrvLoader& loader);
int HandleStatusCommand(DrvLoader& loader);
int HandleLoadCommand(DrvLoader& loader, int argc, wchar_t* argv[]);
int HandleReloadCommand(DrvLoader& loader, int argc, wchar_t* argv[]);
int HandleRemoveCommand(DrvLoader& loader, int argc, wchar_t* argv[]);
int HandleStopCommand(DrvLoader& loader, int argc, wchar_t* argv[]);
int HandleHistoryCommand();
int HandleOffsetsCommand(DrvLoader& loader);
void ShowHelp();

int wmain(int argc, wchar_t* argv[]) {
    UI::DisplayBanner();

    // Safety check for HVCI
    if (!ConfigManager::CheckAndDisableMemoryIntegrity()) {
        return 1;
    }

    DrvLoader loader;

    if (!loader.Initialize()) {
        std::wcout << L"\n[FAILED] Loader initialization failed\n";
        UI::WaitForAnyKey(L"\nPress any key to exit...");
        return 1;
    }

    // CLI Execution
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
        else if (cmd == L"load") {
            return HandleLoadCommand(loader, argc, argv);
        }
        else if (cmd == L"reload") {
            return HandleReloadCommand(loader, argc, argv);
        }
        else if (cmd == L"remove") {
            return HandleRemoveCommand(loader, argc, argv);
        }
        else if (cmd == L"stop") {
            return HandleStopCommand(loader, argc, argv);
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

    // Interactive Mode
    std::wcout << L"DSE Bypass Tool - Universal (Dynamic PDB)\n";
    std::wcout << L"==========================================\n";
    std::wcout << L"Technique: SeCiCallbacks replacement\n";
    std::wcout << L"Driver: RTCore64 (Embedded)\n";

    bool isPatched = false;
    if (!loader.CheckDSEStatus(isPatched)) {
        std::wcout << L"\n[FAILED] Could not check DSE status\n";
        UI::WaitForAnyKey(L"\nPress any key to exit...");
        return 1;
    }

    while (true) {
        UI::DisplayMenu(isPatched);

        int choice = 0;
        std::wcin >> choice;
        UI::ClearInputBuffer();

        if (choice == 1) {
            if (isPatched) {
                if (loader.RestoreDSE()) {
                    std::wcout << L"\n[SUCCESS] DSE Restored\n";
                    isPatched = false;
                } else {
                    std::wcout << L"\n[FAILED] Restore failed\n";
                }
            } else {
                if (loader.BypassDSE()) {
                    std::wcout << L"\n[SUCCESS] DSE Bypassed\n";
                    isPatched = true;
                } else {
                    std::wcout << L"\n[FAILED] Bypass failed\n";
                }
            }
            UI::WaitForAnyKey(L"\nPress any key...");
        }
        else if (choice == 2) {
            UI::DisplayLoadDriverMenu(loader);
        }
        else if (choice == 3) {
            // Interactive mode: waitForKey = true (default)
            UI::DisplayOffsetInfo(loader);
        }
        else if (choice == 4) {
            break;
        }
        else {
            std::wcout << L"\n[!] Invalid option\n";
        }
    }

    return 0;
}

int HandleBypassCommand(DrvLoader& loader) {
    return loader.BypassDSE() ? 0 : 1;
}

int HandleRestoreCommand(DrvLoader& loader) {
    return loader.RestoreDSE() ? 0 : 1;
}

int HandleStatusCommand(DrvLoader& loader) {
    bool isPatched = false;
    if (loader.CheckDSEStatus(isPatched)) return 0;
    return 1;
}

int HandleLoadCommand(DrvLoader& loader, int argc, wchar_t* argv[]) {
    // If no driver path provided, open interactive menu
    if (argc == 2) {
        UI::DisplayLoadDriverMenu(loader, true);
        return 0;
    }
    
    std::wstring driverPath = argv[2];
    DWORD startType = SERVICE_DEMAND_START;
    
    // Check for optional start type flag (-s <type>)
    if (argc >= 5) {
        std::wstring flag = argv[3];
        std::transform(flag.begin(), flag.end(), flag.begin(), ::towlower);
        if (flag == L"-s") {
            startType = _wtoi(argv[4]);
        }
    }
    
    return loader.LoadDriver(driverPath, startType) ? 0 : 1;
}

int HandleReloadCommand(DrvLoader& loader, int argc, wchar_t* argv[]) {
    if (argc < 3) {
        std::wcout << L"Usage: drvloader reload <driver>\n";
        return 1;
    }
    return loader.ReloadDriver(argv[2]) ? 0 : 1;
}

int HandleRemoveCommand(DrvLoader& loader, int argc, wchar_t* argv[]) {
    if (argc < 3) {
        std::wcout << L"Usage: drvloader remove <driver>\n";
        return 1;
    }
    return loader.RemoveDriver(argv[2]) ? 0 : 1;
}

int HandleStopCommand(DrvLoader& loader, int argc, wchar_t* argv[]) {
    if (argc < 3) {
        std::wcout << L"Usage: drvloader stop <driver>\n";
        return 1;
    }
    return loader.StopDriver(argv[2]) ? 0 : 1;
}

int HandleHistoryCommand() {
    UI::DisplayDriverHistory();
    return 0;
}

int HandleOffsetsCommand(DrvLoader& loader) {
    // FIX: Pass false to skip waiting for keypress in CLI mode.
    // This delegates the logic to UserInterface.cpp and avoids calling WaitForAnyKey here.
    UI::DisplayOffsetInfo(loader, false);
    return 0;
}

void ShowHelp() {
    std::wcout << L"\nUsage: drvloader [command] [options]\n\n";
    std::wcout << L"Commands:\n";
    std::wcout << L"  (no args)              Interactive mode\n";
    std::wcout << L"  bypass                 Disable DSE\n";
    std::wcout << L"  restore                Enable DSE\n";
    std::wcout << L"  status                 Check DSE status\n";
    std::wcout << L"  load <path>            Load driver (Stop -> Patch -> Start -> Restore)\n";
    std::wcout << L"  load <path> -s <0-4>   Load with specific StartType\n";
    std::wcout << L"  reload <driver>        Reload driver\n";
    std::wcout << L"  remove <driver>        Stop and delete service\n";
    std::wcout << L"  stop <driver>          Stop service (no delete)\n";
    std::wcout << L"  history                Show load history\n";
    std::wcout << L"  offsets                Dump offsets for external tools\n";
}