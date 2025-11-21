#pragma once

#include <Windows.h>
#include <string>
#include "DrvCore.h"

namespace UI {

    // Displays the application banner with author information
    void DisplayBanner();

    // Clears the input buffer to prevent skipped prompts
    void ClearInputBuffer();

    // Pauses execution until the user presses a key
    void WaitForAnyKey(const std::wstring& message);

    // Calculates, displays, and saves kernel offsets for external tools
    // waitForKey: If true, pauses after display (interactive mode); if false, returns immediately (CLI mode)
    void DisplayOffsetInfo(DrvLoader& loader, bool waitForKey = true);

    // Displays the main menu options based on current DSE status
    void DisplayMenu(bool isPatched);

    // Shows the history of loaded drivers
    void DisplayDriverHistory();

    // Helper to prompt user for driver file path
    std::wstring PromptForDriverPath();

    // Helper to prompt user for service start type (default: DEMAND)
    DWORD PromptForStartType();

    // Displays the submenu for driver operations (Load, Reload, Stop, Remove)
    // fromCLI: If true, hides the "Return to main menu" option
    void DisplayLoadDriverMenu(DrvLoader& loader, bool fromCLI = false);

}