#pragma once

#include <Windows.h>
#include <string>

// Forward declaration to avoid circular dependency
class DrvLoader;

// User interface and console interaction functions
namespace UI {
    // Displays application banner with author information
    void DisplayBanner();
    
    // Displays offset information for external tools (e.g., BootBypass)
    void DisplayOffsetInfo(DrvLoader& loader);
    
    // Displays load driver submenu with history
	void DisplayLoadDriverMenu(DrvLoader& loader, bool fromCLI = false);

    
    // Displays driver load history
    void DisplayDriverHistory();
    
    // Prompts user for driver path
    std::wstring PromptForDriverPath();
    
    // Prompts user for StartType (0-4)
    DWORD PromptForStartType();
    
    // Displays main menu based on current patch state
    void DisplayMenu(bool isPatched);
    
    // Clears input buffer to prevent leftover characters
    void ClearInputBuffer();
    
    // Waits for user keypress with custom message
    void WaitForAnyKey(const std::wstring& message = L"\nPress any key to continue...");
}