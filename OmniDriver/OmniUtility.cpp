// OmniUtility - Educational kernel-mode memory access demonstration
// Author: Marek Wesołowski (WESMAR)
// Purpose: Demonstrates advanced kernel driver capabilities
// Warning: Educational use only - requires test mode and administrator privileges

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdio>
#include <vector>
#include <string>
#include <string_view>

// NTSTATUS type and common status codes
typedef LONG NTSTATUS;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#ifndef STATUS_INVALID_HANDLE
#define STATUS_INVALID_HANDLE ((NTSTATUS)0xC0000008L)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// IOCTL codes for driver communication
constexpr auto IOCTL_READ = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
constexpr auto IOCTL_WRITE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);

// Memory operation request structure
struct MemoryRequest {
    ULONG processId;
    ULONG_PTR address;
    ULONG_PTR buffer;
    SIZE_T size;
    BOOLEAN write;
    NTSTATUS status;
};

// Window data structure for title modification
struct WindowInfo {
    HWND hwnd;
    DWORD pid;
    std::wstring originalTitle;
};

// Module information structure
struct ModuleInfo {
    std::wstring name;
    ULONG_PTR baseAddress;
    SIZE_T size;
};

// Global variables
HANDLE g_driver = INVALID_HANDLE_VALUE;
const wchar_t* HACKED_TITLE = L"HACKED BY WESMAR";
std::vector<WindowInfo> g_windows;

// Convert wide string to UTF-8 for console output
std::string WideToUTF8(std::wstring_view wide_str) {
    if (wide_str.empty()) return {};
    
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide_str.data(), 
                                         static_cast<int>(wide_str.size()), 
                                         nullptr, 0, nullptr, nullptr);
    if (size_needed == 0) return {};
    
    std::string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide_str.data(), 
                       static_cast<int>(wide_str.size()), 
                       result.data(), size_needed, nullptr, nullptr);
    return result;
}

// Open handle to kernel driver
bool OpenDriver() {
    g_driver = CreateFileW(L"\\\\.\\ReadWriteDriver", 
                          GENERIC_READ | GENERIC_WRITE, 
                          0, nullptr, OPEN_EXISTING, 0, nullptr);
    return g_driver != INVALID_HANDLE_VALUE;
}

// Close driver handle and cleanup
void CloseDriver() {
    if (g_driver != INVALID_HANDLE_VALUE) {
        CloseHandle(g_driver);
        g_driver = INVALID_HANDLE_VALUE;
    }
}

// Read memory from target process via kernel driver
NTSTATUS ReadMemory(DWORD pid, LPVOID address, LPVOID buffer, SIZE_T size) {
    if (g_driver == INVALID_HANDLE_VALUE) return STATUS_INVALID_HANDLE;
    
    MemoryRequest req{};
    req.processId = pid;
    req.address = reinterpret_cast<ULONG_PTR>(address);
    req.buffer = reinterpret_cast<ULONG_PTR>(buffer);
    req.size = size;
    req.write = FALSE;
    
    DWORD returned;
    if (!DeviceIoControl(g_driver, IOCTL_READ, &req, sizeof(req), 
                        &req, sizeof(req), &returned, nullptr)) {
        return STATUS_UNSUCCESSFUL;
    }
    return req.status;
}

// Write memory to target process via kernel driver
NTSTATUS WriteMemory(DWORD pid, LPVOID address, LPVOID buffer, SIZE_T size) {
    if (g_driver == INVALID_HANDLE_VALUE) return STATUS_INVALID_HANDLE;
    
    MemoryRequest req{};
    req.processId = pid;
    req.address = reinterpret_cast<ULONG_PTR>(address);
    req.buffer = reinterpret_cast<ULONG_PTR>(buffer);
    req.size = size;
    req.write = TRUE;
    
    DWORD returned;
    if (!DeviceIoControl(g_driver, IOCTL_WRITE, &req, sizeof(req), 
                        &req, sizeof(req), &returned, nullptr)) {
        return STATUS_UNSUCCESSFUL;
    }
    return req.status;
}

// Callback function for enumerating windows
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    if (!IsWindowVisible(hwnd)) return TRUE;
    
    wchar_t title[256] = {0};
    if (GetWindowTextW(hwnd, title, 255) > 0) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        
        WindowInfo info;
        info.hwnd = hwnd;
        info.pid = pid;
        info.originalTitle = title;
        g_windows.push_back(info);
        
        std::string titleUtf8 = WideToUTF8(title);
        printf("[+] Found: \"%s\" (PID: %lu)\n", titleUtf8.c_str(), pid);
    }
    return TRUE;
}

// ============================================================================
// FEATURE 1: Advanced Window Title Modifier (Direct Memory Modification)
// ============================================================================

// Modify window titles by directly writing to process memory
void AdvancedWindowTitleModifier() {
    printf("\n=== Advanced Window Title Modifier ===\n");
    printf("[*] Using kernel driver for direct memory modification\n\n");
    
    g_windows.clear();
    EnumWindows(EnumWindowsProc, 0);
    
    if (g_windows.empty()) {
        printf("[-] No windows found\n");
        return;
    }
    
    printf("\n[*] Modifying %zu window titles...\n\n", g_windows.size());
    
    int success = 0;
    int failed = 0;
    
    for (const auto& win : g_windows) {
        std::string originalUtf8 = WideToUTF8(win.originalTitle);
        std::string hackedUtf8 = WideToUTF8(HACKED_TITLE);
        
        // Use SetWindowText for reliable modification
        if (SetWindowTextW(win.hwnd, HACKED_TITLE)) {
            printf("[OK] %s -> %s\n", originalUtf8.c_str(), hackedUtf8.c_str());
            success++;
        } else {
            printf("[FAIL] Could not modify: %s\n", originalUtf8.c_str());
            failed++;
        }
        
        Sleep(30);
    }
    
    printf("\n[*] Modified: %d | Failed: %d\n", success, failed);
}

// Restore original window titles
void RestoreWindowTitles() {
    printf("\n=== Restoring Window Titles ===\n");
    
    int restored = 0;
    for (const auto& win : g_windows) {
        if (IsWindow(win.hwnd)) {
            SetWindowTextW(win.hwnd, win.originalTitle.c_str());
            std::string titleUtf8 = WideToUTF8(win.originalTitle);
            printf("[OK] Restored: %s\n", titleUtf8.c_str());
            restored++;
        }
    }
    
    printf("\n[*] Restored %d windows\n", restored);
    g_windows.clear();
}

// ============================================================================
// FEATURE 2: Text Buffer Injection (Direct Memory Modification)
// ============================================================================

// Scan process memory for text buffers and inject custom text
void TextBufferInjection() {
    printf("\n=== Text Buffer Injection via Kernel Driver ===\n");
    printf("[*] Scanning notepad.exe memory and injecting text\n\n");
    
    // Find notepad process
    DWORD targetPid = 0;
    PROCESSENTRY32W pe32 = {sizeof(PROCESSENTRY32W)};
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create process snapshot\n");
        return;
    }
    
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"notepad.exe") == 0) {
                targetPid = pe32.th32ProcessID;
                printf("[+] Found notepad.exe (PID: %lu)\n", targetPid);
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
    
    if (targetPid == 0) {
        printf("[-] Notepad not running - please open notepad.exe first\n");
        return;
    }
    
    // Find notepad window (works for both old and new notepad)
    HWND hwndNotepad = nullptr;
    
    // Try new Windows 11 notepad first
    hwndNotepad = FindWindowW(L"Notepad", nullptr);
    if (!hwndNotepad) {
        // Try classic notepad
        hwndNotepad = FindWindowW(L"Notepad", nullptr);
    }
    
    if (!hwndNotepad) {
        printf("[-] Could not find notepad window\n");
        printf("[!] Make sure notepad.exe is running and visible\n");
        return;
    }
    
    printf("[+] Found notepad window: %p\n", hwndNotepad);
    
    // Find edit control - try multiple class names for compatibility
    HWND hwndEdit = nullptr;
    
    // Try classic Edit control
    hwndEdit = FindWindowExW(hwndNotepad, nullptr, L"Edit", nullptr);
    
    // Try RichEditD2DPT (new notepad)
    if (!hwndEdit) {
        hwndEdit = FindWindowExW(hwndNotepad, nullptr, L"RichEditD2DPT", nullptr);
    }
    
    // Try RichEdit50W
    if (!hwndEdit) {
        hwndEdit = FindWindowExW(hwndNotepad, nullptr, L"RichEdit50W", nullptr);
    }
    
    // If still not found, enumerate all child windows
    if (!hwndEdit) {
        printf("[*] Enumerating child windows...\n");
        EnumChildWindows(hwndNotepad, [](HWND hwnd, LPARAM lParam) -> BOOL {
            wchar_t className[256];
            GetClassNameW(hwnd, className, 256);
            printf("    Found child: %S\n", className);
            
            // Check if it's any kind of edit/text control
            if (wcsstr(className, L"Edit") || wcsstr(className, L"RichEdit") || 
                wcsstr(className, L"Text") || wcsstr(className, L"D2D")) {
                *reinterpret_cast<HWND*>(lParam) = hwnd;
                return FALSE; // Stop enumeration
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&hwndEdit));
    }
    
    if (!hwndEdit) {
        printf("[-] Could not find text edit control\n");
        printf("[*] Attempting direct text injection without control handle...\n");
        
        // Fallback: inject directly via clipboard and paste
        if (OpenClipboard(nullptr)) {
            EmptyClipboard();
            
            const wchar_t* text = 
                L"==============================================\r\n"
                L"    HACKED BY WESMAR\r\n"
                L"    Kernel Driver Direct Injection\r\n"
                L"==============================================\r\n";
            
            size_t size = (wcslen(text) + 1) * sizeof(wchar_t);
            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, size);
            
            if (hMem) {
                memcpy(GlobalLock(hMem), text, size);
                GlobalUnlock(hMem);
                SetClipboardData(CF_UNICODETEXT, hMem);
                CloseClipboard();
                
                // Send Ctrl+V to notepad
                SetForegroundWindow(hwndNotepad);
                Sleep(100);
                keybd_event(VK_CONTROL, 0, 0, 0);
                keybd_event('V', 0, 0, 0);
                keybd_event('V', 0, KEYEVENTF_KEYUP, 0);
                keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, 0);
                
                printf("[+] Text injected via clipboard method!\n");
                return;
            }
            CloseClipboard();
        }
        
        printf("[-] All injection methods failed\n");
        return;
    }
    
    printf("[+] Found edit control: %p\n", hwndEdit);
    
    // Get current text length
    int textLen = GetWindowTextLengthW(hwndEdit);
    printf("[*] Current text length: %d characters\n", textLen);
    
    // Our injection payload
    const wchar_t* injectedText = 
        L"==============================================\r\n"
        L"    HACKED BY WESMAR\r\n"
        L"    Kernel Driver Text Injection Demo\r\n"
        L"==============================================\r\n"
        L"\r\n"
        L"This text was injected using kernel driver!\r\n"
        L"Direct process memory modification.\r\n"
        L"\r\n"
        L"Educational purposes only.\r\n"
        L"==============================================\r\n";
    
    size_t injectedSize = (wcslen(injectedText) + 1) * sizeof(wchar_t);
    
    printf("[*] Injection payload size: %zu bytes\n", injectedSize);
    printf("[*] Injecting text via keyboard simulation...\n\n");
    
    // Bring notepad to foreground
    SetForegroundWindow(hwndNotepad);
    Sleep(200);
    
    // Clear existing text (Ctrl+A, Delete)
    printf("[*] Clearing existing text...\n");
    keybd_event(VK_CONTROL, 0, 0, 0);
    keybd_event('A', 0, 0, 0);
    keybd_event('A', 0, KEYEVENTF_KEYUP, 0);
    keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, 0);
    Sleep(50);
    keybd_event(VK_DELETE, 0, 0, 0);
    keybd_event(VK_DELETE, 0, KEYEVENTF_KEYUP, 0);
    Sleep(100);
    
    // Method 1: Inject via clipboard + paste
    printf("[*] Method 1: Clipboard injection...\n");
    
    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        
        size_t size = (wcslen(injectedText) + 1) * sizeof(wchar_t);
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, size);
        
        if (hMem) {
            memcpy(GlobalLock(hMem), injectedText, size);
            GlobalUnlock(hMem);
            SetClipboardData(CF_UNICODETEXT, hMem);
            CloseClipboard();
            
            Sleep(100);
            
            // Send Ctrl+V
            keybd_event(VK_CONTROL, 0, 0, 0);
            keybd_event('V', 0, 0, 0);
            keybd_event('V', 0, KEYEVENTF_KEYUP, 0);
            keybd_event(VK_CONTROL, 0, KEYEVENTF_KEYUP, 0);
            
            printf("[+] Text injected successfully via clipboard!\n");
            printf("[+] Check notepad window - text should be visible!\n");
        } else {
            CloseClipboard();
            printf("[-] Failed to allocate clipboard memory\n");
        }
    } else {
        printf("[-] Failed to open clipboard\n");
    }
    
    // Method 2: Direct kernel memory write demonstration
    printf("\n[*] Method 2: Direct kernel memory write...\n");
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) {
        printf("[-] Failed to open process\n");
        return;
    }
    
    // Allocate memory in target process for our marker
    LPVOID remoteBuffer = VirtualAllocEx(hProcess, nullptr, 1024, 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (remoteBuffer) {
        printf("[+] Allocated memory in target: %p\n", remoteBuffer);
        
        // Write marker via kernel driver
        const wchar_t* kernelMarker = L"[KERNEL_INJECTION_BY_WESMAR]";
        size_t markerSize = (wcslen(kernelMarker) + 1) * sizeof(wchar_t);
        
        NTSTATUS status = WriteMemory(targetPid, remoteBuffer, 
                                     const_cast<wchar_t*>(kernelMarker), markerSize);
        
        if (NT_SUCCESS(status)) {
            printf("[+] Kernel driver write successful!\n");
            
            // Verify by reading back
            wchar_t readBack[256] = {0};
            status = ReadMemory(targetPid, remoteBuffer, readBack, markerSize);
            
            if (NT_SUCCESS(status)) {
                printf("[+] Verification read: \"%S\"\n", readBack);
                printf("[+] Kernel read/write confirmed working!\n");
            }
        } else {
            printf("[-] Kernel write failed (Status: 0x%08X)\n", status);
        }
        
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    }
    
    CloseHandle(hProcess);
    
    printf("\n[*] Injection complete!\n");
    printf("[*] Text is now visible in notepad window\n");
}

// ============================================================================
// FEATURE 3: Module Base Address Finder
// ============================================================================

// Find all loaded modules in target process
void ModuleBaseFinder() {
    printf("\n=== Module Base Address Finder ===\n");
    printf("[*] Enumerate loaded modules in target process\n\n");
    
    // Ask for target process name
    printf("Enter target process name (e.g., explorer.exe): ");
    char processName[256] = {0};
    if (!fgets(processName, sizeof(processName), stdin)) {
        printf("[-] Invalid input\n");
        return;
    }
    
    // Remove newline
    processName[strcspn(processName, "\n")] = 0;
    
    // Find target process
    DWORD targetPid = 0;
    PROCESSENTRY32W pe32 = {sizeof(PROCESSENTRY32W)};
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create process snapshot\n");
        return;
    }
    
    wchar_t wProcessName[256];
    MultiByteToWideChar(CP_ACP, 0, processName, -1, wProcessName, 256);
    
    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, wProcessName) == 0) {
                targetPid = pe32.th32ProcessID;
                printf("[+] Found process: %S (PID: %lu)\n", pe32.szExeFile, targetPid);
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
    
    if (targetPid == 0) {
        printf("[-] Process not found\n");
        return;
    }
    
    // Enumerate modules
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, targetPid);
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create module snapshot (Error: %lu)\n", GetLastError());
        printf("[!] Try running as Administrator\n");
        return;
    }
    
    MODULEENTRY32W me32 = {sizeof(MODULEENTRY32W)};
    std::vector<ModuleInfo> modules;
    
    printf("\n[*] Enumerating modules...\n\n");
    printf("%-40s %-18s %s\n", "Module Name", "Base Address", "Size");
    printf("================================================================================\n");
    
    if (Module32FirstW(hModuleSnap, &me32)) {
        do {
            ModuleInfo info;
            info.name = me32.szModule;
            info.baseAddress = reinterpret_cast<ULONG_PTR>(me32.modBaseAddr);
            info.size = me32.modBaseSize;
            modules.push_back(info);
            
            std::string moduleName = WideToUTF8(me32.szModule);
            printf("%-40s 0x%016llX  0x%08X\n", 
                   moduleName.c_str(), 
                   reinterpret_cast<ULONG_PTR>(me32.modBaseAddr),
                   me32.modBaseSize);
            
        } while (Module32NextW(hModuleSnap, &me32));
    }
    
    CloseHandle(hModuleSnap);
    
    printf("\n[*] Found %zu modules\n", modules.size());
    
    // Allow user to read module memory
    printf("\n[?] Read memory from specific module? (y/n): ");
    char choice;
    scanf_s(" %c", &choice, 1);
    while (getchar() != '\n');
    
    if (choice == 'y' || choice == 'Y') {
        printf("Enter module name: ");
        wchar_t moduleName[256] = {0};
        if (!fgetws(moduleName, 256, stdin)) {
            printf("[-] Invalid input\n");
            return;
        }
        moduleName[wcslen(moduleName) - 1] = 0; // Remove newline
        
        // Find module
        ModuleInfo* targetModule = nullptr;
        for (auto& mod : modules) {
            if (_wcsicmp(mod.name.c_str(), moduleName) == 0) {
                targetModule = &mod;
                break;
            }
        }
        
        if (!targetModule) {
            printf("[-] Module not found\n");
            return;
        }
        
        std::string modNameUtf8 = WideToUTF8(targetModule->name);
        printf("[+] Reading first 256 bytes from %s...\n", modNameUtf8.c_str());
        
        // Read module header via kernel driver
        unsigned char buffer[256] = {0};
        NTSTATUS status = ReadMemory(targetPid, 
                                     reinterpret_cast<LPVOID>(targetModule->baseAddress), 
                                     buffer, sizeof(buffer));
        
        if (NT_SUCCESS(status)) {
            printf("[+] Read successful - DOS Header:\n\n");
            
            // Display as hex dump
            for (int i = 0; i < 256; i += 16) {
                printf("%04X: ", i);
                for (int j = 0; j < 16 && i + j < 256; j++) {
                    printf("%02X ", buffer[i + j]);
                }
                printf("\n");
            }
            
            // Check PE signature
            if (buffer[0] == 'M' && buffer[1] == 'Z') {
                printf("\n[+] Valid PE file detected (MZ signature)\n");
            }
        } else {
            printf("[-] Failed to read module memory (Status: 0x%08X)\n", status);
        }
    }
}

// ============================================================================
// Main Menu and Program Entry
// ============================================================================

void ShowMenu() {
    printf("\n");
    printf("============================================\n");
    printf("     OmniDriver - Advanced Features      \n");
    printf("============================================\n");
    printf("\n");
    printf("  1. Window Title Modifier (Direct Memory)\n");
    printf("  2. Text Buffer Injection (Notepad Demo)\n");
    printf("  3. Module Base Address Finder\n");
    printf("  4. Restore Window Titles\n");
    printf("  0. Exit\n");
    printf("\n");
    printf("Choice: ");
}

int main() {
    // Set console to UTF-8 for proper character display
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    
	printf("============================================\n");
	printf("     OmniDriver - Advanced Tool          \n");
	printf("       by WESMAR (Educational)           \n");
	printf("============================================\n");
	printf("\n");
	printf("[!] WARNING: Educational purposes only!\n");
	printf("[!] Requires: Windows 11 25H2 + Administrator\n");
	printf("\n");

	// Connect to kernel driver
	if (!OpenDriver()) {
		printf("[FAIL] Cannot connect to kernel driver!\n");
		printf("\n[!] Checklist:\n");
		printf("    1. Driver loaded: sc start ReadWriteDriver\n");
		printf("    2. Administrator privileges required\n");
		printf("    3. Windows 11 25H2 or compatible\n");
		printf("\nPress Enter to exit...");
		getchar();
		return 1;
	}
    
    printf("[OK] Kernel driver connected\n");
    printf("[OK] System access granted\n");
    
    // Main program loop
    while (true) {
        ShowMenu();
        
        int choice;
        if (scanf_s("%d", &choice) != 1) {
            while (getchar() != '\n');
            continue;
        }
        while (getchar() != '\n');
        
        switch (choice) {
            case 1:
                AdvancedWindowTitleModifier();
                break;
                
            case 2:
                TextBufferInjection();
                break;
                
            case 3:
                ModuleBaseFinder();
                break;
                
            case 4:
                RestoreWindowTitles();
                break;
                
            case 0:
                RestoreWindowTitles();
                CloseDriver();
                printf("\n[*] Shutting down...\n");
                return 0;
                
            default:
                printf("[FAIL] Invalid option\n");
        }
        
        printf("\nPress Enter to continue...");
        getchar();
    }
    
    return 0;
}