#pragma once

#include <Windows.h>
#include <dbghelp.h>
#include <winhttp.h>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "winhttp.lib")

// Manages symbol downloading from Microsoft Symbol Server and PDB parsing
class SymbolDownloader {
private:
    std::wstring symbolCachePath;
    std::wstring symbolServer;
    
    // Extracts PDB name and GUID from PE file debug directory
    std::pair<std::wstring, std::wstring> GetPdbInfoFromPe(const std::wstring& pePath);
    
    // Ensures symbol cache directory exists
    bool EnsureSymbolCache();
    
    // Downloads PDB file from symbol server
    bool DownloadPdb(const std::wstring& modulePath);
    
    // Extracts PDB GUID/signature from PE file
    std::wstring GetPdbGuidFromPe(const std::wstring& pePath);
    
    // Downloads file from URL to local path
    bool DownloadFile(const std::wstring& url, const std::wstring& outputPath);

public:
    SymbolDownloader(const std::wstring& cachePath = L"");
    
    // Initializes symbol handler and cache
    bool Initialize();
    
    // Gets offset of symbol from module's PDB
    std::optional<uint64_t> GetSymbolOffset(const std::wstring& moduleName, const std::wstring& symbolName);
    
    // Downloads symbols for specified module if not cached
    bool DownloadSymbolsForModule(const std::wstring& modulePath);
    
    std::wstring GetSymbolCachePath() const { return symbolCachePath; }
};