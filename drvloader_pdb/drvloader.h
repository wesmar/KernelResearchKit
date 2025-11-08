#pragma once

#include <Windows.h>
#include <dbghelp.h>
#include <winhttp.h>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <map>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "winhttp.lib")

class SymbolDownloader {
private:
    std::wstring symbolCachePath;
    std::wstring symbolServer;
	std::pair<std::wstring, std::wstring> GetPdbInfoFromPe(const std::wstring& pePath);    

public:
    SymbolDownloader(const std::wstring& cachePath = L"");
    bool Initialize();
    std::optional<uint64_t> GetSymbolOffset(const std::wstring& moduleName, const std::wstring& symbolName);
    bool DownloadSymbolsForModule(const std::wstring& modulePath);
    std::wstring GetSymbolCachePath() const { return symbolCachePath; }
    
private:
    bool EnsureSymbolCache();
    bool DownloadPdb(const std::wstring& modulePath);
    std::wstring GetPdbGuidFromPe(const std::wstring& pePath);
    bool DownloadFile(const std::wstring& url, const std::wstring& outputPath);
};

struct DrvLoader {
    HANDLE hDriver{ INVALID_HANDLE_VALUE };
    std::optional<uint64_t> originalCallback;
    SymbolDownloader symbolDownloader;
    
    bool Initialize();
    void Cleanup();
    bool WriteMemory32(uint64_t address, uint32_t value);
    bool WriteMemory64(uint64_t address, uint64_t value);
    std::optional<uint32_t> ReadMemory32(uint64_t address);
    std::optional<uint64_t> ReadMemory64(uint64_t address);
    bool CheckDSEStatus(bool& isPatched);
    bool BypassDSE();
    bool RestoreDSE();
    
private:
    std::optional<uint64_t> GetNtoskrnlBase();
    std::optional<uint64_t> GetKernelSymbolOffset(const std::wstring& symbolName);
    bool SaveOriginalCallback(uint64_t callback);
    std::optional<uint64_t> LoadOriginalCallback();
    bool DeleteStateFile();
    bool InstallAndStartDriver();
    bool StopAndRemoveDriver();
    bool CheckDriverFileExists();
};