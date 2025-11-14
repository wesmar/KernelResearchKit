#include "SymbolDownloader.h"
#include <iostream>
#include <shlwapi.h>
#include <shlobj.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

SymbolDownloader::SymbolDownloader(const std::wstring& cachePath)
    : symbolServer(L"https://msdl.microsoft.com/download/symbols") {
    
    if (cachePath.empty()) {
        WCHAR exePath[MAX_PATH];
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        PathRemoveFileSpecW(exePath);
        symbolCachePath = std::wstring(exePath) + L"\\symbols";
    } else {
        symbolCachePath = cachePath;
    }
}

bool SymbolDownloader::Initialize() {
    if (!EnsureSymbolCache()) {
        return false;
    }
    
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_DEBUG);
    
    if (!SymInitializeW(GetCurrentProcess(), symbolCachePath.c_str(), FALSE)) {
        std::wcout << L"[-] Failed to initialize symbol handler (error: " << GetLastError() << L")\n";
        return false;
    }
    
    std::wcout << L"[+] Symbol handler initialized with cache: " << symbolCachePath << L"\n";
    return true;
}

bool SymbolDownloader::EnsureSymbolCache() {
    DWORD attrib = GetFileAttributesW(symbolCachePath.c_str());
    
    if (attrib == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectoryW(symbolCachePath.c_str(), nullptr)) {
            std::wcout << L"[-] Failed to create symbol cache directory: " << symbolCachePath << L"\n";
            return false;
        }
        std::wcout << L"[+] Created symbol cache directory: " << symbolCachePath << L"\n";
    }
    
    return true;
}

std::pair<std::wstring, std::wstring> SymbolDownloader::GetPdbInfoFromPe(const std::wstring& pePath) {
    HANDLE hFile = CreateFileW(pePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return {L"", L""};
    }
    
    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        CloseHandle(hFile);
        return {L"", L""};
    }
    
    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return {L"", L""};
    }
    
    std::wstring guidStr;
    std::wstring pdbName;
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDos->e_lfanew);
        if (pNt->Signature == IMAGE_NT_SIGNATURE) {
            DWORD debugDirRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            DWORD debugDirSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
            
            if (debugDirRva && debugDirSize) {
                PIMAGE_DEBUG_DIRECTORY pDebugDir = (PIMAGE_DEBUG_DIRECTORY)((BYTE*)pBase + debugDirRva);
                
                for (DWORD i = 0; i < debugDirSize / sizeof(IMAGE_DEBUG_DIRECTORY); i++) {
                    if (pDebugDir[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
                        struct CV_INFO_PDB70 {
                            DWORD CvSignature;
                            GUID Signature;
                            DWORD Age;
                            char PdbFileName[1];
                        };
                        
                        CV_INFO_PDB70* pCv = (CV_INFO_PDB70*)((BYTE*)pBase + pDebugDir[i].AddressOfRawData);
                        
                        if (pCv->CvSignature == 0x53445352) {
                            wchar_t guidBuf[64];
                            swprintf_s(guidBuf, L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
                                pCv->Signature.Data1, pCv->Signature.Data2, pCv->Signature.Data3,
                                pCv->Signature.Data4[0], pCv->Signature.Data4[1], pCv->Signature.Data4[2],
                                pCv->Signature.Data4[3], pCv->Signature.Data4[4], pCv->Signature.Data4[5],
                                pCv->Signature.Data4[6], pCv->Signature.Data4[7], pCv->Age);
                            guidStr = guidBuf;
                            
                            int len = MultiByteToWideChar(CP_UTF8, 0, pCv->PdbFileName, -1, nullptr, 0);
                            if (len > 0) {
                                std::vector<wchar_t> wideBuf(len);
                                MultiByteToWideChar(CP_UTF8, 0, pCv->PdbFileName, -1, wideBuf.data(), len);
                                
                                std::wstring fullPath = wideBuf.data();
                                size_t pos = fullPath.find_last_of(L"\\/");
                                pdbName = (pos != std::wstring::npos) ? fullPath.substr(pos + 1) : fullPath;
                            }
                            
                            break;
                        }
                    }
                }
            }
        }
    }
    
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    
    return {pdbName, guidStr};
}

std::wstring SymbolDownloader::GetPdbGuidFromPe(const std::wstring& pePath) {
    HANDLE hFile = CreateFileW(pePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return L"";
    }
    
    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        CloseHandle(hFile);
        return L"";
    }
    
    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return L"";
    }
    
    std::wstring guidStr;
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDos->e_lfanew);
        if (pNt->Signature == IMAGE_NT_SIGNATURE) {
            DWORD debugDirRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
            DWORD debugDirSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
            
            if (debugDirRva && debugDirSize) {
                PIMAGE_DEBUG_DIRECTORY pDebugDir = (PIMAGE_DEBUG_DIRECTORY)((BYTE*)pBase + debugDirRva);
                
                for (DWORD i = 0; i < debugDirSize / sizeof(IMAGE_DEBUG_DIRECTORY); i++) {
                    if (pDebugDir[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
                        struct CV_INFO_PDB70 {
                            DWORD CvSignature;
                            GUID Signature;
                            DWORD Age;
                            char PdbFileName[1];
                        };
                        
                        CV_INFO_PDB70* pCv = (CV_INFO_PDB70*)((BYTE*)pBase + pDebugDir[i].AddressOfRawData);
                        
                        if (pCv->CvSignature == 0x53445352) {
                            wchar_t guidBuf[64];
                            swprintf_s(guidBuf, L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
                                pCv->Signature.Data1, pCv->Signature.Data2, pCv->Signature.Data3,
                                pCv->Signature.Data4[0], pCv->Signature.Data4[1], pCv->Signature.Data4[2],
                                pCv->Signature.Data4[3], pCv->Signature.Data4[4], pCv->Signature.Data4[5],
                                pCv->Signature.Data4[6], pCv->Signature.Data4[7], pCv->Age);
                            guidStr = guidBuf;
                            break;
                        }
                    }
                }
            }
        }
    }
    
    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    
    return guidStr;
}

bool SymbolDownloader::DownloadFile(const std::wstring& url, const std::wstring& outputPath) {
    std::wcout << L"[*] Downloading from: " << url << L"\n";
    
    URL_COMPONENTSW urlParts = { sizeof(urlParts) };
    wchar_t host[256], path[1024];
    urlParts.lpszHostName = host;
    urlParts.dwHostNameLength = _countof(host);
    urlParts.lpszUrlPath = path;
    urlParts.dwUrlPathLength = _countof(path);
    
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlParts)) {
        std::wcout << L"[-] Failed to parse URL\n";
        return false;
    }
    
    HINTERNET hSession = WinHttpOpen(L"SymbolDownloader/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::wcout << L"[-] Failed to open HTTP session\n";
        return false;
    }
    
    HINTERNET hConnect = WinHttpConnect(hSession, host, urlParts.nPort, 0);
    if (!hConnect) {
        std::wcout << L"[-] Failed to connect to server\n";
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, urlParts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        std::wcout << L"[-] Failed to open HTTP request\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        std::wcout << L"[-] Failed to send HTTP request\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        std::wcout << L"[-] Failed to receive HTTP response\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);
    
    if (statusCode != 200) {
        std::wcout << L"[-] HTTP error: " << statusCode << L"\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    HANDLE hFile = CreateFileW(outputPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] Failed to create output file\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    BYTE buffer[8192];
    DWORD bytesRead = 0, bytesWritten = 0;
    DWORD totalBytes = 0;
    
    while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        if (!WriteFile(hFile, buffer, bytesRead, &bytesWritten, nullptr)) {
            std::wcout << L"[-] Failed to write to file\n";
            CloseHandle(hFile);
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }
        totalBytes += bytesWritten;
    }
    
    std::wcout << L"[+] Downloaded " << totalBytes << L" bytes\n";
    
    CloseHandle(hFile);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return true;
}

bool SymbolDownloader::DownloadPdb(const std::wstring& modulePath) {
    std::wcout << L"[*] Extracting PDB information from: " << modulePath << L"\n";
    
    auto [pdbName, guid] = GetPdbInfoFromPe(modulePath);
    
    if (guid.empty() || pdbName.empty()) {
        std::wcout << L"[-] Failed to extract PDB info from PE file\n";
        return false;
    }
    
    std::wcout << L"[+] PDB Name: " << pdbName << L"\n";
    std::wcout << L"[+] PDB GUID: " << guid << L"\n";
    
    std::wstring url = symbolServer + L"/" + pdbName + L"/" + guid + L"/" + pdbName;
    
    std::wstring localDir = symbolCachePath + L"\\" + pdbName + L"\\" + guid;
    std::wstring localPath = localDir + L"\\" + pdbName;
    
    if (GetFileAttributesW(localPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        std::wcout << L"[+] PDB already exists in cache: " << localPath << L"\n";
        return true;
    }
    
    SHCreateDirectoryExW(nullptr, localDir.c_str(), nullptr);
    
    if (!DownloadFile(url, localPath)) {
        std::wcout << L"[-] Failed to download PDB file\n";
        return false;
    }
    
    std::wcout << L"[+] PDB downloaded successfully: " << localPath << L"\n";
    return true;
}

bool SymbolDownloader::DownloadSymbolsForModule(const std::wstring& modulePath) {
    std::wcout << L"[*] Preparing symbols for: " << modulePath << L"\n";
    
    auto [pdbName, guid] = GetPdbInfoFromPe(modulePath);
    
    if (guid.empty() || pdbName.empty()) {
        std::wcout << L"[-] Failed to read PE debug info\n";
        return false;
    }
    
    std::wstring localPath = symbolCachePath + L"\\" + pdbName + L"\\" + guid + L"\\" + pdbName;
    
    if (GetFileAttributesW(localPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcout << L"[*] PDB not in cache, downloading...\n";
        if (!DownloadPdb(modulePath)) {
            return false;
        }
    } else {
        std::wcout << L"[+] Using cached PDB: " << localPath << L"\n";
    }
    
    return true;
}

std::optional<uint64_t> SymbolDownloader::GetSymbolOffset(const std::wstring& moduleName, const std::wstring& symbolName) {
    std::wcout << L"[*] Looking up symbol: " << symbolName << L"\n";
    
    DWORD64 baseAddr = SymLoadModuleExW(GetCurrentProcess(), nullptr, moduleName.c_str(), nullptr, 0x10000000, 0, nullptr, 0);
    if (!baseAddr) {
        std::wcout << L"[-] Failed to load module symbols (error: " << GetLastError() << L")\n";
        return std::nullopt;
    }
    
    BYTE buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t)];
    PSYMBOL_INFOW pSymbol = (PSYMBOL_INFOW)buffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
    pSymbol->MaxNameLen = MAX_SYM_NAME;
    
    if (!SymFromNameW(GetCurrentProcess(), symbolName.c_str(), pSymbol)) {
        std::wcout << L"[-] Symbol not found: " << symbolName << L" (error: " << GetLastError() << L")\n";
        SymUnloadModule64(GetCurrentProcess(), baseAddr);
        return std::nullopt;
    }
    
    uint64_t offset = pSymbol->Address - baseAddr;
    std::wcout << L"[+] Symbol found: " << symbolName << L" at offset 0x" << std::hex << offset << std::dec << L"\n";
    
    SymUnloadModule64(GetCurrentProcess(), baseAddr);
    return offset;
}