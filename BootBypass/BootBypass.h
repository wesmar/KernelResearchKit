#pragma comment(lib, "ntdll.lib")
#pragma comment(linker, "/SUBSYSTEM:NATIVE /ENTRY:NtProcessStartup /NODEFAULTLIB /STACK:0x100000,0x100000")
#pragma optimize("", off)
#pragma check_stack(off)

#ifndef BootBypass_H
#define BootBypass_H

#define NTAPI __stdcall
#define NULL 0
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS 0
#define STATUS_NO_SUCH_DEVICE 0xC0000000
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034
#define STATUS_OBJECT_NAME_COLLISION 0xC0000035
#define STATUS_IMAGE_ALREADY_LOADED 0xC000010E
#define STATUS_REGISTRY_RECOVERED 0xC000014D
#define SE_LOAD_DRIVER_PRIVILEGE 10
#define SE_BACKUP_PRIVILEGE 17
#define SE_RESTORE_PRIVILEGE 18
#define SE_SHUTDOWN_PRIVILEGE 19
#define OBJ_CASE_INSENSITIVE 0x40
#define OBJ_KERNEL_HANDLE 0x200
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#define FILE_SHARE_READ 0x00000001
#define FILE_SHARE_WRITE 0x00000002
#define FILE_SHARE_DELETE 0x00000004
#define SYNCHRONIZE 0x00100000L
#define DELETE 0x00010000
#define FILE_READ_DATA 0x00000001
#define FILE_WRITE_DATA 0x00000002
#define FILE_OVERWRITE 0x00000004
#define FILE_CREATE 0x00000002
#define FILE_ATTRIBUTE_NORMAL 0x00000080
#define KEY_READ 0x00020019
#define KEY_WRITE 0x00020006
#define KEY_ALL_ACCESS 0x000F003F
#define REG_OPTION_NON_VOLATILE 0x00000000
#define REG_CREATED_NEW_KEY 0x00000001
#define REG_OPENED_EXISTING_KEY 0x00000002
#define REG_SZ 1
#define REG_EXPAND_SZ 2
#define REG_DWORD 4
#define REG_MULTI_SZ 7
#define MAX_ENTRIES 64
#define MAX_PATH_LEN 512
#define STATE_FILE_PATH L"\\SystemRoot\\drivers.ini"
#define HVCI_REG_PATH L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"
#define ShutdownReboot 1

typedef void VOID;
typedef unsigned char UCHAR;
typedef unsigned char BOOLEAN;
typedef unsigned short USHORT;
typedef unsigned short WCHAR;
typedef unsigned long ULONG;
typedef unsigned long DWORD;
typedef unsigned long long ULONGLONG;
typedef unsigned long long SIZE_T;
typedef long LONG;
typedef long NTSTATUS;
typedef void* HANDLE;
typedef void* PVOID;
typedef WCHAR* PWSTR;
typedef const WCHAR* PCWSTR;
typedef BOOLEAN* PBOOLEAN;
typedef HANDLE* PHANDLE;
typedef ULONG* PULONG;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef enum _ACTION_TYPE {
    ACTION_LOAD = 0,
    ACTION_UNLOAD = 1,
    ACTION_PATCH_DSE = 2,
    ACTION_UNPATCH_DSE = 3,
    ACTION_RENAME = 4
} ACTION_TYPE;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } u;
    ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef union _LARGE_INTEGER {
    struct {
        ULONG LowPart;
        LONG HighPart;
    };
    ULONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _FILE_RENAME_INFORMATION {
    BOOLEAN ReplaceIfExists;
    UCHAR Reserved[7];
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

#define FileStandardInformation 5

typedef struct _SYSTEM_MODULE_ENTRY {
    PVOID Reserved1;
    PVOID Reserved2;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    char ImageName[256];
} SYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION;

typedef struct _RTC_PACKET {
    UCHAR pad0[8];
    ULONGLONG addr;
    UCHAR pad1[8];
    ULONG size;
    ULONG value;
    UCHAR pad3[16];
} RTC_PACKET;

typedef struct _INI_ENTRY {
    ACTION_TYPE Action;
    
    // For LOAD/UNLOAD actions
    WCHAR ServiceName[MAX_PATH_LEN];
    WCHAR DisplayName[MAX_PATH_LEN];
    WCHAR ImagePath[MAX_PATH_LEN];
    WCHAR DriverType[16];
    WCHAR StartType[16];
    BOOLEAN CheckIfLoaded;
    
    // For PATCH/UNPATCH actions
    WCHAR DriverDevice[MAX_PATH_LEN];
    ULONG IoControlCode_Read;
    ULONG IoControlCode_Write;
    WCHAR TargetModule[MAX_PATH_LEN];
    ULONGLONG Offset_SeCiCallbacks;
    ULONGLONG Offset_Callback;
    ULONGLONG Offset_SafeFunction;
    
    // For RENAME actions
    WCHAR SourcePath[MAX_PATH_LEN];
    WCHAR TargetPath[MAX_PATH_LEN];
    BOOLEAN ReplaceIfExists;
    
} INI_ENTRY, *PINI_ENTRY;

#define InitializeObjectAttributes(p, n, a, r, s) \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL

// NT API functions
__declspec(dllimport) NTSTATUS NTAPI NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, ULONG FileInformationClass);
__declspec(dllimport) NTSTATUS NTAPI NtOpenKey(PHANDLE KeyHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
__declspec(dllimport) NTSTATUS NTAPI NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
__declspec(dllimport) NTSTATUS NTAPI NtFlushKey(HANDLE KeyHandle);
__declspec(dllimport) NTSTATUS NTAPI NtShutdownSystem(ULONG Action);
__declspec(dllimport) NTSTATUS NTAPI NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
__declspec(dllimport) NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN OldValue);
__declspec(dllimport) VOID NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
__declspec(dllimport) NTSTATUS NTAPI NtUnloadDriver(PUNICODE_STRING DriverServiceName);
__declspec(dllimport) NTSTATUS NTAPI NtLoadDriver(PUNICODE_STRING DriverServiceName);
__declspec(dllimport) NTSTATUS NTAPI NtDisplayString(PUNICODE_STRING String);
__declspec(dllimport) NTSTATUS NTAPI NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
__declspec(dllimport) NTSTATUS NTAPI NtOpenFile(PHANDLE FileHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
__declspec(dllimport) NTSTATUS NTAPI NtCreateFile(PHANDLE FileHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
__declspec(dllimport) NTSTATUS NTAPI NtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
__declspec(dllimport) NTSTATUS NTAPI NtWriteFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
__declspec(dllimport) NTSTATUS NTAPI NtClose(HANDLE Handle);
__declspec(dllimport) NTSTATUS NTAPI NtCreateKey(PHANDLE KeyHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition);
__declspec(dllimport) NTSTATUS NTAPI NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);
__declspec(dllimport) NTSTATUS NTAPI NtDeleteKey(HANDLE KeyHandle);
__declspec(dllimport) NTSTATUS NTAPI NtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName);
__declspec(dllimport) NTSTATUS NTAPI NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, ULONG FileInformationClass);
__declspec(dllimport) NTSTATUS NTAPI NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
__declspec(dllimport) NTSTATUS NTAPI NtQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
__declspec(dllimport) NTSTATUS NTAPI NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, ULONG FileInformationClass);

// Updated function declarations with better names
BOOLEAN LoadStateSection(ULONGLONG* outCallback);
BOOLEAN CheckAndDisableHVCI(void);
BOOLEAN RemoveStateSection(void);
BOOLEAN SaveStateSection(ULONGLONG callback);
NTSTATUS AddThemesDependency(void);
NTSTATUS RemoveThemesDependency(void); 
NTSTATUS RestoreHVCI(void);

#endif
