/*
 * OmniUtility - Educational demonstration header
 * 
 * Purpose: Demonstrates kernel-mode memory operations through driver
 * Author: Educational demonstration
 * Requirements: Windows kernel driver (OmniDriver) loaded
 */

#pragma once

#include <windows.h>
#include <winternl.h>

// NTSTATUS type definition
typedef LONG NTSTATUS;

// Driver communication constants
#define IOCTL_READWRITE_DRIVER_READ  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READWRITE_DRIVER_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Status codes
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

#ifndef STATUS_INVALID_HANDLE
#define STATUS_INVALID_HANDLE ((NTSTATUS)0xC0000008L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif

#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Memory request structure matching kernel driver
struct MemoryRequest {
    ULONG processId;        // Target process ID
    ULONG_PTR address;      // Target address
    ULONG_PTR buffer;       // Source/destination buffer
    SIZE_T size;            // Transfer size
    BOOLEAN write;          // Read/Write flag
    NTSTATUS status;        // Operation status
};

// Function declarations
bool OpenDriver();
void CloseDriver();
NTSTATUS ReadMemory(DWORD pid, LPVOID address, LPVOID buffer, SIZE_T size);
NTSTATUS WriteMemory(DWORD pid, LPVOID address, LPVOID buffer, SIZE_T size);
void ModifyWindowTitles();
void RestoreWindowTitles();
void DemonstrateKernelRead();
void DemonstrateKernelWrite();
