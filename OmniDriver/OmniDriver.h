/*
 * ReadWriteDriver - Kernel-mode driver for inter-process memory operations
 *
 * This driver provides secure read/write access to process memory space
 * through IOCTL interface. Implements proper process attachment and
 * exception handling to prevent system crashes.
 *
 * Author: Marek Wesołowski
 * Purpose: Educational demonstration of kernel-mode programming
 */

#pragma once

#include <ntdef.h>

 // IOCTL codes for driver communication
#define IOCTL_READWRITE_DRIVER_READ  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READWRITE_DRIVER_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Memory pool tag for allocations (reversed 'RWpm' = 'pmwR')
#define MEMORY_POOL_TAG 'pmwR'

// Maximum transfer size (4 pages = 16KB)
#define MAX_TRANSFER_SIZE (PAGE_SIZE * 4)

/*
 * Structure for read/write requests
 *
 * This structure is passed between user-mode and kernel-mode
 * to perform memory operations on target processes.
 */
typedef struct _KERNEL_READWRITE_REQUEST {
    ULONG ProcessId;        // Target process ID
    ULONG_PTR Address;      // Target address in process memory
    ULONG_PTR Buffer;       // Source/destination buffer in caller's memory
    SIZE_T Size;            // Number of bytes to transfer
    BOOLEAN Write;          // TRUE = write, FALSE = read
    NTSTATUS Status;        // Operation result status
} KERNEL_READWRITE_REQUEST, * PKERNEL_READWRITE_REQUEST;