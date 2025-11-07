// ReadWriteDriver - Minimal kernel memory R/W driver

#include "OmniDriver.h"
#include <ntdef.h>
#include <ntifs.h>

#define DEVICE_NAME L"\\Device\\ReadWriteDriver"
#define SYMBOLIC_NAME L"\\DosDevices\\ReadWriteDriver"
#define POOL_TAG 'pmwR'
#define MAX_SIZE (PAGE_SIZE * 4)

PDEVICE_OBJECT g_DeviceObject = NULL;
UNICODE_STRING g_DeviceName, g_SymbolicLink;

// Handle create/close
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Cleanup on unload
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    if (g_DeviceObject) {
        IoDeleteSymbolicLink(&g_SymbolicLink);
        IoDeleteDevice(g_DeviceObject);
    }
}

// Copy memory between processes using temporary kernel buffer
NTSTATUS CopyMemoryBetweenProcesses(PEPROCESS SrcProc, PVOID SrcAddr, PEPROCESS DstProc, PVOID DstAddr, SIZE_T Size)
{
    KAPC_STATE apc;
    PVOID buf = NULL;
    BOOLEAN attached = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, POOL_TAG);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    __try {
        KeStackAttachProcess(SrcProc, &apc);
        attached = TRUE;
        ProbeForRead(SrcAddr, Size, sizeof(UCHAR));
        RtlCopyMemory(buf, SrcAddr, Size);
        KeUnstackDetachProcess(&apc);
        attached = FALSE;
        
        KeStackAttachProcess(DstProc, &apc);
        attached = TRUE;
        ProbeForWrite(DstAddr, Size, sizeof(UCHAR));
        RtlCopyMemory(DstAddr, buf, Size);
        KeUnstackDetachProcess(&apc);
        attached = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (attached) KeUnstackDetachProcess(&apc);
    }

    if (buf) ExFreePoolWithTag(buf, POOL_TAG);
    return status;
}

// Process memory read/write request
NTSTATUS ReadWriteMemory(PKERNEL_READWRITE_REQUEST Req)
{
    PEPROCESS target = NULL;
    PEPROCESS current;
    NTSTATUS status;

    if (!Req || Req->Size == 0 || Req->Size > MAX_SIZE) 
        return STATUS_INVALID_PARAMETER;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Req->ProcessId, &target);
    if (!NT_SUCCESS(status)) return status;

    current = PsGetCurrentProcess();

    __try {
        if (Req->Write) {
            status = CopyMemoryBetweenProcesses(current, (PVOID)Req->Buffer, target, (PVOID)Req->Address, Req->Size);
        } else {
            status = CopyMemoryBetweenProcesses(target, (PVOID)Req->Address, current, (PVOID)Req->Buffer, Req->Size);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (target) ObDereferenceObject(target);
    return status;
}

// Handle IOCTL requests
NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    stack = IoGetCurrentIrpStackLocation(Irp);

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_READWRITE_DRIVER_READ:
        case IOCTL_READWRITE_DRIVER_WRITE:
            if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(KERNEL_READWRITE_REQUEST)) {
                PKERNEL_READWRITE_REQUEST req = (PKERNEL_READWRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
                req->Status = ReadWriteMemory(req);
                Irp->IoStatus.Information = sizeof(KERNEL_READWRITE_REQUEST);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// Driver entry point
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&g_DeviceName, DEVICE_NAME);
    RtlInitUnicodeString(&g_SymbolicLink, SYMBOLIC_NAME);

    status = IoCreateDevice(DriverObject, 0, &g_DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&g_SymbolicLink, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

    return STATUS_SUCCESS;
}