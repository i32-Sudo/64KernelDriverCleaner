#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include "IoCreateDriver/CreateDriver.h"
#include "../clean/clean.hpp"
#include "../kernel/log.h"
#include "../kernel/xor.h"
#include "../kernel/structures.hpp"

// Function to clean driver systems
void CleanDriverSys(const UNICODE_STRING& driverInt, ULONG timeDateStamp) {
    if (clear::clearCache(driverInt, timeDateStamp) == 0) {
        log(_("PiDDB Cache Found and Cleared!"));
    }
    else {
        log(_("PiDDB Non-Zero"));
    }

    if (clear::clearHashBucket(driverInt) == 0) {
        log(_("HashBucket Found and Cleared!"));
    }
    else {
        log(_("HashBucket Non-Zero"));
    }

    if (clear::CleanMmu(driverInt) == 0) {
        log(_("MMU/MML Found and Cleaned!"));
    }
    else {
        log(_("MMU/MML Non-Zero"));
    }
}

EXTERN_C
PLIST_ENTRY PsLoadedModuleList;

typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    PVOID GpValue;
    PVOID NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Unused5;
    PVOID SectionPointer;
    ULONG CheckSum;
    PVOID LoadedImports;
    PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

EXTERN_C
NTSTATUS OEPDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status = STATUS_SUCCESS;

    KeEnterGuardedRegion();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, _(" - OEP Started"));

    PKLDR_DATA_TABLE_ENTRY pSelfEntry = nullptr;
    for (auto pNext = PsLoadedModuleList->Flink; pNext != PsLoadedModuleList; pNext = pNext->Flink) {
        auto pEntry = CONTAINING_RECORD(pNext, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (DriverObject->DriverStart == pEntry->DllBase) {
            pSelfEntry = pEntry;
            break;
        }
    }

    if (pSelfEntry) {
        KIRQL kIrql = KeRaiseIrqlToDpcLevel();
        auto pPrevEntry = (PKLDR_DATA_TABLE_ENTRY)pSelfEntry->InLoadOrderLinks.Blink;
        auto pNextEntry = (PKLDR_DATA_TABLE_ENTRY)pSelfEntry->InLoadOrderLinks.Flink;

        if (pPrevEntry) {
            pPrevEntry->InLoadOrderLinks.Flink = pSelfEntry->InLoadOrderLinks.Flink;
        }
        if (pNextEntry) {
            pNextEntry->InLoadOrderLinks.Blink = pSelfEntry->InLoadOrderLinks.Blink;
        }
        pSelfEntry->InLoadOrderLinks.Flink = (PLIST_ENTRY)pSelfEntry;
        pSelfEntry->InLoadOrderLinks.Blink = (PLIST_ENTRY)pSelfEntry;

        KeLowerIrql(kIrql);
    }

    // Clean specific drivers
    CleanDriverSys(RTL_CONSTANT_STRING(L"DriverKL.sys"), 0x63EF9904);
    CleanDriverSys(RTL_CONSTANT_STRING(L"srv2.sys"), 0xBF8A5E6A);
    CleanDriverSys(RTL_CONSTANT_STRING(L"PROCEXP152.sys"), 0x611AB60D);

    KeLeaveGuardedRegion();
    return STATUS_SUCCESS;
}

EXTERN_C
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, _(" - Driver Started"));
    return IoCreateDriver(OEPDriverEntry);
}
