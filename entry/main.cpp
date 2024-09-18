#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>

#include "../global.h"

extern "C" DRIVER_INITIALIZE DriverEntry;

//extern void NTAPI initiliaze_sys(void*);

EXTERN_C
PLIST_ENTRY PsLoadedModuleList;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	/*PNON_PAGED_DEBUG_INFO*/ PVOID NonPagedDebugInfo;
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
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;


void CleanDriverSys(UNICODE_STRING driver_int, ULONG timeDateStamp) {
	if (clearCache(driver_int, timeDateStamp) == 0) {
		log(_("PiDDB Cache Found and Cleared!"));
	}
	else {
		log(_("PiDDB Non-Zero"));
	}
	if (clearHashBucket(driver_int) == 0) {
		log(_("HashBucket Found and Cleared!"));
	}
	else {
		log(_("HashBucket Non-Zero"));
	}
	if (CleanMmu(driver_int) == 0) {
		log(_("MMU/MML Found and Cleaned!"));
	}
	else {
		log(_("MMU/MML Non-Zero"));
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////

extern "C" NTSTATUS OEPDriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	NTSTATUS status = STATUS_SUCCESS;
	KeEnterGuardedRegion();
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, _(" - OEP Started"));

	//////////////////////////////////////////////////////////////////////////////////////////////////////////

	/*
	0x5284EAC3 - iqvw64e.sys
	0xBF8A5E6A - srv2.sys | 2071-10-31 14:26:34
	0x63EF9904 - DriverK.sys | Feb 16 2023 6:31
	0x611AB60D - PROCEXP152.SYS | August 16, 2021 7:01:33 PM
	*/

	// Loader Drivers @ Host Driver
	CleanDriverSys(UNICODE_STRING(RTL_CONSTANT_STRING(L"DriverK.sys")), 0x63EF9904); /* Cheat Driver (Current Driver) */
	CleanDriverSys(UNICODE_STRING(RTL_CONSTANT_STRING(L"PROCEXP152.sys")), 0x611AB60D); /* Exploit-Vulnerable Driver (Mapping Driver) */


	KeLeaveGuardedRegion();
	return STATUS_SUCCESS;
}

/* Fake OEP */
extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, _(" - Driver Started"));
	return OEPDriverEntry(DriverObject, RegistryPath);
}
