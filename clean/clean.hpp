#pragma once
#include "../kernel/struct.h"
#include "../kernel/log.h"
#include "../kernel/kernelTools.h"
#include "../kernel/xor.h"

#define BB_POOL_TAG 'Esk' // For Recognition

/*  */

NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound, int index = 0)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_ACCESS_DENIED; //STATUS_INVALID_PARAMETER;
	int cIndex = 0;
	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE && cIndex++ == index)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;

PVOID GetKernelBase(OUT PULONG pSize)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	PVOID checkPtr = NULL;
	UNICODE_STRING routineName;

	// Already found
	if (g_KernelBase != NULL)
	{
		if (pSize)
			*pSize = g_KernelSize;
		return g_KernelBase;
	}

	RtlUnicodeStringInit(&routineName, _(L"NtOpenFile"));

	checkPtr = MmGetSystemRoutineAddress(&routineName);
	if (checkPtr == NULL)
		return NULL;

	// Protect from UserMode AV
	status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
	if (bytes == 0)
	{
		log(_("Invalid SystemModuleInformation size"));
		return NULL;
	}

	pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, BB_POOL_TAG);
	if (pMods) {
		RtlZeroMemory(pMods, bytes);
	}
	else {
		log(_("pMods = NULL"));
		return NULL;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

	if (NT_SUCCESS(status))
	{
		PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

		for (ULONG i = 0; i < pMods->NumberOfModules; i++)
		{
			// System routine is inside module
			if (checkPtr >= pMod[i].ImageBase &&
				checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
			{
				g_KernelBase = pMod[i].ImageBase;
				g_KernelSize = pMod[i].ImageSize;
				if (pSize)
					*pSize = g_KernelSize;
				break;
			}
		}
	}

	if (pMods)
		ExFreePoolWithTag(pMods, BB_POOL_TAG);
	//log("g_KernelBase: %x", g_KernelBase);
	//log("g_KernelSize: %x", g_KernelSize);
	return g_KernelBase;
}

NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound, PVOID base = nullptr)
{
	//ASSERT(ppFound != NULL);
	if (ppFound == NULL)
		return STATUS_ACCESS_DENIED; //STATUS_INVALID_PARAMETER

	if (nullptr == base)
		base = GetKernelBase(&g_KernelSize);
	if (base == nullptr)
		return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;

	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr)
		return STATUS_ACCESS_DENIED; // STATUS_INVALID_IMAGE_FORMAT;

	//PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&pHdr->FileHeader + pHdr->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		//DbgPrint("section: %s\r\n", pSection->Name);
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if (RtlCompareString(&s1, &s2, TRUE) == 0)
		{
			PVOID ptr = NULL;
			NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status)) {
				*(PULONG64)ppFound = (ULONG_PTR)(ptr); //- (PUCHAR)base
				//DbgPrint("found\r\n");
				return status;
			}
			//we continue scanning because there can be multiple sections with the same name.
		}
	}

	return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;
}
extern "C" bool LocatePiDDB(PERESOURCE * lock, PRTL_AVL_TABLE * table)
{
	PVOID PiDDBLockPtr = nullptr, PiDDBCacheTablePtr = nullptr;

	if (NT_SUCCESS(BBScanSection(_("PAGE"), PiDDBLockPtr_sig_win10, 0, sizeof(PiDDBLockPtr_sig_win10) - 1, reinterpret_cast<PVOID*>(&PiDDBLockPtr)))) {
		/* Win10 Signature Captured */
		PiDDBLockPtr = PVOID((uintptr_t)PiDDBLockPtr + 28);
		log(_("Win10 Signature Found"));
	}
	else {
		/* Win10 Signature Failed */
		if (NT_SUCCESS(BBScanSection(_("PAGE"), PiDDBLockPtr_sig_win11, 0, sizeof(PiDDBLockPtr_sig_win11) - 1, reinterpret_cast<PVOID*>(&PiDDBLockPtr)))) {
			/* Win11 Signature Captured */
			PiDDBLockPtr = PVOID((uintptr_t)PiDDBLockPtr + 16);
			log(_("Win11 Signature Found"));
		}
		else {
			/* Both Failed */
			log(_("Could not find PiDDB for Win10 or Win11..."));
			return 1;
		}

	}

	if (!NT_SUCCESS(BBScanSection(_("PAGE"), PiDDBCacheTablePtr_sig, 0, sizeof(PiDDBCacheTablePtr_sig) - 1, reinterpret_cast<PVOID*>(&PiDDBCacheTablePtr)))) {
		log(_("Unable to find PiDDBCacheTablePtr sig"));
		return false;
	}

	PiDDBCacheTablePtr = PVOID((uintptr_t)PiDDBCacheTablePtr + 3);

	*lock = (PERESOURCE)(ResolveRelativeAddress(PiDDBLockPtr, 3, 7));
	*table = (PRTL_AVL_TABLE)(ResolveRelativeAddress(PiDDBCacheTablePtr, 3, 7));

	return true;
}





PMM_UNLOADED_DRIVER MmUnloadedDrivers;
PULONG				MmLastUnloadedDriver;

BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;

	return (*szMask) == 0;
}

UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE* bMask, char* szMask)
{
	for (UINT64 i = 0; i < dwLen; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (UINT64)(dwAddress + i);

	return 0;
}

BOOLEAN IsUnloadedDriverEntryEmpty(
	_In_ PMM_UNLOADED_DRIVER Entry
)
{
	if (Entry->Name.MaximumLength == 0 ||
		Entry->Name.Length == 0 ||
		Entry->Name.Buffer == NULL)
	{
		return TRUE;
	}

	return FALSE;
}

BOOLEAN IsMmUnloadedDriversFilled(
	VOID
)
{
	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
	{
		PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
		if (IsUnloadedDriverEntryEmpty(Entry))
		{
			return FALSE;
		}
	}

	return TRUE;
}



ERESOURCE PsLoadedModuleResource;




namespace clear {

	BOOL clearCache(UNICODE_STRING DriverName, ULONG timeDateStamp) {
		PERESOURCE PiDDBLock; PRTL_AVL_TABLE PiDDBCacheTable;
		if (!LocatePiDDB(&PiDDBLock, &PiDDBCacheTable)) {
			log(_("ClearCache Failed"));
			return 1;
		}

		PiDDBCacheEntry lookupEntry = { };
		lookupEntry.DriverName = DriverName;
		lookupEntry.TimeDateStamp = timeDateStamp;

		ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);
		auto pFoundEntry = (PiDDBCacheEntry*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &lookupEntry);
		if (pFoundEntry == nullptr)
		{
			// release the ddb resource lock
			ExReleaseResourceLite(PiDDBLock);
			log(_("ClearCache Failed (Not found)"));
			return 1;
		}
		// first, unlink from the list
		RemoveEntryList(&pFoundEntry->List);
		// then delete the element from the avl table
		if (!RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry)) {
			log(_("RtlDeleteElementFromTableAVL Failed!"));
			return 1;
		}

		// release the ddb resource lock
		ExReleaseResourceLite(PiDDBLock);
		log(_("chache cleared"));
		return 0;
	}

	BOOL clearHashBucket(UNICODE_STRING DriverName) {
		char* CIDLLString = _("ci.dll");
		CONST PVOID CIDLLBase = GetKernelModuleBase(CIDLLString);

		if (!CIDLLBase) {
			log(_("Couldn't Find CIDDLBase"));
			return 1;
		}

		char* pKernelBucketHashPattern_21H1 = _(KernelBucketHashPattern_21H1);
		char* pKernelBucketHashMask_21H1 = _(KernelBucketHashMask_21H1);

		char* pKernelBucketHashPattern_22H2 = _(KernelBucketHashPattern_22H2);
		char* pKernelBucketHashMask_22H2 = _(KernelBucketHashMask_22H2);

		PVOID SignatureAddress = FindPatternImage((PCHAR)CIDLLBase, pKernelBucketHashPattern_21H1, pKernelBucketHashMask_21H1);
		if (!SignatureAddress) {
			SignatureAddress = FindPatternImage((PCHAR)CIDLLBase, pKernelBucketHashPattern_22H2, pKernelBucketHashMask_22H2);
			if (!SignatureAddress) {
				log(_("Couldn't find signature address for KernelBucketHash"));
				return 1;
			}
		}

		CONST ULONGLONG* g_KernelHashBucketList = (ULONGLONG*)ResolveRelativeAddress(SignatureAddress, 3, 7);
		if (!g_KernelHashBucketList) {
			return 1;
		}

		LARGE_INTEGER Time{};
		KeQuerySystemTimePrecise(&Time);

		BOOL Status = FALSE;
		for (ULONGLONG i = *g_KernelHashBucketList; i; i = *(ULONGLONG*)i) {
			CONST PWCHAR wsName = PWCH(i + 0x48);
			if (wcsstr(wsName, DriverName.Buffer)) {
				PUCHAR Hash = PUCHAR(i + 0x18);
				for (UINT j = 0; j < 20; j++)
					Hash[j] = UCHAR(RtlRandomEx(&Time.LowPart) % 255);

				Status = TRUE;
			}
		}

		if (Status == FALSE) {
			log(_("KernelHashBucket Failed to Clean"));
			return 1;
		}
		else {
			log(_("KernelHashBucket Cleaned!"));
			return 0;
		}
		return 0;
	}

	BOOL
		CleanMmu(
			UNICODE_STRING DriverName
		) {
		auto ps_loaded = GetPsLoaded();

		if (ps_loaded == NULL) {
			log(_("Failed to get ps_loaded resource"));
			return 1;
		}

		ExAcquireResourceExclusiveLite(ps_loaded, TRUE);

		BOOLEAN Modified = FALSE;
		BOOLEAN Filled = IsMmuFilled();

		for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index) {
			PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];
			if (IsUnloadEmpty(Entry)) {
				continue;
			}
			BOOL empty = IsUnloadEmpty(Entry);
			if (Modified) {
				PMM_UNLOADED_DRIVER PrevEntry = &GetMmuAddress()[Index - 1];
				RtlCopyMemory(PrevEntry, Entry, sizeof(MM_UNLOADED_DRIVER));

				if (Index == MM_UNLOADED_DRIVERS_SIZE - 1) {
					RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
				}
			}
			else if (RtlEqualUnicodeString(&DriverName, &Entry->Name, TRUE)) {
				PVOID BufferPool = Entry->Name.Buffer;
				RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
				ExFreePoolWithTag(BufferPool, 'TDmM');

				*GetMmlAddress() = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *GetMmlAddress()) - 1;
				Modified = TRUE;
			}
		}

		if (Modified) {
			ULONG64 PreviousTime = 0;

			for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index) {
				PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];
				if (IsUnloadEmpty(Entry)) {
					continue;
				}

				if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime) {
					Entry->UnloadTime = PreviousTime - RandomNumber();
				}

				PreviousTime = Entry->UnloadTime;
			}

			CleanMmu(DriverName);
		}

		ExReleaseResourceLite(ps_loaded);

		if (Modified == FALSE) {
			log(_("No modifications were made"));
			return 1;
		}
		else {
			log(_("Modifications to MMU/MML Were made and have been cleared..."));
			return 0;
		}

		return 0;
	}
}