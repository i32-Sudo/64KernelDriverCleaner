#include "../global.h"

/* 1903, 1909, 2004, 20H2, 21H1, 22H2 */
#define MmuPattern "\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9"
#define MmuMask "xxx????xxx"

/* 1903, 1909, 2004, 20H2, 21H1, 22H2 */
#define MmlPattern "\x8B\x05\x00\x00\x00\x00\x83\xF8\x32"
#define MmlMask "xx????xxx"

PMM_UNLOADED_DRIVER
GetMmuAddress() {
	PCHAR base = (PCHAR)GetKernelBase2();

	char* pMmuPattern = _(MmuPattern);
	char* pMmuMask = _(MmuMask);

	PVOID MmUnloadedDriversInstr = FindPatternImage(base, pMmuPattern, pMmuMask);

	if (MmUnloadedDriversInstr == NULL)
		return { };

	return *(PMM_UNLOADED_DRIVER*)ResolveRelativeAddress(MmUnloadedDriversInstr, 3, 7);
}

PULONG
GetMmlAddress() {
	PCHAR Base = (PCHAR)GetKernelBase2();

	char* pMmlPattern = _(MmlPattern);
	char* pMmlMask = _(MmlMask);

	PVOID mmlastunloadeddriverinst = FindPatternImage(Base, pMmlPattern, pMmlMask);

	if (mmlastunloadeddriverinst == NULL)
		return { };

	return (PULONG)ResolveRelativeAddress(mmlastunloadeddriverinst, 2, 6);
}

BOOL
VerifyMmu() {
	return (GetMmuAddress() != NULL && GetMmlAddress() != NULL);
}

BOOL
IsUnloadEmpty(
	PMM_UNLOADED_DRIVER Entry
) {
	if (Entry->Name.MaximumLength == 0 || Entry->Name.Length == 0 || Entry->Name.Buffer == NULL)
		return TRUE;

	return FALSE;
}

BOOL
IsMmuFilled() {
	for (ULONG Idx = 0; Idx < MM_UNLOADED_DRIVERS_SIZE; ++Idx) {
		PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Idx];
		if (IsUnloadEmpty(Entry))
			return FALSE;
	}
	return TRUE;
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