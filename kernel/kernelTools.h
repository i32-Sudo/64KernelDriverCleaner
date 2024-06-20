#pragma once
#include "../kernel/xor.h"

/* 1903, 1909, 2004, 20H2, 21H1, 22H2 */
#define MmuPattern "\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9"
#define MmuMask "xxx????xxx"

/* 1903, 1909, 2004, 20H2, 21H1, 22H2 */
#define MmlPattern "\x8B\x05\x00\x00\x00\x00\x83\xF8\x32"
#define MmlMask "xx????xxx"

/* 1903, 1909, 2004, 20H2, 21H1*/
#define KernelBucketHashPattern_21H1 "\x4C\x8D\x35\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x8B\x84\x24"
#define KernelBucketHashMask_21H1 "xxx????x????xxx"

/* 22H2 */
#define KernelBucketHashPattern_22H2 "\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00"
#define KernelBucketHashMask_22H2 "xxx????x?xxxxxxx"

/* 1903, 1909, 2004, 20H2, 21H1*/
UCHAR PiDDBLockPtr_sig_win10[] = "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24";

/* 22H2 */
UCHAR PiDDBLockPtr_sig_win11[] = "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8";

/* 1903, 1909, 2004, 20H2, 21H1, 22H2 */
UCHAR PiDDBCacheTablePtr_sig[] = "\x66\x03\xD2\x48\x8D\x0D";

EXTERN_C PVOID ResolveRelativeAddress(
	_In_ PVOID Instruction,
	_In_ ULONG OffsetOffset,
	_In_ ULONG InstructionSize
)
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

	return ResolvedAddr;
}

static char* stristr(const char* str1, const char* str2) {
	const char* p1 = str1;
	const char* p2 = str2;
	const char* r = *p2 == 0 ? str1 : 0;
	while (*p1 != 0 && *p2 != 0)
	{
		if (tolower((unsigned char)*p1) == tolower((unsigned char)*p2))
		{
			if (r == 0)
			{
				r = p1;
			}
			p2++;
		}
		else
		{
			p2 = str2;
			if (r != 0)
			{
				p1 = r + 1;
			}
			if (tolower((unsigned char)*p1) == tolower((unsigned char)*p2))
			{
				r = p1;
				p2++;
			}
			else
			{
				r = 0;
			}
		}
		p1++;
	}
	return *p2 == 0 ? (char*)r : 0;
}

PVOID
	GetKernelModuleBase(
		CHAR* ModuleName
	) {
	PVOID ModuleBase = NULL;

	ULONG size = NULL;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		return ModuleBase;
	}

	PSYSTEM_MODULE_INFORMATION Modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, size);
	if (!Modules) {
		return ModuleBase;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, Modules, size, 0))) {
		ExFreePool(Modules);
		return ModuleBase;
	}

	for (UINT i = 0; i < Modules->NumberOfModules; i++) {
		CHAR* CurrentModuleName = reinterpret_cast<CHAR*>(Modules->Modules[i].FullPathName);
		if (stristr(CurrentModuleName, ModuleName)) {
			ModuleBase = Modules->Modules[i].ImageBase;
			break;
		}
	}

	ExFreePool(Modules);
	return ModuleBase;
}

BOOL
	CheckMask(
		PCHAR Base,
		PCHAR Pattern,
		PCHAR Mask
	) {
	for (; *Mask; ++Base, ++Pattern, ++Mask) {
		if (*Mask == 'x' && *Base != *Pattern) {
			return FALSE;
		}
	}

	return TRUE;
}

PVOID
	FindPattern2(
		PCHAR Base,
		DWORD Length,
		PCHAR Pattern,
		PCHAR Mask
	) {
	Length -= (DWORD)strlen(Mask);
	for (DWORD i = 0; i <= Length; ++i) {
		PVOID Addr = &Base[i];
		if (CheckMask((PCHAR)Addr, Pattern, Mask)) {
			return Addr;
		}
	}

	return 0;
}

PVOID FindPatternImage(
	PCHAR Base,
	PCHAR Pattern,
	PCHAR Mask
) {
	PVOID Match = 0;

	PIMAGE_NT_HEADERS Headers = (PIMAGE_NT_HEADERS)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
	PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Headers);
	for (DWORD i = 0; i < Headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER Section = &Sections[i];
		if (*(PINT)Section->Name == 'EGAP' || memcmp(Section->Name, _(".text"), 5) == 0) {
			Match = FindPattern2(Base + Section->VirtualAddress, Section->Misc.VirtualSize, Pattern, Mask);
			if (Match) {
				break;
			}
		}
	}

	return Match;
}

PVOID GetKernelBase2() {
	PVOID KernelBase = NULL;

	ULONG size = NULL;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		return KernelBase;
	}

	PSYSTEM_MODULE_INFORMATION Modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, size);
	if (!Modules) {
		return KernelBase;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, Modules, size, 0))) {
		ExFreePool(Modules);
		return KernelBase;
	}

	if (Modules->NumberOfModules > 0) {
		KernelBase = Modules->Modules[0].ImageBase;
	}

	ExFreePool(Modules);
	return KernelBase;
}

ULONGLONG GetExportedFunction(
	CONST ULONGLONG mod,
	CONST CHAR* name
) {
	const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(mod);
	const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<ULONGLONG>(dos_header) + dos_header->e_lfanew);

	const auto data_directory = nt_headers->OptionalHeader.DataDirectory[0];
	const auto export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(mod + data_directory.VirtualAddress);

	const auto address_of_names = reinterpret_cast<ULONG*>(mod + export_directory->AddressOfNames);

	for (size_t i = 0; i < export_directory->NumberOfNames; i++)
	{
		const auto function_name = reinterpret_cast<const char*>(mod + address_of_names[i]);

		if (!_stricmp(function_name, name))
		{
			const auto name_ordinal = reinterpret_cast<unsigned short*>(mod + export_directory->AddressOfNameOrdinals)[i];

			const auto function_rva = mod + reinterpret_cast<ULONG*>(mod + export_directory->AddressOfFunctions)[name_ordinal];
			return function_rva;
		}
	}

	return 0;
}

#define MM_UNLOADED_DRIVERS_SIZE 50
typedef struct _MM_UNLOADED_DRIVER {
	UNICODE_STRING 	Name;
	PVOID 			ModuleStart;
	PVOID 			ModuleEnd;
	ULONG64 		UnloadTime;
} MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;

PERESOURCE
GetPsLoaded() {
	PCHAR base = (PCHAR)GetKernelBase2();

	auto cMmGetSystemRoutineAddress = reinterpret_cast<decltype(&MmGetSystemRoutineAddress)>(GetExportedFunction((ULONGLONG)base, _("MmGetSystemRoutineAddress")));

	ERESOURCE PsLoadedModuleResource;
	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"PsLoadedModuleResource");
	auto cPsLoadedModuleResource = reinterpret_cast<decltype(&PsLoadedModuleResource)>(cMmGetSystemRoutineAddress(&routineName));

	return cPsLoadedModuleResource;
}

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

UCHAR
RandomNumber() {
	PVOID Base = GetKernelBase2();

	auto cMmGetSystemRoutineAddress = reinterpret_cast<decltype(&MmGetSystemRoutineAddress)>(GetExportedFunction((ULONGLONG)Base, _("MmGetSystemRoutineAddress")));

	UNICODE_STRING RoutineName = RTL_CONSTANT_STRING(L"RtlRandom");
	auto cRtlRandom = reinterpret_cast<decltype(&RtlRandom)>(cMmGetSystemRoutineAddress(&RoutineName));

	ULONG Seed = 1234765;
	ULONG Rand = cRtlRandom(&Seed) % 100;

	UCHAR RandInt = 0;

	if (Rand >= 101 || Rand <= -1)
		RandInt = 72;

	return (UCHAR)(Rand);
}