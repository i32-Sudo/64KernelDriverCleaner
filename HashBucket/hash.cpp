#include "../global.h"

/* 1903, 1909, 2004, 20H2, 21H1*/
#define KernelBucketHashPattern_21H1 "\x4C\x8D\x35\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x8B\x84\x24"
#define KernelBucketHashMask_21H1 "xxx????x????xxx"

/* 22H2 */
#define KernelBucketHashPattern_22H2 "\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00"
#define KernelBucketHashMask_22H2 "xxx????x?xxxxxxx"

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