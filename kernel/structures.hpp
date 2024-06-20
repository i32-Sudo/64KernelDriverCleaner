#pragma once
#include <stdint.h>
#include <ntddmou.h>
#include <ntddk.h>
#include <ntifs.h>

namespace globals
{
	uintptr_t entry_point = 0;
	uintptr_t cave_base = 0;
	uintptr_t ntos_image_base = 0;
	uintptr_t win32k_image_base = 0;

	uintptr_t shadow_base = 0;
	PETHREAD k_thread = 0;

	// driver
	NTSTATUS( __fastcall* mi_process_loader_entry )(PVOID pDriverSection, BOOLEAN bLoad);
	NTSTATUS( __fastcall* io_create_driver )(_In_opt_ PUNICODE_STRING Driver, PDRIVER_INITIALIZE INIT);

	// mouse -> i would hook MouClass
	NTSTATUS( __fastcall* RIMIDECreatePseudoMouseOrKeyboardDevice )(UINT, PVOID) = nullptr;
	NTSTATUS( __fastcall* RIMIDEInjectMouseFromMouseInputStruct )(PVOID, PVOID, UINT) = nullptr;
	NTSTATUS( __fastcall* RawInputManagerDeviceObjectResolveHandle )(PVOID, ACCESS_MASK, KPROCESSOR_MODE, PVOID*) = nullptr;
	PVOID( __fastcall* PsGetCurrentProcessWin32Process )(VOID) = nullptr;
}

/*
 * Generic macros that allow you to quickly determine whether
 *  or not a page table entry is present or may forward to a
 *  large page of data, rather than another page table (applies
 *  only to PDPTEs and PDEs)
 */
#define IS_LARGE_PAGE(x)    ( (BOOLEAN)((x >> 7) & 1) )
#define IS_PAGE_PRESENT(x)  ( (BOOLEAN)(x & 1) )

 /*
  * Macros allowing us to more easily deal with page offsets.
  *
  * The *_SHIFT values will allow us to correctly format physical
  *  addresses obtained using the bitfield structures below.
  *
  * The *_OFFSET macro functions will pull out physical page
  *  offsets from virtual addresses. This is only really to make handling
  *  1GB huge pages and 2MB large pages easier.
  * An example: 2MB large pages will require a 21-bit offset to index
  *  page data at one-byte granularity. So if we have the physical base address
  *  of a 2MB large page, in order to get the right physical address for our
  *  target data, we need to add the bottom 21-bits of a virtual address to this
 *   base address. MAXUINT64 is simply a 64-bit value with every possible bit
 *   set (0xFFFFFFFF`FFFFFFFF). In the case of a 2MB large page, we need the
 *   bottom 21-bits from a virtual address to index, so we apply a function which
 *   shifts this MAXUINT64 value by 21-bits, and then inverts all of the bits to
  *  create a mask that can pull out the bottom 21-bits of a target virtual
  *  address. The resulting mask is a value with only the bottom 21-bits of a 64-bit
  *  value set (0x1FFFFF). The below macro functions just make use of previous
  *  macros to make calculating this value easier, which sticks to theory and
  *  avoids magic values that have not yet been explained.
  */

#define PAGE_1GB_SHIFT      30
#define PAGE_1GB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_1GB_SHIFT)) )

#define PAGE_2MB_SHIFT      21
#define PAGE_2MB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_2MB_SHIFT)) )

#define PAGE_4KB_SHIFT      12
#define PAGE_4KB_OFFSET(x)  ( x & (~(MAXUINT64 << PAGE_4KB_SHIFT)) )

#pragma warning(push)
#pragma warning(disable:4214) // warning C4214: nonstandard extension used: bit field types other than int

  /*
   * This is the format of a virtual address which would map a 4KB underlying
   *  chunk of physical memory
   */
typedef union _VIRTUAL_MEMORY_ADDRESS
{
	struct
	{
		UINT64 PageIndex : 12;  /* 0:11  */
		UINT64 PtIndex : 9;   /* 12:20 */
		UINT64 PdIndex : 9;   /* 21:29 */
		UINT64 PdptIndex : 9;   /* 30:38 */
		UINT64 Pml4Index : 9;   /* 39:47 */
		UINT64 Unused : 16;  /* 48:63 */
	} Bits;
	UINT64 All;
} VIRTUAL_ADDRESS, * PVIRTUAL_ADDRESS;

/*
 * [Intel Software Development Manual, Volume 3A: Table 4-12]
 *  "Use of CR3 with 4-Level Paging and 5-level Paging and CR4.PCIDE = 0"
 */
typedef union _DIRECTORY_TABLE_BASE
{
	struct
	{
		UINT64 Ignored0 : 3;    /* 2:0   */
		UINT64 PageWriteThrough : 1;    /* 3     */
		UINT64 PageCacheDisable : 1;    /* 4     */
		UINT64 _Ignored1 : 7;    /* 11:5  */
		UINT64 PhysicalAddress : 36;   /* 47:12 */
		UINT64 _Reserved0 : 16;   /* 63:48 */
	} Bits;
	UINT64 All;
} CR3, DIR_TABLE_BASE;

/*
 * [Intel Software Development Manual, Volume 3A: Table 4-15]
 *  "Format of a PML4 Entry (PML4E) that References a Page-Directory-Pointer Table"
 */
typedef union _PML4_ENTRY
{
	struct
	{
		UINT64 Present : 1;    /* 0     */
		UINT64 ReadWrite : 1;    /* 1     */
		UINT64 UserSupervisor : 1;    /* 2     */
		UINT64 PageWriteThrough : 1;    /* 3     */
		UINT64 PageCacheDisable : 1;    /* 4     */
		UINT64 Accessed : 1;    /* 5     */
		UINT64 _Ignored0 : 1;    /* 6     */
		UINT64 _Reserved0 : 1;    /* 7     */
		UINT64 _Ignored1 : 4;    /* 11:8  */
		UINT64 PhysicalAddress : 40;   /* 51:12 */
		UINT64 _Ignored2 : 11;   /* 62:52 */
		UINT64 ExecuteDisable : 1;    /* 63    */
	} Bits;
	UINT64 All;
} PML4E;

/*
 * [Intel Software Development Manual, Volume 3A: Table 4-16]
 *  "Table 4-16. Format of a Page-Directory-Pointer-Table Entry (PDPTE) that Maps a 1-GByte Page"
 */
typedef union _PDPT_ENTRY_LARGE
{
	struct
	{
		UINT64 Present : 1;    /* 0     */
		UINT64 ReadWrite : 1;    /* 1     */
		UINT64 UserSupervisor : 1;    /* 2     */
		UINT64 PageWriteThrough : 1;    /* 3     */
		UINT64 PageCacheDisable : 1;    /* 4     */
		UINT64 Accessed : 1;    /* 5     */
		UINT64 Dirty : 1;    /* 6     */
		UINT64 PageSize : 1;    /* 7     */
		UINT64 Global : 1;    /* 8     */
		UINT64 _Ignored0 : 3;    /* 11:9  */
		UINT64 PageAttributeTable : 1;    /* 12    */
		UINT64 _Reserved0 : 17;   /* 29:13 */
		UINT64 PhysicalAddress : 22;   /* 51:30 */
		UINT64 _Ignored1 : 7;    /* 58:52 */
		UINT64 ProtectionKey : 4;    /* 62:59 */
		UINT64 ExecuteDisable : 1;    /* 63    */
	} Bits;
	UINT64 All;
} PDPTE_LARGE;

/*
 * [Intel Software Development Manual, Volume 3A: Table 4-17]
 *  "Format of a Page-Directory-Pointer-Table Entry (PDPTE) that References a Page Directory"
 */
typedef union _PDPT_ENTRY
{
	struct
	{
		UINT64 Present : 1;    /* 0     */
		UINT64 ReadWrite : 1;    /* 1     */
		UINT64 UserSupervisor : 1;    /* 2     */
		UINT64 PageWriteThrough : 1;    /* 3     */
		UINT64 PageCacheDisable : 1;    /* 4     */
		UINT64 Accessed : 1;    /* 5     */
		UINT64 _Ignored0 : 1;    /* 6     */
		UINT64 PageSize : 1;    /* 7     */
		UINT64 _Ignored1 : 4;    /* 11:8  */
		UINT64 PhysicalAddress : 40;   /* 51:12 */
		UINT64 _Ignored2 : 11;   /* 62:52 */
		UINT64 ExecuteDisable : 1;    /* 63    */
	} Bits;
	UINT64 All;
} PDPTE;

/*
 * [Intel Software Development Manual, Volume 3A: Table 4-18]
 *  "Table 4-18. Format of a Page-Directory Entry that Maps a 2-MByte Page"
 */
typedef union _PD_ENTRY_LARGE
{
	struct
	{
		UINT64 Present : 1;    /* 0     */
		UINT64 ReadWrite : 1;    /* 1     */
		UINT64 UserSupervisor : 1;    /* 2     */
		UINT64 PageWriteThrough : 1;    /* 3     */
		UINT64 PageCacheDisable : 1;    /* 4     */
		UINT64 Accessed : 1;    /* 5     */
		UINT64 Dirty : 1;    /* 6     */
		UINT64 PageSize : 1;    /* 7     */
		UINT64 Global : 1;    /* 8     */
		UINT64 _Ignored0 : 3;    /* 11:9  */
		UINT64 PageAttributeTalbe : 1;    /* 12    */
		UINT64 _Reserved0 : 8;    /* 20:13 */
		UINT64 PhysicalAddress : 29;   /* 49:21 */
		UINT64 _Reserved1 : 2;    /* 51:50 */
		UINT64 _Ignored1 : 7;    /* 58:52 */
		UINT64 ProtectionKey : 4;    /* 62:59 */
		UINT64 ExecuteDisable : 1;    /* 63    */
	} Bits;
	UINT64 All;
} PDE_LARGE;

/*
 * [Intel Software Development Manual, Volume 3A: Table 4-19]
 *  "Format of a Page-Directory Entry that References a Page Table"
 */
typedef union _PD_ENTRY
{
	struct
	{
		UINT64 Present : 1;    /* 0     */
		UINT64 ReadWrite : 1;    /* 1     */
		UINT64 UserSupervisor : 1;    /* 2     */
		UINT64 PageWriteThrough : 1;    /* 3     */
		UINT64 PageCacheDisable : 1;    /* 4     */
		UINT64 Accessed : 1;    /* 5     */
		UINT64 _Ignored0 : 1;    /* 6     */
		UINT64 PageSize : 1;    /* 7     */
		UINT64 _Ignored1 : 4;    /* 11:8  */
		UINT64 PhysicalAddress : 38;   /* 49:12 */
		UINT64 _Reserved0 : 2;    /* 51:50 */
		UINT64 _Ignored2 : 11;   /* 62:52 */
		UINT64 ExecuteDisable : 1;    /* 63    */
	} Bits;
	UINT64 All;
} PDE;

/*
 * [Intel Software Development Manual, Volume 3A: Table 4-20]
 *  "Format of a Page-Table Entry that Maps a 4-KByte Page"
 */
typedef union _PT_ENTRY
{
	struct
	{
		UINT64 Present : 1;    /* 0     */
		UINT64 ReadWrite : 1;    /* 1     */
		UINT64 UserSupervisor : 1;    /* 2     */
		UINT64 PageWriteThrough : 1;    /* 3     */
		UINT64 PageCacheDisable : 1;    /* 4     */
		UINT64 Accessed : 1;    /* 5     */
		UINT64 Dirty : 1;    /* 6     */
		UINT64 PageAttributeTable : 1;    /* 7     */
		UINT64 Global : 1;    /* 8     */
		UINT64 _Ignored0 : 3;    /* 11:9  */
		UINT64 PhysicalAddress : 38;   /* 49:12 */
		UINT64 _Reserved0 : 2;    /* 51:50 */
		UINT64 _Ignored1 : 7;    /* 58:52 */
		UINT64 ProtectionKey : 4;    /* 62:59 */
		UINT64 ExecuteDisable : 1;    /* 63    */
	} Bits;
	UINT64 All;
} PTE;

/*
 * Above I'm making use of some paging structures I
 *  created while parsing out definitions within the SDM.
 *  The address bits in the above structures should be
 *  right. You can also use the previously-mentioned
 *  Windows-specific general page table structure definition,
 *  which I have taken out of KD and added a definition
 *  for below.
 *
 * 1: kd> dt ntkrnlmp!_MMPTE_HARDWARE
 *    +0x000 Valid            : Pos 0, 1 Bit
 *    +0x000 Dirty1           : Pos 1, 1 Bit
 *    +0x000 Owner            : Pos 2, 1 Bit
 *    +0x000 WriteThrough     : Pos 3, 1 Bit
 *    +0x000 CacheDisable     : Pos 4, 1 Bit
 *    +0x000 Accessed         : Pos 5, 1 Bit
 *    +0x000 Dirty            : Pos 6, 1 Bit
 *    +0x000 LargePage        : Pos 7, 1 Bit
 *    +0x000 Global           : Pos 8, 1 Bit
 *    +0x000 CopyOnWrite      : Pos 9, 1 Bit
 *    +0x000 Unused           : Pos 10, 1 Bit
 *    +0x000 Write            : Pos 11, 1 Bit
 *    +0x000 PageFrameNumber  : Pos 12, 36 Bits
 *    +0x000 ReservedForHardware : Pos 48, 4 Bits
 *    +0x000 ReservedForSoftware : Pos 52, 4 Bits
 *    +0x000 WsleAge          : Pos 56, 4 Bits
 *    +0x000 WsleProtection   : Pos 60, 3 Bits
 *    +0x000 NoExecute        : Pos 63, 1 Bit
 */
typedef union _MMPTE_HARDWARE
{
	struct
	{
		UINT64 Valid : 1;    /* 0     */
		UINT64 Dirty1 : 1;    /* 1     */
		UINT64 Owner : 1;    /* 2     */
		UINT64 WriteThrough : 1;    /* 3     */
		UINT64 CacheDisable : 1;    /* 4     */
		UINT64 Accessed : 1;    /* 5     */
		UINT64 Dirty : 1;    /* 6     */
		UINT64 LargePage : 1;    /* 7     */
		UINT64 Global : 1;    /* 8     */
		UINT64 CopyOnWrite : 1;    /* 9     */
		UINT64 Unused : 1;    /* 10    */
		UINT64 Write : 1;    /* 11    */
		UINT64 PageFrameNumber : 36;   /* 47:12 */
		UINT64 ReservedForHardware : 4;    /* 51:48 */
		UINT64 ReservedForSoftware : 4;    /* 55:52 */
		UINT64 WsleAge : 4;    /* 59:56 */
		UINT64 WsleProtection : 3;    /* 62:60 */
		UINT64 NoExecute : 1;    /* 63 */
	} Bits;
	UINT64 All;
} MMPTE_HARDWARE;

enum InjectedInputMouseOptions
{
	Absolute = 32768,
	HWheel = 4096,
	LeftDown = 2,
	LeftUp = 4,
	MiddleDown = 32,
	MiddleUp = 64,
	Move = 1,
	MoveNoCoalesce = 8192,
	None = 0,
	RightDown = 8,
	RightUp = 16,
	VirtualDesk = 16384,
	Wheel = 2048,
	XDown = 128,
	XUp = 256
};

struct InjectedInputMouseInfo
{
	int                       DeltaX;
	int                       DeltaY;
	unsigned int              MouseData;
	InjectedInputMouseOptions MouseOptions;
	unsigned int              TimeOffsetInMilliseconds;
	void* ExtraInfo;
};

///
/// Header options
///
//#define PRINT_DEBUG // Enable/disable(commented out) printf debugging into DebugView with this option.

typedef unsigned __int64 QWORD;

QWORD ResolveRelativeAddress(
	QWORD Instruction,
	DWORD OffsetOffset,
	DWORD InstructionSize
)
{

	QWORD Instr = ( QWORD ) Instruction;
	INT32 RipOffset = *( INT32* ) (Instr + OffsetOffset);
	QWORD ResolvedAddr = ( QWORD ) (Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

extern "C"
{

	NTKERNELAPI
		PVOID
		PsGetProcessSectionBaseAddress(
			PEPROCESS Process
		);

	NTSYSCALLAPI
		NTSTATUS NTAPI ExRaiseHardError(
			NTSTATUS ErrorStatus,
			ULONG NumberOfParameters,
			ULONG UnicodeStringParameterMask,
			PULONG_PTR Parameters,
			ULONG ValidResponseOptions,
			PULONG Response
		);

	NTSYSCALLAPI
		NTKERNELAPI
		PVOID
		NTAPI
		PsGetProcessWow64Process( _In_ PEPROCESS Process );

	NTSYSCALLAPI
		NTSTATUS NTAPI MmCopyVirtualMemory
		(
			PEPROCESS SourceProcess,
			PVOID SourceAddress,
			PEPROCESS TargetProcess,
			PVOID TargetAddress,
			SIZE_T BufferSize,
			KPROCESSOR_MODE PreviousMode,
			PSIZE_T ReturnSize
		);

	NTKERNELAPI PVOID NTAPI
		PsGetCurrentThreadWin32Thread(
			VOID
		);

	NTKERNELAPI
		PPEB
		NTAPI
		PsGetProcessPeb(
			IN PEPROCESS Process );

	NTSYSAPI
		NTSTATUS
		NTAPI
		ObReferenceObjectByName(
			_In_ PUNICODE_STRING ObjectName,
			_In_ ULONG Attributes,
			_In_opt_ PACCESS_STATE AccessState,
			_In_opt_ ACCESS_MASK DesiredAccess,
			_In_ POBJECT_TYPE ObjectType,
			_In_ KPROCESSOR_MODE AccessMode,
			_Inout_opt_ PVOID ParseContext,
			_Out_ PVOID* Object
		);

	ULONG
		NTAPI
		KeCapturePersistentThreadState(
			IN PCONTEXT Context,
			IN PKTHREAD Thread,
			IN ULONG BugCheckCode,
			IN ULONG BugCheckParameter1,
			IN ULONG BugCheckParameter2,
			IN ULONG BugCheckParameter3,
			IN ULONG BugCheckParameter4,
			OUT PVOID VirtualAddress
		);

}


typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag [ 4 ];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo [ ANYSIZE_ARRAY ];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;



///
/// Definitions
///
/// 

#ifdef PRINT_DEBUG
#define print(text, ...) DbgPrintEx(DPFLTR_IHVBUS_ID, 0, _("[dolby-kernel-device]: " text), ##__VA_ARGS__)
#else
#define print(text, ...) 
#endif

#define print_dbg(fmt, ...) qtx_import(DbgPrintEx)(0, 0, fmt, ##__VA_ARGS__) 

//#define print(fmt, ...) qtx_import(DbgPrintEx)(0, 0, fmt, ##__VA_ARGS__) 

#define PFN_TO_PAGE(pfn) ( pfn << 12 )
#define dereference(ptr) (const uintptr_t)(ptr + *( int * )( ( BYTE * )ptr + 3 ) + 7)
#define in_range(x,a,b)    (x >= a && x <= b) 
#define get_bits( x )    (in_range((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xA) : (in_range(x,'0','9') ? x - '0' : 0))
#define get_byte( x )    (get_bits(x[0]) << 4 | get_bits(x[1]))
#define size_align(Size) ((Size + 0xFFF) & 0xFFFFFFFFFFFFF000)
#define to_lower_i(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)
#define to_lower_c(Char) ((Char >= (char*)'A' && Char <= (char*)'Z') ? (Char + 32) : Char)

#define rva(addr, size)       ((uintptr_t)((uintptr_t)(addr) + *(PINT)((uintptr_t)(addr) + ((size) - sizeof(INT))) + (size)))


//
// Protection Bits part of the internal memory manager Protection Mask, from:
// http://reactos.org/wiki/Techwiki:Memory_management_in_the_Windows_XP_kernel
// https://www.reactos.org/wiki/Techwiki:Memory_Protection_constants
// and public assertions.
//
#define MM_ZERO_ACCESS         0
#define MM_READONLY            1
#define MM_EXECUTE             2
#define MM_EXECUTE_READ        3
#define MM_READWRITE           4
#define MM_WRITECOPY           5
#define MM_EXECUTE_READWRITE   6
#define MM_EXECUTE_WRITECOPY   7
#define MM_PROTECT_ACCESS      7




///
/// Structures
///
typedef union _KWAIT_STATUS_REGISTER
{
	union
	{
		/* 0x0000 */ unsigned char Flags;
		struct /* bitfield */
		{
			/* 0x0000 */ unsigned char State : 3; /* bit position: 0 */
			/* 0x0000 */ unsigned char Affinity : 1; /* bit position: 3 */
			/* 0x0000 */ unsigned char Priority : 1; /* bit position: 4 */
			/* 0x0000 */ unsigned char Apc : 1; /* bit position: 5 */
			/* 0x0000 */ unsigned char UserApc : 1; /* bit position: 6 */
			/* 0x0000 */ unsigned char Alert : 1; /* bit position: 7 */
		}; /* bitfield */
	}; /* size: 0x0001 */
} KWAIT_STATUS_REGISTER, * PKWAIT_STATUS_REGISTER; /* size: 0x0001 */

typedef struct _KTHREAD_META
{
	/* 0x0000 */ struct _DISPATCHER_HEADER Header;
	/* 0x0018 */ void* SListFaultAddress;
	/* 0x0020 */ unsigned __int64 QuantumTarget;
	/* 0x0028 */ void* InitialStack;
	/* 0x0030 */ void* volatile StackLimit;
	/* 0x0038 */ void* StackBase;
	/* 0x0040 */ unsigned __int64 ThreadLock;
	/* 0x0048 */ volatile unsigned __int64 CycleTime;
	/* 0x0050 */ unsigned long CurrentRunTime;
	/* 0x0054 */ unsigned long ExpectedRunTime;
	/* 0x0058 */ void* KernelStack;
	/* 0x0060 */ struct _XSAVE_FORMAT* StateSaveArea;
	/* 0x0068 */ struct _KSCHEDULING_GROUP* volatile SchedulingGroup;
	/* 0x0070 */ union _KWAIT_STATUS_REGISTER WaitRegister;
	/* 0x0071 */ volatile unsigned char Running;
	/* 0x0072 */ unsigned char Alerted [ 2 ];
	union
	{
		struct /* bitfield */
		{
			/* 0x0074 */ unsigned long AutoBoostActive : 1; /* bit position: 0 */
			/* 0x0074 */ unsigned long ReadyTransition : 1; /* bit position: 1 */
			/* 0x0074 */ unsigned long WaitNext : 1; /* bit position: 2 */
			/* 0x0074 */ unsigned long SystemAffinityActive : 1; /* bit position: 3 */
			/* 0x0074 */ unsigned long Alertable : 1; /* bit position: 4 */
			/* 0x0074 */ unsigned long UserStackWalkActive : 1; /* bit position: 5 */
			/* 0x0074 */ unsigned long ApcInterruptRequest : 1; /* bit position: 6 */
			/* 0x0074 */ unsigned long QuantumEndMigrate : 1; /* bit position: 7 */
			/* 0x0074 */ unsigned long UmsDirectedSwitchEnable : 1; /* bit position: 8 */
			/* 0x0074 */ unsigned long TimerActive : 1; /* bit position: 9 */
			/* 0x0074 */ unsigned long SystemThread : 1; /* bit position: 10 */
			/* 0x0074 */ unsigned long ProcessDetachActive : 1; /* bit position: 11 */
			/* 0x0074 */ unsigned long CalloutActive : 1; /* bit position: 12 */
			/* 0x0074 */ unsigned long ScbReadyQueue : 1; /* bit position: 13 */
			/* 0x0074 */ unsigned long ApcQueueable : 1; /* bit position: 14 */
			/* 0x0074 */ unsigned long ReservedStackInUse : 1; /* bit position: 15 */
			/* 0x0074 */ unsigned long UmsPerformingSyscall : 1; /* bit position: 16 */
			/* 0x0074 */ unsigned long TimerSuspended : 1; /* bit position: 17 */
			/* 0x0074 */ unsigned long SuspendedWaitMode : 1; /* bit position: 18 */
			/* 0x0074 */ unsigned long SuspendSchedulerApcWait : 1; /* bit position: 19 */
			/* 0x0074 */ unsigned long CetUserShadowStack : 1; /* bit position: 20 */
			/* 0x0074 */ unsigned long BypassProcessFreeze : 1; /* bit position: 21 */
			/* 0x0074 */ unsigned long CetKernelShadowStack : 1; /* bit position: 22 */
			/* 0x0074 */ unsigned long Reserved : 9; /* bit position: 23 */
		}; /* bitfield */
		/* 0x0074 */ long MiscFlags;
	}; /* size: 0x0004 */
} KTHREAD_META, * PKTHREAD_META; /* size: 0x0430 */

//0x438 bytes (sizeof)
struct _KPROCESS
{
	struct _DISPATCHER_HEADER Header;                                       //0x0
	struct _LIST_ENTRY ProfileListHead;                                     //0x18
	ULONGLONG DirectoryTableBase;                                           //0x28
	struct _LIST_ENTRY ThreadListHead;                                      //0x30
	ULONG ProcessLock;                                                      //0x40
	ULONG ProcessTimerDelay;                                                //0x44
	ULONGLONG DeepFreezeStartTime;                                          //0x48
	//struct _KAFFINITY_EX Affinity;                                          //0x50
	ULONGLONG AffinityPadding [ 12 ];                                          //0xf8
	struct _LIST_ENTRY ReadyListHead;                                       //0x158
	struct _SINGLE_LIST_ENTRY SwapListEntry;                                //0x168
	// volatile struct _KAFFINITY_EX ActiveProcessors;                         //0x170
	ULONGLONG ActiveProcessorsPadding [ 12 ];                                  //0x218
	union
	{
		struct
		{
			ULONG AutoAlignment : 1;                                          //0x278
			ULONG DisableBoost : 1;                                           //0x278
			ULONG DisableQuantum : 1;                                         //0x278
			ULONG DeepFreeze : 1;                                             //0x278
			ULONG TimerVirtualization : 1;                                    //0x278
			ULONG CheckStackExtents : 1;                                      //0x278
			ULONG CacheIsolationEnabled : 1;                                  //0x278
			ULONG PpmPolicy : 3;                                              //0x278
			ULONG VaSpaceDeleted : 1;                                         //0x278
			ULONG ReservedFlags : 21;                                         //0x278
		};
		volatile LONG ProcessFlags;                                         //0x278
	};
	ULONG ActiveGroupsMask;                                                 //0x27c
	CHAR BasePriority;                                                      //0x280
	CHAR QuantumReset;                                                      //0x281
	CHAR Visited;                                                           //0x282
	//  union _KEXECUTE_OPTIONS Flags;                                          //0x283
	USHORT ThreadSeed [ 20 ];                                                  //0x284
	USHORT ThreadSeedPadding [ 12 ];                                           //0x2ac
	USHORT IdealProcessor [ 20 ];                                              //0x2c4
	USHORT IdealProcessorPadding [ 12 ];                                       //0x2ec
	USHORT IdealNode [ 20 ];                                                   //0x304
	USHORT IdealNodePadding [ 12 ];                                            //0x32c
	USHORT IdealGlobalNode;                                                 //0x344
	USHORT Spare1;                                                          //0x346
	// unionvolatile _KSTACK_COUNT StackCount;                                 //0x348
	struct _LIST_ENTRY ProcessListEntry;                                    //0x350
	ULONGLONG CycleTime;                                                    //0x360
	ULONGLONG ContextSwitches;                                              //0x368
	struct _KSCHEDULING_GROUP* SchedulingGroup;                             //0x370
	ULONG FreezeCount;                                                      //0x378
	ULONG KernelTime;                                                       //0x37c
	ULONG UserTime;                                                         //0x380
	ULONG ReadyTime;                                                        //0x384
	ULONGLONG UserDirectoryTableBase;                                       //0x388
	UCHAR AddressPolicy;                                                    //0x390
	UCHAR Spare2 [ 71 ];                                                       //0x391
	VOID* InstrumentationCallback;                                          //0x3d8
	union
	{
		ULONGLONG SecureHandle;                                             //0x3e0
		struct
		{
			ULONGLONG SecureProcess : 1;                                      //0x3e0
			ULONGLONG Unused : 1;                                             //0x3e0
		} Flags;                                                            //0x3e0
	} SecureState;                                                          //0x3e0
	ULONGLONG KernelWaitTime;                                               //0x3e8
	ULONGLONG UserWaitTime;                                                 //0x3f0
	ULONGLONG EndPadding [ 8 ];                                                //0x3f8
};

//0x430 bytes (sizeof)
struct _KTHREAD
{
	struct _DISPATCHER_HEADER Header;                                       //0x0
	VOID* SListFaultAddress;                                                //0x18
	ULONGLONG QuantumTarget;                                                //0x20
	VOID* InitialStack;                                                     //0x28
	VOID* volatile StackLimit;                                              //0x30
	VOID* StackBase;                                                        //0x38
	ULONGLONG ThreadLock;                                                   //0x40
	volatile ULONGLONG CycleTime;                                           //0x48
	ULONG CurrentRunTime;                                                   //0x50
	ULONG ExpectedRunTime;                                                  //0x54
	VOID* KernelStack;                                                      //0x58
	struct _XSAVE_FORMAT* StateSaveArea;                                    //0x60
	struct _KSCHEDULING_GROUP* volatile SchedulingGroup;                    //0x68
	union _KWAIT_STATUS_REGISTER WaitRegister;                              //0x70
	volatile UCHAR Running;                                                 //0x71
	UCHAR Alerted [ 2 ];                                                       //0x72
	union
	{
		struct
		{
			ULONG AutoBoostActive : 1;                                        //0x74
			ULONG ReadyTransition : 1;                                        //0x74
			ULONG WaitNext : 1;                                               //0x74
			ULONG SystemAffinityActive : 1;                                   //0x74
			ULONG Alertable : 1;                                              //0x74
			ULONG UserStackWalkActive : 1;                                    //0x74
			ULONG ApcInterruptRequest : 1;                                    //0x74
			ULONG QuantumEndMigrate : 1;                                      //0x74
			ULONG UmsDirectedSwitchEnable : 1;                                //0x74
			ULONG TimerActive : 1;                                            //0x74
			ULONG SystemThread : 1;                                           //0x74
			ULONG ProcessDetachActive : 1;                                    //0x74
			ULONG CalloutActive : 1;                                          //0x74
			ULONG ScbReadyQueue : 1;                                          //0x74
			ULONG ApcQueueable : 1;                                           //0x74
			ULONG ReservedStackInUse : 1;                                     //0x74
			ULONG UmsPerformingSyscall : 1;                                   //0x74
			ULONG TimerSuspended : 1;                                         //0x74
			ULONG SuspendedWaitMode : 1;                                      //0x74
			ULONG SuspendSchedulerApcWait : 1;                                //0x74
			ULONG CetUserShadowStack : 1;                                     //0x74
			ULONG BypassProcessFreeze : 1;                                    //0x74
			ULONG Reserved : 10;                                              //0x74
		};
		LONG MiscFlags;                                                     //0x74
	};
	union
	{
		struct
		{
			ULONG ThreadFlagsSpare : 2;                                       //0x78
			ULONG AutoAlignment : 1;                                          //0x78
			ULONG DisableBoost : 1;                                           //0x78
			ULONG AlertedByThreadId : 1;                                      //0x78
			ULONG QuantumDonation : 1;                                        //0x78
			ULONG EnableStackSwap : 1;                                        //0x78
			ULONG GuiThread : 1;                                              //0x78
			ULONG DisableQuantum : 1;                                         //0x78
			ULONG ChargeOnlySchedulingGroup : 1;                              //0x78
			ULONG DeferPreemption : 1;                                        //0x78
			ULONG QueueDeferPreemption : 1;                                   //0x78
			ULONG ForceDeferSchedule : 1;                                     //0x78
			ULONG SharedReadyQueueAffinity : 1;                               //0x78
			ULONG FreezeCount : 1;                                            //0x78
			ULONG TerminationApcRequest : 1;                                  //0x78
			ULONG AutoBoostEntriesExhausted : 1;                              //0x78
			ULONG KernelStackResident : 1;                                    //0x78
			ULONG TerminateRequestReason : 2;                                 //0x78
			ULONG ProcessStackCountDecremented : 1;                           //0x78
			ULONG RestrictedGuiThread : 1;                                    //0x78
			ULONG VpBackingThread : 1;                                        //0x78
			ULONG ThreadFlagsSpare2 : 1;                                      //0x78
			ULONG EtwStackTraceApcInserted : 8;                               //0x78
		};
		volatile LONG ThreadFlags;                                          //0x78
	};
	volatile UCHAR Tag;                                                     //0x7c
	UCHAR SystemHeteroCpuPolicy;                                            //0x7d
	UCHAR UserHeteroCpuPolicy : 7;                                            //0x7e
	UCHAR ExplicitSystemHeteroCpuPolicy : 1;                                  //0x7e
	union
	{
		struct
		{
			UCHAR RunningNonRetpolineCode : 1;                                //0x7f
			UCHAR SpecCtrlSpare : 7;                                          //0x7f
		};
		UCHAR SpecCtrl;                                                     //0x7f
	};
	ULONG SystemCallNumber;                                                 //0x80
	ULONG ReadyTime;                                                        //0x84
	VOID* FirstArgument;                                                    //0x88
	struct _KTRAP_FRAME* TrapFrame;                                         //0x90
	union
	{
		struct _KAPC_STATE ApcState;                                        //0x98
		struct
		{
			UCHAR ApcStateFill [ 43 ];                                         //0x98
			CHAR Priority;                                                  //0xc3
			ULONG UserIdealProcessor;                                       //0xc4
		};
	};
	volatile LONGLONG WaitStatus;                                           //0xc8
	struct _KWAIT_BLOCK* WaitBlockList;                                     //0xd0
	union
	{
		struct _LIST_ENTRY WaitListEntry;                                   //0xd8
		struct _SINGLE_LIST_ENTRY SwapListEntry;                            //0xd8
	};
	struct _DISPATCHER_HEADER* volatile Queue;                              //0xe8
	VOID* Teb;                                                              //0xf0
	ULONGLONG RelativeTimerBias;                                            //0xf8
	struct _KTIMER Timer;                                                   //0x100
	union
	{
		struct _KWAIT_BLOCK WaitBlock [ 4 ];                                   //0x140
		struct
		{
			UCHAR WaitBlockFill4 [ 20 ];                                       //0x140
			ULONG ContextSwitches;                                          //0x154
		};
		struct
		{
			UCHAR WaitBlockFill5 [ 68 ];                                       //0x140
			volatile UCHAR State;                                           //0x184
			CHAR Spare13;                                                   //0x185
			UCHAR WaitIrql;                                                 //0x186
			CHAR WaitMode;                                                  //0x187
		};
		struct
		{
			UCHAR WaitBlockFill6 [ 116 ];                                      //0x140
			ULONG WaitTime;                                                 //0x1b4
		};
		struct
		{
			UCHAR WaitBlockFill7 [ 164 ];                                      //0x140
			union
			{
				struct
				{
					SHORT KernelApcDisable;                                 //0x1e4
					SHORT SpecialApcDisable;                                //0x1e6
				};
				ULONG CombinedApcDisable;                                   //0x1e4
			};
		};
		struct
		{
			UCHAR WaitBlockFill8 [ 40 ];                                       //0x140
			struct _KTHREAD_COUNTERS* ThreadCounters;                       //0x168
		};
		struct
		{
			UCHAR WaitBlockFill9 [ 88 ];                                       //0x140
			struct _XSTATE_SAVE* XStateSave;                                //0x198
		};
		struct
		{
			UCHAR WaitBlockFill10 [ 136 ];                                     //0x140
			VOID* volatile Win32Thread;                                     //0x1c8
		};
		struct
		{
			UCHAR WaitBlockFill11 [ 176 ];                                     //0x140
			struct _UMS_CONTROL_BLOCK* Ucb;                                 //0x1f0
			struct _KUMS_CONTEXT_HEADER* volatile Uch;                      //0x1f8
		};
	};
	union
	{
		volatile LONG ThreadFlags2;                                         //0x200
		struct
		{
			ULONG BamQosLevel : 8;                                            //0x200
			ULONG ThreadFlags2Reserved : 24;                                  //0x200
		};
	};
	ULONG Spare21;                                                          //0x204
	struct _LIST_ENTRY QueueListEntry;                                      //0x208
	union
	{
		volatile ULONG NextProcessor;                                       //0x218
		struct
		{
			ULONG NextProcessorNumber : 31;                                   //0x218
			ULONG SharedReadyQueue : 1;                                       //0x218
		};
	};
	LONG QueuePriority;                                                     //0x21c
	struct _KPROCESS* Process;                                              //0x220
	union
	{
		struct _GROUP_AFFINITY UserAffinity;                                //0x228
		struct
		{
			UCHAR UserAffinityFill [ 10 ];                                     //0x228
			CHAR PreviousMode;                                              //0x232
			CHAR BasePriority;                                              //0x233
			union
			{
				CHAR PriorityDecrement;                                     //0x234
				struct
				{
					UCHAR ForegroundBoost : 4;                                //0x234
					UCHAR UnusualBoost : 4;                                   //0x234
				};
			};
			UCHAR Preempted;                                                //0x235
			UCHAR AdjustReason;                                             //0x236
			CHAR AdjustIncrement;                                           //0x237
		};
	};
	ULONGLONG AffinityVersion;                                              //0x238
	union
	{
		struct _GROUP_AFFINITY Affinity;                                    //0x240
		struct
		{
			UCHAR AffinityFill [ 10 ];                                         //0x240
			UCHAR ApcStateIndex;                                            //0x24a
			UCHAR WaitBlockCount;                                           //0x24b
			ULONG IdealProcessor;                                           //0x24c
		};
	};
	ULONGLONG NpxState;                                                     //0x250
	union
	{
		struct _KAPC_STATE SavedApcState;                                   //0x258
		struct
		{
			UCHAR SavedApcStateFill [ 43 ];                                    //0x258
			UCHAR WaitReason;                                               //0x283
			CHAR SuspendCount;                                              //0x284
			CHAR Saturation;                                                //0x285
			USHORT SListFaultCount;                                         //0x286
		};
	};
	union
	{
		struct _KAPC SchedulerApc;                                          //0x288
		struct
		{
			UCHAR SchedulerApcFill0 [ 1 ];                                     //0x288
			UCHAR ResourceIndex;                                            //0x289
		};
		struct
		{
			UCHAR SchedulerApcFill1 [ 3 ];                                     //0x288
			UCHAR QuantumReset;                                             //0x28b
		};
		struct
		{
			UCHAR SchedulerApcFill2 [ 4 ];                                     //0x288
			ULONG KernelTime;                                               //0x28c
		};
		struct
		{
			UCHAR SchedulerApcFill3 [ 64 ];                                    //0x288
			struct _KPRCB* volatile WaitPrcb;                               //0x2c8
		};
		struct
		{
			UCHAR SchedulerApcFill4 [ 72 ];                                    //0x288
			VOID* LegoData;                                                 //0x2d0
		};
		struct
		{
			UCHAR SchedulerApcFill5 [ 83 ];                                    //0x288
			UCHAR CallbackNestingLevel;                                     //0x2db
			ULONG UserTime;                                                 //0x2dc
		};
	};
	struct _KEVENT SuspendEvent;                                            //0x2e0
	struct _LIST_ENTRY ThreadListEntry;                                     //0x2f8
	struct _LIST_ENTRY MutantListHead;                                      //0x308
	UCHAR AbEntrySummary;                                                   //0x318
	UCHAR AbWaitEntryCount;                                                 //0x319
	UCHAR AbAllocationRegionCount;                                          //0x31a
	CHAR SystemPriority;                                                    //0x31b
	ULONG SecureThreadCookie;                                               //0x31c
	struct _KLOCK_ENTRY* LockEntries;                                       //0x320
	struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;                         //0x328
	struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;                            //0x330
	UCHAR PriorityFloorCounts [ 16 ];                                          //0x338
	UCHAR PriorityFloorCountsReserved [ 16 ];                                  //0x348
	ULONG PriorityFloorSummary;                                             //0x358
	volatile LONG AbCompletedIoBoostCount;                                  //0x35c
	volatile LONG AbCompletedIoQoSBoostCount;                               //0x360
	volatile SHORT KeReferenceCount;                                        //0x364
	UCHAR AbOrphanedEntrySummary;                                           //0x366
	UCHAR AbOwnedEntryCount;                                                //0x367
	ULONG ForegroundLossTime;                                               //0x368
	union
	{
		struct _LIST_ENTRY GlobalForegroundListEntry;                       //0x370
		struct
		{
			struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;          //0x370
			ULONGLONG InGlobalForegroundList;                               //0x378
		};
	};
	LONGLONG ReadOperationCount;                                            //0x380
	LONGLONG WriteOperationCount;                                           //0x388
	LONGLONG OtherOperationCount;                                           //0x390
	LONGLONG ReadTransferCount;                                             //0x398
	LONGLONG WriteTransferCount;                                            //0x3a0
	LONGLONG OtherTransferCount;                                            //0x3a8
	struct _KSCB* QueuedScb;                                                //0x3b0
	volatile ULONG ThreadTimerDelay;                                        //0x3b8
	union
	{
		volatile LONG ThreadFlags3;                                         //0x3bc
		struct
		{
			ULONG ThreadFlags3Reserved : 8;                                   //0x3bc
			ULONG PpmPolicy : 2;                                              //0x3bc
			ULONG ThreadFlags3Reserved2 : 22;                                 //0x3bc
		};
	};
	ULONGLONG TracingPrivate [ 1 ];                                            //0x3c0
	VOID* SchedulerAssist;                                                  //0x3c8
	VOID* volatile AbWaitObject;                                            //0x3d0
	ULONG ReservedPreviousReadyTimeValue;                                   //0x3d8
	ULONGLONG KernelWaitTime;                                               //0x3e0
	ULONGLONG UserWaitTime;                                                 //0x3e8
	union
	{
		struct _LIST_ENTRY GlobalUpdateVpThreadPriorityListEntry;           //0x3f0
		struct
		{
			struct _SINGLE_LIST_ENTRY UpdateVpThreadPriorityDpcStackListEntry; //0x3f0
			ULONGLONG InGlobalUpdateVpThreadPriorityList;                   //0x3f8
		};
	};
	LONG SchedulerAssistPriorityFloor;                                      //0x400
	ULONG Spare28;                                                          //0x404
	ULONGLONG EndPadding [ 5 ];                                                //0x408
};

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_CRITICAL_SECTION
{
	VOID* DebugInfo;
	LONG LockCount;
	LONG RecursionCount;
	PVOID OwningThread;
	PVOID LockSemaphore;
	ULONG SpinCount;
} RTL_CRITICAL_SECTION, * PRTL_CRITICAL_SECTION;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG ImageUsesLargePages : 1;
	ULONG IsProtectedProcess : 1;
	ULONG IsLegacyProcess : 1;
	ULONG IsImageDynamicallyRelocated : 1;
	ULONG SpareBits : 4;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	VOID* ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PRTL_CRITICAL_SECTION FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	ULONG CrossProcessFlags;
	ULONG ProcessInJob : 1;
	ULONG ProcessInitializing : 1;
	ULONG ReservedBits0 : 30;
	union
	{
		PVOID KernelCallbackTable;
		PVOID UserSharedInfoPtr;
	};
	ULONG SystemReserved [ 1 ];
	ULONG SpareUlong;
	VOID* FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits [ 2 ];
	PVOID ReadOnlySharedMemoryBase;
	PVOID HotpatchInformation;
	VOID** ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	VOID** ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	PRTL_CRITICAL_SECTION LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	WORD OSBuildNumber;
	WORD OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG ImageProcessAffinityMask;
	ULONG GdiHandleBuffer [ 34 ];
	PVOID PostProcessInitRoutine;
	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits [ 32 ];
	ULONG SessionId;
	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;
	UNICODE_STRING CSDVersion;
	VOID* ActivationContextData;
	VOID* ProcessAssemblyStorageMap;
	VOID* SystemDefaultActivationContextData;
	VOID* SystemAssemblyStorageMap;
	ULONG MinimumStackCommit;
	VOID* FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits [ 4 ];
	ULONG FlsHighIndex;
	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;
} PEB, * PPEB;

typedef struct _MDL_INFORMATION
{
	MDL* mdl;
	uintptr_t va;
}MDL_INFORMATION, * PMDL_INFORMATION;


struct _EX_PUSH_LOCK
{
	union
	{
		struct
		{
			ULONG Locked : 1;                                                 //0x0
			ULONG Waiting : 1;                                                //0x0
			ULONG Waking : 1;                                                 //0x0
			ULONG MultipleShared : 1;                                         //0x0
			ULONG Shared : 28;                                                //0x0
		};
		ULONG Value;                                                        //0x0
		VOID* Ptr;                                                          //0x0
	};
};

typedef struct _MMVAD_FLAGS
{
	ULONG Lock : 1;
	ULONG LockContended : 1;
	ULONG DeleteInProgress : 1;
	ULONG NoChange : 1;
	ULONG VadType : 3;
	ULONG Protection : 5;
	ULONG PreferredNode : 6;
	ULONG PageSize : 2;
	ULONG PrivateMemory : 1;
} MMVAD_FLAGS, * PMMVAD_FLAGS;

struct _MMVAD_FLAGS1
{
	unsigned long CommitCharge : 31;
	unsigned long MemCommit : 1;
};

struct _MMVAD_FLAGS2
{
	unsigned long FileOffset : 24;
	unsigned long Large : 1;
	unsigned long TrimBehind : 1;
	unsigned long Inherit : 1;
	unsigned long CopyOnWrite : 1;
	unsigned long NoValidationNeeded : 1;
	unsigned long Spare : 3;
};

union ___unnamed1952 // Size=4
{
	unsigned long LongFlags1; // Size=4 Offset=0
	struct _MMVAD_FLAGS1 VadFlags1; // Size=4 Offset=0
};
union ___unnamed1951 // Size=4
{
	unsigned long LongFlags; // Size=4 Offset=0
	struct _MMVAD_FLAGS VadFlags; // Size=4 Offset=0
};
typedef struct _MMVAD_SHORT
{
	union
	{
		struct
		{
			struct _MMVAD_SHORT* NextVad;
			VOID* ExtraCreateInfo;
		};
		struct _RTL_BALANCED_NODE VadNode;
	};
	ULONG StartingVpn;
	ULONG EndingVpn;
	UCHAR StartingVpnHigh;
	UCHAR EndingVpnHigh;
	UCHAR CommitChargeHigh;
	UCHAR SpareNT64VadUChar;
	LONG ReferenceCount;
	_EX_PUSH_LOCK PushLock;
	union ___unnamed1951 u;
	union ___unnamed1952 u1;
	struct _MI_VAD_EVENT_BLOCK* EventList;
} MMVAD_SHORT, * PMMVAD_SHORT;

typedef struct _MM_AVL_NODE // Size=24
{
	struct _MM_AVL_NODE* LeftChild; // Size=8 Offset=0
	struct _MM_AVL_NODE* RightChild; // Size=8 Offset=8

	union ___unnamed1666 // Size=8
	{
		struct
		{
			__int64 Balance : 2; // Size=8 Offset=0 BitOffset=0 BitCount=2
		};
		struct _MM_AVL_NODE* Parent; // Size=8 Offset=0
	} u1;
} MM_AVL_NODE, * PMM_AVL_NODE, * PMMADDRESS_NODE;

typedef struct _RTL_AVL_TREE // Size=8
{
	PMM_AVL_NODE BalancedRoot;
	void* NodeHint;
	unsigned __int64 NumberGenericTableElements;
} RTL_AVL_TREE, * PRTL_AVL_TREE, MM_AVL_TABLE, * PMM_AVL_TABLE;