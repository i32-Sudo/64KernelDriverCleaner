#pragma once

// Inclusions
#include <ntifs.h>
#include <ntstrsafe.h>
#include <windef.h>

/* Definitions */
extern "C" __declspec( dllimport ) POBJECT_TYPE IoDriverObjectType;		// IoDriverObjectType

// ObCreateObject
extern "C" NTSTATUS NTAPI ObCreateObject( IN KPROCESSOR_MODE ProbeMode 	OPTIONAL,
	IN POBJECT_TYPE 	Type,
	IN POBJECT_ATTRIBUTES ObjectAttributes 	OPTIONAL,
	IN KPROCESSOR_MODE 	AccessMode,
	IN OUT PVOID ParseContext 	OPTIONAL,
	IN ULONG 	ObjectSize,
	IN ULONG PagedPoolCharge 	OPTIONAL,
	IN ULONG NonPagedPoolCharge 	OPTIONAL,
	OUT PVOID* Object
);

extern "C" typedef struct _IO_CLIENT_EXTENSION
{
	struct _IO_CLIENT_EXTENSION* NextExtension;
	PVOID ClientIdentificationAddress;
} IO_CLIENT_EXTENSION, * PIO_CLIENT_EXTENSION;

extern "C" typedef struct _EXTENDED_DRIVER_EXTENSION
{
	struct _DRIVER_OBJECT* DriverObject;
	PDRIVER_ADD_DEVICE AddDevice;
	ULONG Count;
	UNICODE_STRING ServiceKeyName;
	PIO_CLIENT_EXTENSION ClientDriverExtension;
	PFS_FILTER_CALLBACKS FsFilterCallbacks;
} EXTENDED_DRIVER_EXTENSION, * PEXTENDED_DRIVER_EXTENSION;