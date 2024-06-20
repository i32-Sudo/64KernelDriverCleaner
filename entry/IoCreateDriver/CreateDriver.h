/*
	***************************************************
	*  Author: Th3Spl                                 *
	*  Lang: C++ | Usable in C as well                *
	*  Date: 27/12/2023                               *
	*  Purpose: IoCreateDriver Implementation         *
	***************************************************
*/

#pragma once

//
// Inclusions
//
#include <ntifs.h>
#include <ntstrsafe.h>
#include <windef.h>
#include "definitions.h"


//
// Dummy function used as default function for the IRP_MJ functions
//
extern "C" NTSTATUS NTAPI IopInvalidDeviceRequest( _In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp )
{
	UNREFERENCED_PARAMETER( DeviceObject );
	Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return STATUS_INVALID_DEVICE_REQUEST;
}


//
// Custom IoCreateDriver in order to bypass PsLoadedModule and EtwTiLogDriverObjectLoad 
// it makes easier tohe usage of IOCTL if you're using KdMapper
// 
extern "C" NTSTATUS __fastcall IoCreateDriver( _In_ NTSTATUS( __fastcall* EntryPoint )( _In_ PDRIVER_OBJECT, _In_ PUNICODE_STRING ) )
{
	//
	// Variables
	//
	HANDLE drv_handle;
	USHORT name_length;
	WCHAR name_buffer[100];
	PDRIVER_OBJECT drv_obj;
	OBJECT_ATTRIBUTES obj_attribs;
	UNICODE_STRING local_drv_name;
	UNICODE_STRING service_key_name;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG obj_size = sizeof( DRIVER_OBJECT ) + sizeof( EXTENDED_DRIVER_EXTENSION );


	//
	// We meed to create a UNICODE_STRING which contains the (randomic) name of the driver (we're not interested in that)
	//
	name_length = ( USHORT )swprintf( name_buffer, L"\\Driver\\%08u", ( ULONG )KeQueryUnbiasedInterruptTime() );
	local_drv_name.Length = name_length * sizeof( WCHAR );
	local_drv_name.MaximumLength = local_drv_name.Length + sizeof( UNICODE_NULL );
	local_drv_name.Buffer = name_buffer;


	//
	// Initializing the object attributes [PERMANENT, CASE_SENSITIVE, KERNEL_HANLE]
	//
	InitializeObjectAttributes( &obj_attribs, &local_drv_name, OBJ_PERMANENT | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL );


	//
	// Creating the driver object itself [ObCreateObject exported by ntoskrnl.exe]
	//
	status = ObCreateObject( KernelMode, IoDriverObjectType, &obj_attribs, KernelMode, NULL, obj_size, 0, 0, ( PVOID* )&drv_obj );
	if( !NT_SUCCESS( status ) )
		return status;


	//
	// Setting up the driver object
	// 
	RtlZeroMemory( drv_obj, obj_size );				// Cleaning up
	drv_obj->Type = IO_TYPE_DRIVER;				// Specifying the driver type
	drv_obj->Size = sizeof( DRIVER_OBJECT );			// Setting its size
	drv_obj->Flags = DRVO_BUILTIN_DRIVER;				// Setting it as a BUILTIN_DRIVER					
	drv_obj->DriverExtension = ( PDRIVER_EXTENSION )( drv_obj + 1 );	// Setting up the driver extension
	drv_obj->DriverExtension->DriverObject = drv_obj;		// Assigning the driver 
	drv_obj->DriverInit = EntryPoint;				// Setting the driver entry point


	//
	// We need to set the IRPP_MJ functions to IopInvalidDeviceRequest
	//
	for( int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++ )
	{
		drv_obj->MajorFunction[i] = IopInvalidDeviceRequest;
	}


	//
	// Setting up the service key for the driver
	//
	service_key_name.MaximumLength = local_drv_name.Length + sizeof( UNICODE_NULL );
	service_key_name.Buffer = ( PWCH )ExAllocatePool2( POOL_FLAG_PAGED, local_drv_name.MaximumLength, ( ULONG )KeQueryUnbiasedInterruptTime() );
	if( !service_key_name.Buffer )
	{
		ObMakeTemporaryObject( drv_obj );
		ObfDereferenceObject( drv_obj );
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlCopyUnicodeString( &service_key_name, &local_drv_name );
	service_key_name.Buffer[service_key_name.Length / sizeof( WCHAR )] = UNICODE_NULL;
	drv_obj->DriverExtension->ServiceKeyName = service_key_name;


	//
	// Saving the driver name within the driver object
	//
	drv_obj->DriverName.MaximumLength = local_drv_name.Length;
	drv_obj->DriverName.Buffer = ( PWCH )ExAllocatePool2( POOL_FLAG_PAGED, drv_obj->DriverName.MaximumLength, ( ULONG )KeQueryUnbiasedInterruptTime() );
	if( !drv_obj->DriverName.Buffer )
	{
		ObMakeTemporaryObject( drv_obj );
		ObfDereferenceObject( drv_obj );
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlCopyUnicodeString( &drv_obj->DriverName, &local_drv_name );


	//
	// Creating the kernel object (DRIVER_OBJECT) so we can get its handle
	// 
	status = ObInsertObject( drv_obj, NULL, FILE_READ_DATA, 0, NULL, &drv_handle );
	ZwClose( drv_handle );
	if( !NT_SUCCESS( status ) )
	{
		ObMakeTemporaryObject( drv_obj );
		ObfDereferenceObject( drv_obj );
		return status;
	}


	//
	// Actually starting the driver's entry point (passing the driver object)
	// 
	status = EntryPoint( drv_obj, NULL );
	if( !NT_SUCCESS( status ) )
	{
		ObMakeTemporaryObject( drv_obj );
		ObDereferenceObject( drv_obj );
		return status;
	}


	//
	// Since having the IRP_MJ functions set to null it's illegal
	// we gotta set them to IopInvalidDeviceRequest
	// 
	for( int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++ )
	{
		if( !drv_obj->MajorFunction[i] )
		{
			drv_obj->MajorFunction[i] = IopInvalidDeviceRequest;
		}
	}

	return status; // If everything went correctly this will return the driver's result
}