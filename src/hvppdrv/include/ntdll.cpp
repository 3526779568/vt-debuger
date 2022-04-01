#include "../include/ntdll.h"
using namespace ddy::Ntdll;
using namespace ddy::Pe;

void ddy::Ntdll::Init()
{
	UNICODE_STRING FileName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	RtlInitUnicodeString(&FileName, L"\\SystemRoot\\system32\\ntdll.dll");
	InitializeObjectAttributes(&ObjectAttributes, &FileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
#ifdef _DEBUG
		DbgPrint("[TITANHIDE] KeGetCurrentIrql != PASSIVE_LEVEL!\n");
#endif
		status = STATUS_UNSUCCESSFUL;
	}

	HANDLE FileHandle;
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS NtStatus = ZwCreateFile(&FileHandle,
		GENERIC_READ,
		&ObjectAttributes,
		&IoStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);
	if (NT_SUCCESS(NtStatus))
	{
		FILE_STANDARD_INFORMATION StandardInformation = { 0 };
		NtStatus = ZwQueryInformationFile(FileHandle, &IoStatusBlock, &StandardInformation, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		if (NT_SUCCESS(NtStatus))
		{
			file_size = StandardInformation.EndOfFile.LowPart;
			file_data = (PUCHAR)ExAllocatePool(NonPagedPool, file_size);
			RtlSecureZeroMemory(file_data, file_size);
			LARGE_INTEGER ByteOffset;
			ByteOffset.LowPart = ByteOffset.HighPart = 0;
			NtStatus = ZwReadFile(FileHandle,
				NULL, NULL, NULL,
				&IoStatusBlock,
				file_data,
				file_size,
				&ByteOffset, NULL);

			if (!NT_SUCCESS(NtStatus))
			{
				ExFreePool(file_data);
				status = STATUS_UNSUCCESSFUL;
			}
		}
		else
		{
			status = STATUS_UNSUCCESSFUL;
		}
		ZwClose(FileHandle);
	}
	else
	{
		status = STATUS_UNSUCCESSFUL;
	}
}


int ddy::Ntdll::GetExportSsdtIndex(const char * ExportName)
{
	if (file_data == 0)
	{
		Init();
	}
	ULONG_PTR ExportOffset = GetExportOffset(file_data, file_size, ExportName);
	if (ExportOffset == PE_ERROR_VALUE)
		return -1;
	int SsdtOffset = -1;
	unsigned char* ExportData = file_data + ExportOffset;
	for (int i = 0; i < 32 && ExportOffset + i < file_size; i++)
	{
		if (ExportData[i] == 0xC2 || ExportData[i] == 0xC3)  //RET
			break;
		if (ExportData[i] == 0xB8)  //mov eax,X
		{
			SsdtOffset = *(int*)(ExportData + i + 1);
			break;
		}
	}

	if (SsdtOffset == -1)
	{
		DbgPrint("[TITANHIDE] SSDT Offset for %s not found...\r\n", ExportName);
	}
	return SsdtOffset;
}
