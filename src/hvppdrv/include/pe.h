#pragma once
#include "ntddk.h"
#include "ntimage.h"

#ifndef DDYLIB_PE_H_
#define DDYLIB_PE_H_
#define PE_ERROR_VALUE (ULONG)-1
namespace ddy
{
	namespace Pe
	{
		BOOLEAN AssertPeStruct(PVOID64 dllbase);
		PVOID GetDataSection(PVOID pebase, const char* section_name = nullptr);
		PVOID GetPageUnUsed(PVOID pebase);
		PVOID GetVaOfSectionBase(IN PVOID pebase, OUT OPTIONAL ULONG* Size, IN PVOID ptr);
		ULONG RvaToSection(IMAGE_NT_HEADERS* pNtHdr, ULONG dwRVA);
		ULONG RvaToOffset(PIMAGE_NT_HEADERS pnth, ULONG Rva, ULONG FileSize);
		ULONG GetExportOffset(const unsigned char* FileData, ULONG FileSize, const char* ExportName);
		PVOID GetPfnByName(ULONG64 base, char* fn_name);
	}
}
#endif // !DDYLIB_PE_H_
