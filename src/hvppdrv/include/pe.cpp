#include "../include/pe.h"

BOOLEAN ddy::Pe::AssertPeStruct(PVOID64 dllbase)
{
	ULONG64 base = (ULONG64)dllbase;
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllbase;
	if (!(dos->e_magic == 'ZM'))
	{
		return FALSE;
	}
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + base);
	if (!(nt->Signature == 'EP'))
	{
		return FALSE;
	}
	return TRUE;
}

PVOID ddy::Pe::GetDataSection(PVOID dllbase, const char* section_name)
{
	if (!AssertPeStruct(dllbase))
	{
		return 0;
	}
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllbase;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG64)dllbase);
	PIMAGE_SECTION_HEADER  section_head = (PIMAGE_SECTION_HEADER)(nt->FileHeader.SizeOfOptionalHeader + (ULONG64)&nt->OptionalHeader);
	if (section_name==nullptr)
	{
		for (size_t i = 0; i < nt->FileHeader.NumberOfSections; i++)
		{
			if (section_head->Characteristics & 0x40000000)
			{
				if (section_head->Characteristics & 0x80000000)
				{
					return section_head->VirtualAddress + (PCHAR)dllbase;
				}
			}
			section_head++;
		}
		return 0;
	}
	else
	{
		for (size_t i = 0; i < nt->FileHeader.NumberOfSections; i++)
		{
			if (strcmp((const char*)section_head->Name,section_name)==0)
			{
				return section_head->VirtualAddress + (PCHAR)dllbase;
			}
			section_head++;
		}
		return 0;
	}
}

PVOID ddy::Pe::GetPageUnUsed(PVOID dllbase)
{
	if (!AssertPeStruct(dllbase))
	{
		return 0;
	}
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllbase;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG64)dllbase);
	PIMAGE_SECTION_HEADER  section_head = (PIMAGE_SECTION_HEADER)(nt->FileHeader.SizeOfOptionalHeader + (ULONG64)&nt->OptionalHeader);
	for (size_t i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		if (section_head->Characteristics & 0x00000020)
		{
			auto datastart = section_head->VirtualAddress + (PCHAR)dllbase;
			auto unuseed_start = section_head->SizeOfRawData + datastart;
			return unuseed_start + 0x10;
		}
	}
	return 0;
}

PVOID ddy::Pe::GetVaOfSectionBase(IN PVOID lpHeader, OUT OPTIONAL ULONG* Size, IN PVOID ptr)
{
	if ((unsigned char*)ptr < (unsigned char*)lpHeader)
		return 0;
	ULONG dwRva = (ULONG)((unsigned char*)ptr - (unsigned char*)lpHeader);
	IMAGE_DOS_HEADER* pdh = (IMAGE_DOS_HEADER*)lpHeader;
	if (pdh->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;
	IMAGE_NT_HEADERS* pnth = (IMAGE_NT_HEADERS*)((unsigned char*)lpHeader + pdh->e_lfanew);
	if (pnth->Signature != IMAGE_NT_SIGNATURE)
		return 0;
	IMAGE_SECTION_HEADER* psh = IMAGE_FIRST_SECTION(pnth);
	int section = RvaToSection(pnth, dwRva);
	if (section == -1)
		return 0;
	if (Size)
		*Size = psh[section].SizeOfRawData;
	return (PVOID)((unsigned char*)lpHeader + psh[section].VirtualAddress);
}

ULONG ddy::Pe::RvaToSection(IMAGE_NT_HEADERS * pNtHdr, ULONG dwRVA)
{
	USHORT wSections;
	PIMAGE_SECTION_HEADER pSectionHdr;
	pSectionHdr = IMAGE_FIRST_SECTION(pNtHdr);
	wSections = pNtHdr->FileHeader.NumberOfSections;
	for (int i = 0; i < wSections; i++)
	{
		if (pSectionHdr[i].VirtualAddress <= dwRVA)
			if ((pSectionHdr[i].VirtualAddress + pSectionHdr[i].Misc.VirtualSize) > dwRVA)
			{
				return i;
			}
	}
	return (ULONG)-1;
}

ULONG ddy::Pe::RvaToOffset(PIMAGE_NT_HEADERS pnth, ULONG Rva, ULONG FileSize)
{
	PIMAGE_SECTION_HEADER psh = IMAGE_FIRST_SECTION(pnth);
	USHORT NumberOfSections = pnth->FileHeader.NumberOfSections;
	for (int i = 0; i < NumberOfSections; i++)
	{
		if (psh->VirtualAddress <= Rva)
		{
			if ((psh->VirtualAddress + psh->Misc.VirtualSize) > Rva)
			{
				Rva -= psh->VirtualAddress;
				Rva += psh->PointerToRawData;
				return Rva < FileSize ? Rva : PE_ERROR_VALUE;
			}
		}
		psh++;
	}
	return PE_ERROR_VALUE;
}

ULONG ddy::Pe::GetExportOffset(const unsigned char * FileData, ULONG FileSize, const char * ExportName)
{
	//Verify DOS Header
	PIMAGE_DOS_HEADER pdh = (PIMAGE_DOS_HEADER)FileData;
	if (pdh->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return PE_ERROR_VALUE;
	}

	//Verify PE Header
	PIMAGE_NT_HEADERS pnth = (PIMAGE_NT_HEADERS)(FileData + pdh->e_lfanew);
	if (pnth->Signature != IMAGE_NT_SIGNATURE)
	{
		return PE_ERROR_VALUE;
	}

	//Verify Export Directory
	PIMAGE_DATA_DIRECTORY pdd = NULL;
	if (pnth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		pdd = ((PIMAGE_NT_HEADERS64)pnth)->OptionalHeader.DataDirectory;
	else
		pdd = ((PIMAGE_NT_HEADERS32)pnth)->OptionalHeader.DataDirectory;
	ULONG ExportDirRva = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	ULONG ExportDirSize = pdd[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	ULONG ExportDirOffset = RvaToOffset(pnth, ExportDirRva, FileSize);
	if (ExportDirOffset == PE_ERROR_VALUE)
	{
		return PE_ERROR_VALUE;
	}

	//Read Export Directory
	PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)(FileData + ExportDirOffset);
	ULONG NumberOfNames = ExportDir->NumberOfNames;
	ULONG AddressOfFunctionsOffset = RvaToOffset(pnth, ExportDir->AddressOfFunctions, FileSize);
	ULONG AddressOfNameOrdinalsOffset = RvaToOffset(pnth, ExportDir->AddressOfNameOrdinals, FileSize);
	ULONG AddressOfNamesOffset = RvaToOffset(pnth, ExportDir->AddressOfNames, FileSize);
	if (AddressOfFunctionsOffset == PE_ERROR_VALUE ||
		AddressOfNameOrdinalsOffset == PE_ERROR_VALUE ||
		AddressOfNamesOffset == PE_ERROR_VALUE)
	{
		return PE_ERROR_VALUE;
	}
	ULONG* AddressOfFunctions = (ULONG*)(FileData + AddressOfFunctionsOffset);
	USHORT* AddressOfNameOrdinals = (USHORT*)(FileData + AddressOfNameOrdinalsOffset);
	ULONG* AddressOfNames = (ULONG*)(FileData + AddressOfNamesOffset);

	//Find Export
	ULONG ExportOffset = PE_ERROR_VALUE;
	for (ULONG i = 0; i < NumberOfNames; i++)
	{
		ULONG CurrentNameOffset = RvaToOffset(pnth, AddressOfNames[i], FileSize);
		if (CurrentNameOffset == PE_ERROR_VALUE)
			continue;
		const char* CurrentName = (const char*)(FileData + CurrentNameOffset);
		ULONG CurrentFunctionRva = AddressOfFunctions[AddressOfNameOrdinals[i]];
		if (CurrentFunctionRva >= ExportDirRva && CurrentFunctionRva < ExportDirRva + ExportDirSize)
			continue; //we ignore forwarded exports
		if (!strcmp(CurrentName, ExportName))  //compare the export name to the requested export
		{
			ExportOffset = RvaToOffset(pnth, CurrentFunctionRva, FileSize);
			break;
		}
	}
	return ExportOffset;
}

PVOID ddy::Pe::GetPfnByName(ULONG64 base, char * fn_name)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dos->e_lfanew + base);
	PIMAGE_EXPORT_DIRECTORY expo = (PIMAGE_EXPORT_DIRECTORY)(nt->OptionalHeader.DataDirectory[0].VirtualAddress + base);
	PULONG AddressOfFunction = (PULONG)(expo->AddressOfFunctions + base);
	PULONG AddressOfNameArry = (PULONG)(expo->AddressOfNames + base);
	PUSHORT AddressOfNameOridinal = (PUSHORT)(expo->AddressOfNameOrdinals + base);
	ULONG32 indexoffun = 0;
	for (size_t i = 0; i < expo->NumberOfNames; i++)
	{
		if (strcmp((const char*)fn_name, (const char*)(base + AddressOfNameArry[i])) == 0)
		{
			indexoffun = i;
			break;
		}
	}
	if (indexoffun != expo->Base)
	{
		return (PVOID)(base + AddressOfFunction[AddressOfNameOridinal[indexoffun]]);
	}
	else
	{
		return nullptr;
	}
}
