#pragma once
#ifndef DDYLIB_NTDLL_H_
#define DDYLIB_NTDLL_H_
#include "ntddk.h"
#include "pe.h"
namespace ddy
{
	namespace Ntdll
	{
		static unsigned char* file_data = 0;
		static ULONG file_size = 0;
		static NTSTATUS status = 0;
		void Init();
		int GetExportSsdtIndex(const char* ExportName);
	}
}

#endif