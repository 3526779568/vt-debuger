#pragma once
#pragma warning(disable:5040)
#ifndef DDYLIB_CR3_H_
#define DDYLIB_CR3_H_
#include "ntddk.h"
#include "intrin.h"
namespace ddy
{
	namespace Cr3
	{
		union CommonEntry {
			ULONG64 all;
			struct {
				ULONG64 present : 1;
				ULONG64 write_access : 1;
				ULONG64 user_access : 1;
				ULONG64 pwt : 1;
				ULONG64 pcd : 1;
				ULONG64 accessed : 1;	/*soft accessed page by this entry*/
				ULONG64 dirty : 1;		/*soft writed page by this entry*/
				ULONG64 pat : 1;
				ULONG64 global : 1;
				ULONG64 ignored : 3;
				ULONG64 physial_address : 36;
				ULONG64 reserved1 : 11;
				ULONG64 protection_key : 4;
				ULONG64  execute_disable : 1;	/*If IA32_EFER.NXE = 1, execute-disable */
			} fields;
		};
		static_assert(sizeof(CommonEntry) == 8, "not 64");

		struct InvPcidDescriptor {
			USHORT vpid;
			USHORT reserved1;
			ULONG32 reserved2;
			ULONG64 linear_address;
		};
		static_assert(sizeof(InvPcidDescriptor) == 16, "Size check");

		CommonEntry * GetPtEntry(ULONG64 physical_address, ULONG64 vad, ULONG table_level);
		CommonEntry * GetPtEntryForProcess(ULONG64 cr3, ULONG64 vad, ULONG64 table_level);
		CommonEntry* GetCurrentPML4TEntry(ULONG64 source_cr3, ULONG64 vad, ULONG64 table_level = 1);
		//ULONG64 GetPML4EForProcess(ULONG64 cr3,)
		BOOLEAN SetPageAccessRight(ULONG64 vad, bool write);

		struct PML4TTABLE
		{
			PVOID pml4t_va;
			CommonEntry* pml4t_va_entry;
		};
		void SetTargetProcessCr3PML4TEntry(ULONG64 target_cr3, ULONG64 vad, PML4TTABLE* pt);
		void SetTargetProcessCr3PML4TEntryWhenZero(ULONG64 target_cr3, ULONG64 vad, PML4TTABLE* pt);
	}
}
#endif // !DDYLIB_CR3_H_