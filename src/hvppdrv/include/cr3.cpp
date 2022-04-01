#include "../include/cr3.h"
#include "../include/instruction_check.h"
using namespace ddy::Cr3;

CommonEntry * ddy::Cr3::GetPtEntry(ULONG64 physical_address, ULONG64 vad, ULONG table_level)
{
	PHYSICAL_ADDRESS phy;
	phy.QuadPart = physical_address << 12;/*4K对齐*/
	CommonEntry *table = (CommonEntry *)MmGetVirtualForPhysical(phy);
	if (!table)
	{
		return nullptr;
	}
	switch (table_level) {
	case 4: {
		// table == PML4
		const auto pxe_index = (vad >> 39) & 0x1ff;
		const auto ept_pml4_entry = &table[pxe_index];
		if (!ept_pml4_entry->all) {
			return nullptr;
		}
		return GetPtEntry(ept_pml4_entry->fields.physial_address, vad, table_level - 1);
	}
	case 3: {
		// table == PDPT
		const auto ppe_index = (vad >> 30) & 0x1ff;
		const auto ept_pdpt_entry = &table[ppe_index];
		if (!ept_pdpt_entry->all) {
			return nullptr;
		}
		return GetPtEntry(ept_pdpt_entry->fields.physial_address, vad, table_level - 1);
	}
	case 2: {
		// table == PDT
		const auto pde_index = (vad >> 21) & 0x1ff;
		const auto ept_pdt_entry = &table[pde_index];
		if (!ept_pdt_entry->all) {
			return nullptr;
		}
		return GetPtEntry(ept_pdt_entry->fields.physial_address, vad, table_level - 1);
	}
	case 1: {
		// table == PT
		const auto pte_index = (vad >> 12) & 0x1ff;
		const auto ept_pt_entry = &table[pte_index];
		return ept_pt_entry;
	}
	default:
		return nullptr;
	}
}

CommonEntry * ddy::Cr3::GetPtEntryForProcess(ULONG64 cr3, ULONG64 vad, ULONG64 table_level = 4)
{
	ULONG64 phyaddress = cr3 >> 12;
	return GetPtEntry(phyaddress, vad, table_level);
}

CommonEntry* ddy::Cr3::GetCurrentPML4TEntry(ULONG64 source_cr3, ULONG64 vad, ULONG64 table_level)
{
	ULONG64 phyaddress = source_cr3 >> 12;
	PHYSICAL_ADDRESS phy = { 0 };
	phy.QuadPart = phyaddress << 12;/*4K对齐*/
	CommonEntry* table = (CommonEntry*)MmGetVirtualForPhysical(phy);
	const auto pxe_index = (vad >> 39) & 0x1ff;
	const auto ept_pml4_entry = &table[pxe_index];
	return ept_pml4_entry;
}

BOOLEAN ddy::Cr3::SetPageAccessRight(ULONG64 vad, bool write)
{
	CommonEntry cr3;
	ddy::CheckInstruction check;
	cr3.all = __readcr3();
	CommonEntry* pte = GetPtEntry(cr3.fields.physial_address, vad, 4);
	if (!pte)
	{
		return FALSE;
	}
	pte->fields.write_access = write;
	InvPcidDescriptor pcid;
	RtlSecureZeroMemory(&pcid, sizeof(InvPcidDescriptor));
	if (check.CheckInvpcid())
	{
		_invpcid(2, &pcid);
	}
	else
	{
		ULONG64 m = vad;
		__invlpg(&m);
	}
	if (pte->fields.global)//全局pte,更新CR3
	{
		__writecr3(cr3.all);
	}
	
	return TRUE;
}

void ddy::Cr3::SetTargetProcessCr3PML4TEntry(ULONG64 target_cr3, ULONG64 vad, PML4TTABLE* pt)
{
	ULONG64 phyaddress = target_cr3 >> 12;
	//让PML4TTABLE指向目标进程的pml4t表地址
	pt->pml4t_va_entry->fields.physial_address = phyaddress;
	ULONG64 m = (ULONG64)pt->pml4t_va;//刷新PML4TTABLE地址,pml4t_va指向了目标进程cr3的pml4t
	__invlpg(&m);
	const auto pxe_index = (vad >> 39) & 0x1ff;
	CommonEntry* e = (CommonEntry*)pt->pml4t_va;
	e[pxe_index] = *GetCurrentPML4TEntry(__readcr3(), vad, 1);
}

void ddy::Cr3::SetTargetProcessCr3PML4TEntryWhenZero(ULONG64 target_cr3, ULONG64 vad, PML4TTABLE* pt)
{
	ULONG64 phyaddress = target_cr3 >> 12;
	//让PML4TTABLE指向目标进程的pml4t表地址
	pt->pml4t_va_entry->fields.physial_address = phyaddress;
	ULONG64 m = (ULONG64)pt->pml4t_va;//刷新PML4TTABLE地址,pml4t_va指向了目标进程cr3的pml4t
	__invlpg(&m);
	const auto pxe_index = (vad >> 39) & 0x1ff;
	CommonEntry* e = (CommonEntry*)pt->pml4t_va;
	if (e[pxe_index].fields.physial_address == 0)
	{
		e[pxe_index] = *GetCurrentPML4TEntry(__readcr3(), vad, 1);
	}
}

