#include "MemoryHide.h"
#include "include/cr3.h"
#include "../hvpp/hvpp/lib/mp.h"
#include "../hvpp/hvpp/hvpp.h"

extern MemoryHide hide;

MemoryHide::~MemoryHide()
{
	for (auto hide : memoryhide)
	{
		if (hide.second->rwe_mdl)
		{
      mp::ipi_call([](void* context)->void {
        HvppVmCall(VMCALLVALUE::DDYRemoveMemoryHide, (ULONG_PTR)context, 0, 0);
        }, &hide.second);
		}
	}
	for (auto hide : memoryhide)
	{
		if (hide.second->rwe_mdl)
		{
			hide.second->rwe_mdl = nullptr;
		}
	}
	memoryhide.clear();
}
BOOLEAN MemoryHide::Hide(PVOID rw_va, PVOID e_va)
{
	auto rw_page = PAGE_ALIGN(rw_va);
	auto e_page = PAGE_ALIGN(e_va);
	if (memoryhide.count(rw_page))
	{
		return FALSE;
	}
	HookData  *data = new HookData;
	__try
	{
		data->rwe_mdl = IoAllocateMdl(rw_page, PAGE_SIZE, FALSE, FALSE, NULL);
		MmProbeAndLockPages(data->rwe_mdl, KernelMode, IoReadAccess);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}
	data->rw_page_va = rw_page;
	data->rw_page_pa = (PVOID)MmGetPhysicalAddress(rw_page).QuadPart;
	data->e_page_va = e_page;
	data->e_page_pa = (PVOID)MmGetPhysicalAddress(e_page).QuadPart;
	this->memoryhide[rw_page] = data;
  mp::ipi_call([](void* context)->void {
    HvppVmCall(DDYMemoryHide, (ULONG64)context, 0, 0);
    }, this->memoryhide[rw_page]);
	return TRUE;
}


void MemoryHide::RemoveHide(PVOID rw_va)
{
	auto rw_page = PAGE_ALIGN(rw_va);
	if (!this->memoryhide.count(rw_page))
	{
		return;
	}

  mp::ipi_call([](void* context)->void {
    HvppVmCall(DDYRemoveMemoryHide, (ULONG64)context, 0, 0);
    }, this->memoryhide[rw_page]);
  this->memoryhide[rw_page]->rwe_mdl = nullptr;
  this->memoryhide.erase(rw_page);
}
