#include "NoTraceBP.h"
#include <intrin.h>

NoTraceBP::NoTraceBP()
{
}

NoTraceBP::~NoTraceBP()
{
}

bool NoTraceBP::IsAddressInBp(ULONG64 address)
{
  return  this->current_bp == address;
}

bool NoTraceBP::IsBpInBp(BreakPoint other)
{
  return this->current_bp == other;
}

bool NoTraceBP::IsBpInCurrentBp(BreakPoint other)
{
  if (this->current_bp == other)
  {
    return true;
  }
  return false;
}

bool NoTraceBP::AddBp(BreakPoint& bp)
{
  this->current_bp = bp;
  return true;
}

bool NoTraceBP::RemoveBp()
{
  this->current_bp.address = 0;
  return true;
}

bool NoTraceBP::AddPmToMonitor(PageMonitor pm)
{
  KAPC_STATE apc;
  pm.locked = true;
  KeStackAttachProcess(pm.eprocess, &apc);
  __try
  {
    //pm.rwe_mdl = IoAllocateMdl((PVOID)pm.page_va, PAGE_SIZE, FALSE, FALSE, NULL);
    //MmProbeAndLockPages(pm.rwe_mdl, KernelMode, IoReadAccess);
    pm.page_pa = (PVOID)MmGetPhysicalAddress(pm.page_va).QuadPart;
  }
  __except(EXCEPTION_EXECUTE_HANDLER)
  {
    pm.locked = false;
  }
  KeUnstackDetachProcess(&apc);
  this->pagemonitor = pm;
  return true;
}

bool NoTraceBP::RemoveFromMonitor()
{
  if (this->pagemonitor.locked)
  {
    this->pagemonitor.rwe_mdl = nullptr;
    this->pagemonitor.locked = false;
  }
  return true;
}

BreakPoint::BreakPoint()
{
}

BreakPoint::~BreakPoint()
{
}

bool BreakPoint::operator==(BreakPoint other)
{
  return *this == other.address;
}

bool BreakPoint::operator==(ULONG64 other)
{
  if (other >= this->address && other <= this->address + this->size - 1)
  {
    return true;
  }
  return false;
}

bool BreakPoint::operator==(PVOID other)
{
  return *this == (ULONG64)other;
}

bool BreakPoint::operator>(BreakPoint other)
{
  if (this->address > other.address + other.size-1)
  {
    return true;
  }
  return false;
}

bool BreakPoint::operator<(BreakPoint other)
{
  if (this->address + this->size - 1 < other.address)
  {
    return true;
  }
  return false;
}

PageMonitor::PageMonitor()
{
}

PageMonitor::~PageMonitor()
{
}

bool PageMonitor::operator==(PageMonitor other)
{
  if (PAGE_ALIGN(this->page_va) == PAGE_ALIGN(other.page_va) && this->eprocess == other.eprocess)
  {
    return true;
  }
  return false;
}

bool PageMonitor::operator<(PageMonitor other)
{
  return this->page_va < other.page_va;
}

bool PageMonitor::operator>(PageMonitor other)
{
  return this->page_va > other.page_va;
}
