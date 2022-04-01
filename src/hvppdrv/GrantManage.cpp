#include "GrantManage.h"
#include "DbgApi.h"
using namespace ddy;

extern DbgkKernel dbgkapi;

GrantManage::GrantManage()
{
}

GrantManage::~GrantManage()
{
}


NTSTATUS GrantManage::GrantThreadPreMode(HANDLE Th, MODE mode)
{
  PETHREAD Thread;
  auto status = ObReferenceObjectByHandle(Th, 0, *PsThreadType, KernelMode, (PVOID*)&Thread, NULL);
  if (NT_SUCCESS(status))
  {
    PCHAR t = (char*)Thread + dbgkapi.DataOffset.PreviousMode;
    this->PreMode = (MODE)*t;
    *t = mode;
    ObDereferenceObject(Thread);
  }
  return status;
}

NTSTATUS GrantManage::GrantThreadPreMode(PETHREAD Th, MODE mode)
{
  PCHAR t = (char*)Th + dbgkapi.DataOffset.PreviousMode;
  this->PreMode = (MODE)*t;
  *t = mode;
  return STATUS_SUCCESS;
}

BOOLEAN GrantManage::BBHandleCallbackWin7(IN PHANDLE_TABLE_ENTRY HandleTableEntry, IN HANDLE Handle, IN PVOID EnumParameter)
{
  BOOLEAN result = FALSE;
  ASSERT(EnumParameter);

  if (EnumParameter != NULL)
  {
    PHANDLE_GRANT_ACCESS pAccess = (PHANDLE_GRANT_ACCESS)EnumParameter;
    if (Handle == (HANDLE)pAccess->handle)
    {
      if (ExpIsValidObjectEntry(HandleTableEntry))
      {
        // Update access
        auto tempAccess = HandleTableEntry->GrantedAccessBits;
        HandleTableEntry->GrantedAccessBits = pAccess->access;
        pAccess->access = tempAccess;
        result = TRUE;
      }
    }
  }
  return result;
}

BOOLEAN GrantManage::BBHandleCallback(IN PHANDLE_TABLE HandleTable, IN PHANDLE_TABLE_ENTRY HandleTableEntry, IN HANDLE Handle, IN PVOID EnumParameter)
{
  BOOLEAN result = FALSE;
  ASSERT(EnumParameter);

  if (EnumParameter != NULL)
  {
    PHANDLE_GRANT_ACCESS pAccess = (PHANDLE_GRANT_ACCESS)EnumParameter;
    if (Handle == (HANDLE)pAccess->handle)
    {
      if (ExpIsValidObjectEntry(HandleTableEntry))
      {
        // Update access
        auto tempAccess = HandleTableEntry->GrantedAccessBits;
        HandleTableEntry->GrantedAccessBits = pAccess->access;
        pAccess->access = tempAccess;
        result = TRUE;
      }
    }
  }

  // Release implicit locks
  _InterlockedExchangeAdd8((char*)&HandleTableEntry->VolatileLowValue, 1);  // Set Unlocked flag to 1
  if (HandleTable != NULL && HandleTable->HandleContentionEvent)
    ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);

  return result;
}

NTSTATUS GrantManage::GrantThreadPreModeBack(HANDLE Th)
{
  return this->GrantThreadPreMode(Th, this->PreMode);
}

NTSTATUS GrantManage::GrantThreadPreModeBack(PETHREAD Th)
{
  return this->GrantThreadPreMode(Th, this->PreMode);
}

NTSTATUS GrantManage::BBGrantAccess(IN PHANDLE_GRANT_ACCESS pAccess)
{
  NTSTATUS status = STATUS_SUCCESS;
  PEPROCESS pProcess = NULL;

  status = PsLookupProcessByProcessId((HANDLE)pAccess->pid, &pProcess);

  if (NT_SUCCESS(status))
  {
    if (dbgkapi.ver.dwMajorVersion == 6)
    {
      PHANDLE_TABLE pTable = *(PHANDLE_TABLE*)((PUCHAR)pProcess + dbgkapi.DataOffset.ObjectTable);
      BOOLEAN found = ExEnumHandleTable(pTable, &BBHandleCallbackWin7, pAccess, NULL);
      this->PreHandleAccess = *pAccess;
      if (found == FALSE)
        status = STATUS_NOT_FOUND;
    }
    else
    {
      PHANDLE_TABLE pTable = *(PHANDLE_TABLE*)((PUCHAR)pProcess + dbgkapi.DataOffset.ObjectTable);
      HANDLE phandle;
      BOOLEAN found = ExEnumHandleTable(pTable, &BBHandleCallback, pAccess, &phandle);
      this->PreHandleAccess = *pAccess;
      if (found == FALSE)
        status = STATUS_NOT_FOUND;
    }
  }

  if (pProcess)
    ObDereferenceObject(pProcess);

  return status;
}

NTSTATUS GrantManage::BBGrantAccessBack()
{
  return this->BBGrantAccess(&this->PreHandleAccess);
}
