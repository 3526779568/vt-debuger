#include "SsdtHook.h"
#include "DbgApi.h"
#include "HookDbgkApi.h"
#include "GrantManage.h"

// WOW64_CONTEXT is not undocumented, but it's missing from the WDK
#define WOW64_SIZE_OF_80387_REGISTERS 80
#define WOW64_MAXIMUM_SUPPORTED_EXTENSION 512

extern ddy::DbgkKernel dbgkapi;
extern map<PETHREAD, set<ULONG64>> AntiInterference;
extern map<PETHREAD, CONTEXT> threadcontext;

typedef struct _WOW64_FLOATING_SAVE_AREA
{
  ULONG ControlWord;
  ULONG StatusWord;
  ULONG TagWord;
  ULONG ErrorOffset;
  ULONG ErrorSelector;
  ULONG DataOffset;
  ULONG DataSelector;
  UCHAR RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
  ULONG Cr0NpxState;
} WOW64_FLOATING_SAVE_AREAa, * PWOW64_FLOATING_SAVE_AREA;

#pragma pack(push, 4)

typedef struct _WOW64_CONTEXT
{
  ULONG ContextFlags;

  ULONG Dr0;
  ULONG Dr1;
  ULONG Dr2;
  ULONG Dr3;
  ULONG Dr6;
  ULONG Dr7;

  WOW64_FLOATING_SAVE_AREAa FloatSave;

  ULONG SegGs;
  ULONG SegFs;
  ULONG SegEs;
  ULONG SegDs;

  ULONG Edi;
  ULONG Esi;
  ULONG Ebx;
  ULONG Edx;
  ULONG Ecx;
  ULONG Eax;

  ULONG Ebp;
  ULONG Eip;
  ULONG SegCs;
  ULONG EFlags;
  ULONG Esp;
  ULONG SegSs;

  UCHAR ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];

} WOW64_CONTEXTa;

typedef WOW64_CONTEXTa* PWOW64_CONTEXT;

#pragma pack(pop)

#pragma pack(1)
struct RetJmp
{
  unsigned char sub_rsp[4] = { 0x48,0x83,0xEC,0x08 };
  struct
  {
    unsigned char mov_rsp[3] = { 0xC7,0x04,0x24 };
    unsigned int value;
  }L;
  struct
  {
    unsigned char mov_rsp[4] = { 0xC7,0x44,0x24,0x04 };
    unsigned int value;
  }H;
  char ret = 0xC3;
};
static_assert(sizeof(RetJmp) == 20, "error size");
#pragma pack(0)


set<PEPROCESS> DebugerMainProcess;
extern map<PETHREAD, CONTEXT> thread_context;
extern map<PETHREAD, BOOLEAN> thread_context_used;
extern set<PEPROCESS> AttachPreocess;


BOOLEAN IsAddressSafe1(UINT_PTR StartAddress)
{
#ifdef AMD64
  //cannonical check. Bits 48 to 63 must match bit 47
  UINT_PTR toppart = (StartAddress >> 47);
  if (toppart & 1)
  {
    //toppart must be 0x1ffff
    if (toppart != 0x1ffff)
      return FALSE;
  }
  else
  {
    //toppart must be 0
    if (toppart != 0)
      return FALSE;
  }

#endif

  {
#ifdef AMD64
    UINT_PTR kernelbase = 0x7fffffffffffffffULL;


    if (StartAddress < kernelbase)
      return TRUE;
    else
    {
      PHYSICAL_ADDRESS physical;
      physical.QuadPart = 0;
      physical = MmGetPhysicalAddress((PVOID)StartAddress);
      return (physical.QuadPart != 0);
    }
#endif
  }

}


BOOLEAN ReadProcessMemory(ULONG PID, PEPROCESS PEProcess, PVOID Address, ULONG Size, PVOID Buffer)
{
  PEPROCESS selectedprocess = PEProcess;
  //KAPC_STATE apc_state;
  NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
  if (Size > 1024 * 1024 * 1024)
  {
    return NT_SUCCESS(ntStatus);
  }
  //DbgPrint("%lx Read Process\n", PID);
  if (PEProcess == NULL)
  {
    if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)(UINT_PTR)PID, &selectedprocess)))
      return FALSE; //couldn't get the PID
  }

  char* kernelBuffer = (char*)ExAllocatePool(PagedPool, Size);
  //selectedprocess now holds a valid peprocess value
  __try
  {
    KeAttachProcess((PEPROCESS)selectedprocess);
    __try
    {
      char* target;
      char* source;
      int i;

      if ((IsAddressSafe1((UINT_PTR)Address)) && (IsAddressSafe1((UINT_PTR)Address + Size - 1)))
      {
        target = (PCHAR)kernelBuffer;
        source = (PCHAR)Address;
        if (((UINT_PTR)source < 0x8000000000000000ULL))
        {
          RtlCopyMemory(target, source, Size);
          ntStatus = STATUS_SUCCESS;
        }
      }
    }
    __finally
    {
      KeDetachProcess();
      RtlCopyMemory(Buffer, kernelBuffer, Size);
    }
  }
  __except (1)
  {
    //DbgPrint("Error while reading: ReadProcessMemory(%x,%p, %p, %d, %p\n", PID, PEProcess, Address, Size, Buffer);

    ntStatus = STATUS_UNSUCCESSFUL;
  }

  if (PEProcess == NULL) //no valid peprocess was given so I made a reference, so lets also dereference
    ObDereferenceObject(selectedprocess);
  ExFreePool(kernelBuffer);
  return NT_SUCCESS(ntStatus);
}

KIRQL WPOFFx64()
{
  KIRQL irql = KeRaiseIrqlToDpcLevel();
  UINT64 cr0 = __readcr0();
  cr0 &= 0xfffffffffffeffff;
  __writecr0(cr0);
  _disable();
  return irql;
}

void WPONx64(KIRQL irql)
{
  UINT64 cr0 = __readcr0();
  cr0 |= 0x10000;
  _enable();
  __writecr0(cr0);
  KeLowerIrql(irql);
}

BOOLEAN WriteProcessMemory(ULONG PID, PEPROCESS PEProcess, PVOID Address, ULONG Size, PVOID Buffer)
{
  PEPROCESS selectedprocess = PEProcess;
  NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
  if (Size > 1024 * 1024 * 1024)
  {
    return FALSE;
  }

  if (selectedprocess == NULL)
  {
    //DbgPrint("WriteProcessMemory:Getting PEPROCESS\n");
    if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)(UINT_PTR)PID, &selectedprocess)))
      return FALSE; //couldn't get the PID
  }

  char* kernelBuffer = (char*)ExAllocatePool(PagedPool, Size);
  //selectedprocess now holds a valid peprocess value
  __try
  {
    RtlCopyMemory(kernelBuffer, Buffer, Size);
    KeAttachProcess((PEPROCESS)selectedprocess);
    __try
    {
      char* target;
      char* source;
      unsigned int i;

      if ((IsAddressSafe1((UINT_PTR)Address)) && (IsAddressSafe1((UINT_PTR)Address + Size - 1)))
      {
        //still here, then I gues it's safe to read. (But I can't be 100% sure though, it's still the users problem if he accesses memory that doesn't exist)
        BOOLEAN disabledWP = FALSE;

        target = (PCHAR)Address;
        source = (PCHAR)kernelBuffer;

        if (((UINT_PTR)target < 0x8000000000000000ULL))
        {
          //auto irql = WPOFFx64();
          RtlCopyMemory(target, source, Size);
          //WPONx64(irql);
          ntStatus = STATUS_SUCCESS;
        }
      }
    }
    __finally
    {
      KeDetachProcess();
    }
  }
  __except (1)
  {
    //DbgPrint("Error while writing\n");
    ntStatus = STATUS_UNSUCCESSFUL;
  }

  if (PEProcess == NULL) //no valid peprocess was given so I made a reference, so lets also dereference
    ObDereferenceObject(selectedprocess);
  ExFreePool(kernelBuffer);
  return NT_SUCCESS(ntStatus);
}



NTSTATUS
NTAPI
Z_NtReadVirtualMemory(
  _In_ HANDLE ProcessHandle,
  _In_opt_ PVOID BaseAddress,
  _Out_ PVOID Buffer,
  _In_ SIZE_T BufferSize,
  _Out_opt_ PSIZE_T NumberOfBytesRead
)
{
  auto eprocess = PsGetCurrentProcess();
  if (DebugerMainProcess.count(eprocess))
  {
    GrantManage gm;
    NTSTATUS ReadStatus;
    //句柄提权
    HANDLE_GRANT_ACCESS handleAccess;
    handleAccess.access = 0x1fffff;
    handleAccess.handle = (ULONG64)ProcessHandle;
    handleAccess.pid = (ULONG)PsGetCurrentProcessId();
    auto AccessStatus = gm.BBGrantAccess(&handleAccess);
    ReadStatus = PreNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
    if (NT_SUCCESS(AccessStatus))
    {
      //恢复进程句柄权限
      gm.BBGrantAccessBack();
    }
    return ReadStatus;
  }
  else//走原生
  {
    return PreNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
  }
}

NTSTATUS
NTAPI
Z_NtWriteVirtualMemory(
  HANDLE ProcessHandle,
  PVOID BaseAddress,
  VOID* Buffer,
  SIZE_T BufferSize,
  PSIZE_T NumberOfBytesWritten
)
{
  auto eprocess = PsGetCurrentProcess();
  if (DebugerMainProcess.count(eprocess))
  {
    GrantManage gm;
    NTSTATUS WriteStatus = STATUS_UNSUCCESSFUL;
    //句柄提权
    HANDLE_GRANT_ACCESS handleAccess;
    handleAccess.access = 0x1fffff;
    handleAccess.handle = (ULONG64)ProcessHandle;
    handleAccess.pid = (ULONG)PsGetCurrentProcessId();
    auto AccessStatus = gm.BBGrantAccess(&handleAccess);
    WriteStatus = PreNtWriteVirtualMemory(ProcessHandle, BaseAddress, (PVOID)Buffer, BufferSize, NumberOfBytesWritten);
    if (NT_SUCCESS(AccessStatus))
    {
      gm.BBGrantAccessBack();
    }
    return WriteStatus;
  }
  else//走原生
  {
    return PreNtWriteVirtualMemory(ProcessHandle, BaseAddress, (PVOID)Buffer, BufferSize, NumberOfBytesWritten);
  }
}


NTSTATUS NTAPI Z_NtQueryInformationThread(
  IN HANDLE ThreadHandle,
  IN THREADINFOCLASS ThreadInformationClass,
  IN OUT PVOID ThreadInformation,
  IN ULONG ThreadInformationLength,
  OUT PULONG ReturnLength OPTIONAL)
{  
  NTSTATUS Status = PreNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
  return Status;
}

extern "C"
NTKERNELAPI
VOID
KeInitializeApc(
  __out PRKAPC Apc,
  __in PRKTHREAD Thread,
  __in int Environment,
  __in PVOID KernelRoutine,
  __in_opt PVOID RundownRoutine,
  __in_opt PVOID NormalRoutine,
  __in_opt KPROCESSOR_MODE ProcessorMode,
  __in_opt PVOID NormalContext
);

extern "C"
NTKERNELAPI
BOOLEAN
KeInsertQueueApc(
  __inout PRKAPC Apc,
  __in_opt PVOID SystemArgument1,
  __in_opt PVOID SystemArgument2,
  __in KPRIORITY Increment
);

NTSTATUS NTAPI Z_NtGetContextThread(
  IN HANDLE ThreadHandle,
  IN OUT PCONTEXT Context)
{
  NTSTATUS ret = STATUS_SUCCESS;
  if (DebugerMainProcess.count(PsGetCurrentProcess()))
  {
    //采用特定上下文
    PETHREAD ThreadObject;
    auto status = ObReferenceObjectByHandle(ThreadHandle, 0, *PsThreadType, KernelMode, (PVOID*)&ThreadObject, nullptr);
    if (NT_SUCCESS(status))
    {
      GrantManage gm;
      //提权
      HANDLE_GRANT_ACCESS handleAccess;
      handleAccess.access = 0x1FFFFF;
      handleAccess.handle = (ULONG64)ThreadHandle;
      handleAccess.pid = (ULONG)PsGetCurrentProcessId();
      auto sss = gm.BBGrantAccess(&handleAccess);
      ret = PreNtGetContextThread(ThreadHandle, Context);
      if (NT_SUCCESS(sss))
      {
        gm.BBGrantAccessBack();
      }
      ObDereferenceObject(ThreadObject);
    }
    
  }
  else
  {
    ret = PreNtGetContextThread(ThreadHandle, Context);
  }
  return ret;
}

void SuperGetContext(const PCONTEXT& Context, PETHREAD ThreadObject)
{
  __try
  {
    if ((Context->ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS)
    {
      Context->Dr0 = threadcontext[ThreadObject].Dr0;
      Context->Dr1 = threadcontext[ThreadObject].Dr1;
      Context->Dr2 = threadcontext[ThreadObject].Dr2;
      Context->Dr3 = threadcontext[ThreadObject].Dr3;
      Context->Dr6 = threadcontext[ThreadObject].Dr6;
      Context->Dr7 = threadcontext[ThreadObject].Dr7;
    }
    if ((Context->ContextFlags & CONTEXT_ALL) == CONTEXT_ALL)
    {
      Context->DebugControl = threadcontext[ThreadObject].DebugControl;
    }
    Context->EFlags = threadcontext[ThreadObject].EFlags;
    Context->R10 = threadcontext[ThreadObject].R10;
    Context->R11 = threadcontext[ThreadObject].R11;
    Context->R12 = threadcontext[ThreadObject].R12;
    Context->R13 = threadcontext[ThreadObject].R13;
    Context->R14 = threadcontext[ThreadObject].R14;
    Context->R15 = threadcontext[ThreadObject].R15;
    Context->R8 = threadcontext[ThreadObject].R8;
    Context->R9 = threadcontext[ThreadObject].R9;
    Context->Rax = threadcontext[ThreadObject].Rax;
    Context->Rbp = threadcontext[ThreadObject].Rbp;
    Context->Rbx = threadcontext[ThreadObject].Rbx;
    Context->Rcx = threadcontext[ThreadObject].Rcx;
    Context->Rdi = threadcontext[ThreadObject].Rdi;
    Context->Rdx = threadcontext[ThreadObject].Rdx;
    Context->Rip = threadcontext[ThreadObject].Rip;
    Context->Rsi = threadcontext[ThreadObject].Rsi;
    Context->Rsp = threadcontext[ThreadObject].Rsp;
    if ((Context->ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS)
    {
      Context->SegCs = threadcontext[ThreadObject].SegCs;
      Context->SegDs = threadcontext[ThreadObject].SegDs;
      Context->SegEs = threadcontext[ThreadObject].SegEs;
      Context->SegFs = threadcontext[ThreadObject].SegFs;
      Context->SegGs = threadcontext[ThreadObject].SegGs;
      Context->SegSs = threadcontext[ThreadObject].SegSs;
    }
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    NOTHING;
  }
}

NTSTATUS NTAPI Z_NtSetContextThread(
  __in HANDLE ThreadHandle,
  __in PCONTEXT ThreadContext
)
{
  NTSTATUS ret = STATUS_SUCCESS;
  auto currentThread = PsGetCurrentThread();
  if (DebugerMainProcess.count(PsGetCurrentProcess()))
  {
    //采用特定上下文
    PETHREAD ThreadObject;
    auto status = ObReferenceObjectByHandle(ThreadHandle, 0, *PsThreadType, KernelMode, (PVOID*)&ThreadObject, nullptr);
    if (NT_SUCCESS(status))
    {
      GrantManage gm;
      //提权
      HANDLE_GRANT_ACCESS handleAccess;
      handleAccess.access = 0x1fffff;
      handleAccess.handle = (ULONG64)ThreadHandle;
      handleAccess.pid = (ULONG)PsGetCurrentProcessId();
      auto sss = gm.BBGrantAccess(&handleAccess);
      ret = PreNtSetContextThread(ThreadHandle, ThreadContext);
      if (NT_SUCCESS(sss))
      {
        gm.BBGrantAccessBack();
      }
      ObDereferenceObject(ThreadObject);
    }

  }
  else
  {
    ret = PreNtSetContextThread(ThreadHandle, ThreadContext);
  }
  return ret;
}

NTSTATUS NTAPI Z_NtSetInformationThread(
  IN HANDLE ThreadHandle,
  IN THREADINFOCLASS ThreadInformationClass,
  IN PVOID ThreadInformation,
  IN ULONG ThreadInformationLength)
{
  //判断句柄是否正常
  PETHREAD thread;
  auto status = ObReferenceObjectByHandle(ThreadHandle, 0, *PsThreadType, UserMode, (PVOID*)&thread, 0);
  if (NT_SUCCESS(status))
  {
    ObDereferenceObject(thread);
    if (ThreadInformationClass == ThreadHideFromDebugger && !ThreadInformationLength)
    {
      return STATUS_SUCCESS;
    }
    return PreNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
  }
  else
  {
    return status;
  }
}

SSDTHook::SSDTHook()
{
}

void SSDTHook::InitHook()
{
  //NtReadProcessMemory
  this->ssdtpoint[dbgkapi.NtReadVirtualMemory] = Z_NtReadVirtualMemory;

  //NtWriteProcessMemory
  this->ssdtpoint[dbgkapi.NtWriteVirtualMemory] = Z_NtWriteVirtualMemory;

  //HOOK KidispatchException
  this->ssdtpoint[dbgkapi.DbgkForwardException] = HookDbgkApi::HookDbgkForwardException;

  //NtGetContextThread
  this->ssdtpoint[dbgkapi.NtGetContextThread] = Z_NtGetContextThread;
  this->ssdtpoint[dbgkapi.NtSetContextThread] = Z_NtSetContextThread;

  ParseApi();
}

void SSDTHook::BeginHookSSDT()
{
  InitHook();
  //按页分类
  for (auto api : this->ssdtpoint)
  {
    page_split[PAGE_ALIGN(api.first)].insert(api.first);
  }
  //按页隐藏
  for (auto page : page_split)
  {
    char* e_page = nullptr;
    if (hide.memoryhide.count(page.first))
    {
      e_page = (char*)hide.memoryhide[page.first]->e_page_va;
    }
    else
    {
      e_page = new char[PAGE_SIZE];
      memcpy(e_page, page.first, PAGE_SIZE);
    }
    for (auto point : page.second)
    {
      auto of = (ULONG64)point - (ULONG64)page.first;
      if ((long long)of >= 0 && of < 0x1000)
      {
        //先关闭页面隐藏。
        hide.RemoveHide(page.first);
        memcpy(e_page + of, "\x0F\x0B", 2);//设为#UD
        //*(e_page + of) = 0xcc;//执行页设置断点
      }
    }
    hide.Hide(page.first, e_page);
    ////隐藏这两个核心
    //page_split[PAGE_ALIGN(dbgkapi.KiDispatchException)].insert(dbgkapi.KiDispatchException);
    //page_split[PAGE_ALIGN(dbgkapi.DbgkForwardException)].insert(dbgkapi.DbgkForwardException);
    ////按页隐藏
    //for (auto page : page_split)
    //{
    //  char* e_page = nullptr;
    //  if (hide.memoryhide.count(page.first))
    //  {
    //    e_page = (char*)hide.memoryhide[page.first]->e_page_va;
    //  }
    //  else
    //  {
    //    e_page = new char[PAGE_SIZE];
    //    memcpy(e_page, page.first, PAGE_SIZE);
    //  }
    //  for (auto point : page.second)
    //  {
    //    auto of = (ULONG64)point - (ULONG64)page.first;
    //    if ((long long)of >= 0 && of < 0x1000)
    //    {
    //      //先关闭页面隐藏。
    //      hide.RemoveHide(page.first);
    //      memcpy(e_page + of, "\x0F\x0B", 2);//设为#UD
    //      //*(e_page + of) = 0xcc;//执行页设置断点
    //    }
    //  }
    //  hide.Hide(page.first, e_page);
    //}
  }

}

void SSDTHook::ParseApi()
{
  //修改跳板原函数
  // Initialize decoder context.
  ZydisDecoder decoder;
  ZydisDecoderInit(
    &decoder,
    ZYDIS_MACHINE_MODE_LONG_64,
    ZYDIS_ADDRESS_WIDTH_64);
  // Initialize formatter. Only required when you actually plan to
  // do instruction formatting ("disassembling"), like we do here.
  ZydisFormatter formatter;
  ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
  uint64_t instructionPointer;
  int count = 0;
  size_t offset = 0;
  ZydisDecodedInstruction instruction;
  InstallHookApi(instructionPointer, dbgkapi.NtReadVirtualMemory, PreNtReadVirtualMemory, decoder, instruction);
  InstallHookApi(instructionPointer, dbgkapi.NtWriteVirtualMemory, PreNtWriteVirtualMemory, decoder, instruction);
  InstallHookApi(instructionPointer, dbgkapi.NtQueryInformationThread, PreNtQueryInformationThread, decoder, instruction);
  InstallHookApi(instructionPointer, dbgkapi.NtGetContextThread, PreNtGetContextThread, decoder, instruction);
  InstallHookApi(instructionPointer, dbgkapi.NtSetContextThread, PreNtSetContextThread, decoder, instruction);
  InstallHookApi(instructionPointer, dbgkapi.NtQueryInformationProcess, PreNtQueryInformationProcess, decoder, instruction);
  InstallHookApi(instructionPointer, dbgkapi.DbgkForwardException, PreDbgkForwardException, decoder, instruction);
}

void SSDTHook::InstallHookApi(uint64_t& instructionPointer, const PVOID& api, const PVOID& detour, ZydisDecoder& decoder, ZydisDecodedInstruction& instruction)
{
  char* data = (char*)api;
  int offset = 0;
  instructionPointer = (ULONG64)api;
  if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
    &decoder, (PVOID)(data + offset), 100 - offset,
    &instruction)))
  {
    auto irql = WPOFFx64();
    memcpy(detour, api, instruction.length);
    RetJmp ret;
    ret.H.value = ((ULONG64)api + instruction.length) >> 32;
    ret.L.value = ((ULONG64)api + instruction.length) & 0xffffffff;
    memcpy(PVOID((ULONG64)detour + instruction.length), &ret, sizeof(RetJmp));
    WPONx64(irql);
  }
}

SSDTHook::~SSDTHook()
{
}

