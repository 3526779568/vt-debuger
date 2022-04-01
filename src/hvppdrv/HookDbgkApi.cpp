#include "HookDbgkApi.h"
#include "DbgApi.h"
#include <SsdtHook.h>
#include <hvpp/lib/log.h>
#include <undocstruct.h>
#include "ntundoc/ntdllnative.h"
#include <EASTL/map.h>
#include <EASTL/set.h>
#include "ntundoc/ntbasex64.h"
#include "NoTraceBP.h"
#include <ntimage.h>

using namespace eastl;

extern map<PEPROCESS, PVOID> CEDebugPort;
extern map<PEPROCESS, PVOID> DbgDebugPort;
extern set<PEPROCESS> DebugerMainProcess;
extern set<PEPROCESS> AttachPreocess;
extern ddy::DbgkKernel dbgkapi;
extern InfEvent infevent;


/// <summary>
/// 发送附加消息
/// </summary>
/// <param name="eprocess"></param>
/// <param name="msg"></param>
/// <param name="flags">0是ce 1是xdbg</param>
/// <returns></returns>
NTSTATUS HookDbgkApi::SendInitDebugMsg(PEPROCESS& eprocess, const PVOID& msg, DWORD flags)
{
  auto cedp = ((DEBUG_OBJECT*)CEDebugPort[eprocess]);
  auto dbgdp = ((DEBUG_OBJECT*)DbgDebugPort[eprocess]);
  auto dp = flags ? dbgdp : cedp;
  if (!dp)
  {
    return STATUS_UNSUCCESSFUL;
  }
  //取得调试对象的Mutxe,可能调试器在读数据
  ExAcquireFastMutex(&dp->Mutex);

  dp->Event.push_back((PEventRecord)msg);

  //通知调试器
  KeSetEvent(&dp->EventsPresent, 1, FALSE);

  //释放Mutex让调试器能操作debugport
  ExReleaseFastMutex(&dp->Mutex);
  //这个模拟的调试消息不需要等待调试器响应
  return ((PEventRecord)msg)->ReturnStatus;
}

NTSTATUS HookDbgkApi::SendExceptionMsg(PEPROCESS& eprocess, const PVOID& msg, DWORD flags)
{
  auto cedp = ((DEBUG_OBJECT*)CEDebugPort[eprocess]);
  auto dbgdp = ((DEBUG_OBJECT*)DbgDebugPort[eprocess]);
  auto dp = flags ? dbgdp : cedp;
  if (!dp)
  {
    return STATUS_UNSUCCESSFUL;
  }
  //取得调试对象的Mutxe,可能调试器在读数据
  ExAcquireFastMutex(&dp->Mutex);
  dp->Event.push_back((PEventRecord)msg);
  KeSetEvent(&dp->EventsPresent, 1, FALSE);//通知调试器
  //释放Mutex让调试器能操作debugport
  ExReleaseFastMutex(&dp->Mutex);
  //等待调试器处理消息
  KeWaitForSingleObject(&((PEventRecord)msg)->ContinueEvent, Executive, KernelMode, FALSE, NULL);
  return ((PEventRecord)msg)->ReturnStatus;
}

map<PETHREAD, set<ULONG64>> AntiInterference;

/// <summary>
/// 该函数构造异常记录，并入调试队列中，并等待调试器返回结果，如果不是
/// DBG_EXCEPTION_HANDLED和DBG_CONTINUE，那么就调用原函数.
/// </summary>
/// <param name="ExceptionRecord"></param>
/// <param name="DebugException"></param>
/// <param name="SecondChance"></param>
/// <returns></returns>
BOOLEAN HookDbgkApi::HookDbgkForwardException(IN PEXCEPTION_RECORD ExceptionRecord, IN BOOLEAN DebugException, IN BOOLEAN SecondChance)
{
  auto thread = PsGetCurrentThread();
  if (true)//抗反调试消息干扰
  {
    if (AntiInterference.count(thread))
    {
      if (AntiInterference[thread].count((ULONG64)ExceptionRecord->ExceptionAddress))
      {
        return PreDbgkForwardException(ExceptionRecord, DebugException, SecondChance);
      }
    }
  }
  auto eprocess = PsGetCurrentProcess();
  if ((CEDebugPort[eprocess] != 0 || DbgDebugPort[eprocess] != 0) && SecondChance == FALSE)//这个是我们的调试进程,只处理第一次异常流程
  {
    //暂停进程
    dbgkapi.SuspenAllThreadWithoutThread(thread);
    //构造debug event
    auto cemsg = new EventRecord;
    auto dbgmsg = new EventRecord;

    cemsg->e.dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
    cemsg->e.dwProcessId = (DWORD)PsGetCurrentProcessId();
    cemsg->e.dwThreadId = (DWORD)PsGetCurrentThreadId();
    cemsg->e.u.Exception.dwFirstChance = !SecondChance;
    cemsg->e.u.Exception.ExceptionRecord = *ExceptionRecord;
    dbgmsg->e = cemsg->e;
    NTSTATUS CeStatus = DBG_EXCEPTION_NOT_HANDLED, DbgStatus = DBG_EXCEPTION_NOT_HANDLED;
    //先发送给CE
    if (CEDebugPort[eprocess] != 0)
    {
      //处理无痕硬断
      if (ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP || ExceptionRecord->ExceptionCode == STATUS_WX86_SINGLE_STEP)
      {
        if (infevent.last_inf[eprocess] == true)//有无痕调试器消息
        {
          cemsg->e = *infevent.debugevent[eprocess];//拷贝无痕消息
          infevent.last_inf[eprocess] = false;//反馈给VT，这个异常已经处理完成，可以接受下一个异常了
        }
      }
      CeStatus = SendExceptionMsg(eprocess, cemsg, 0);
    }
    delete cemsg;
    if (DbgDebugPort[eprocess] != 0)//X64DBG
    {
      DbgStatus = SendExceptionMsg(eprocess, dbgmsg, 1);
    }
    delete dbgmsg;
    if (CeStatus == DBG_EXCEPTION_HANDLED ||
      CeStatus == DBG_CONTINUE ||
      DbgStatus == DBG_EXCEPTION_HANDLED ||
      DbgStatus == DBG_CONTINUE)
    {
      //需要刷新指令
      dbgkapi.ZwFlushInstructionCache((HANDLE)-1, 0, 0);
      dbgkapi.ResumeAllThreadWithoutThread(thread);
      return TRUE;
    }
    if (ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)//缺页的干扰难搞。统一都处理一遍
    {
      AntiInterference[thread].insert((ULONG64)ExceptionRecord->ExceptionAddress);//这个异常是调试器自己产生的，可能是反调试加入抗干扰
    }
    dbgkapi.ResumeAllThreadWithoutThread(thread);
  }
  return PreDbgkForwardException(ExceptionRecord, DebugException, SecondChance);
}


PVOID HookDbgkApi::CreateProcessMessage(InputOutputData* data, PEPROCESS& eprocess, RTL_OSVERSIONINFOW& ver)
{
  InputOutputData temp = *data;
  auto msg = new EventRecord;
  KAPC_STATE apc;
  msg->e.dwDebugEventCode = CREATE_PROCESS_DEBUG_EVENT;
  msg->e.dwProcessId = temp.ParamDebugActiveProcess.dwProcessId;
  msg->e.dwThreadId = (DWORD)PsGetThreadId(dbgkapi.PsGetNextProcessThread(eprocess, NULL));
  KeStackAttachProcess(eprocess, &apc);
  auto SectionObject = (PVOID) * (PULONG64)((char*)eprocess + dbgkapi.DataOffset.SectionObject);
  auto SectionBaseAddress = (PVOID) * (PULONG64)((char*)eprocess + dbgkapi.DataOffset.SectionBaseAddress);
  //定位到数据结构
  msg->e.u.CreateProcessInfo.hFile = dbgkapi.DbgkpSectionToFileHandle(SectionObject);
  msg->e.u.CreateProcessInfo.lpBaseOfImage = SectionBaseAddress;
  __try {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)SectionBaseAddress;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG64)dos);
    if (NtHeaders) {
      msg->e.u.CreateProcessInfo.lpStartAddress = NULL; // Filling this in breaks MSDEV!
      msg->e.u.CreateProcessInfo.dwDebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
      msg->e.u.CreateProcessInfo.nDebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
    }
  }
  __except (EXCEPTION_EXECUTE_HANDLER) {
    msg->e.u.CreateProcessInfo.lpStartAddress = NULL;
    msg->e.u.CreateProcessInfo.dwDebugInfoFileOffset = 0;
    msg->e.u.CreateProcessInfo.nDebugInfoSize = 0;
  }

  KeUnstackDetachProcess(&apc);
  ObOpenObjectByPointer(dbgkapi.PsGetNextProcessThread(eprocess, NULL),
    0,
    NULL,
    DBGK_THREAD_ALL_ACCESS,
    *PsThreadType,
    KernelMode,
    &msg->e.u.CreateProcessInfo.hThread);

  ObOpenObjectByPointer(eprocess,
    0,
    NULL,
    DBGK_PROCESS_ALL_ACCESS,
    *PsProcessType,
    KernelMode,
    &msg->e.u.CreateProcessInfo.hProcess);

  auto OldHandle = msg->e.u.CreateProcessInfo.hFile;
  if (OldHandle != NULL) {
    auto CurrentProcess = PsGetCurrentProcess();
    dbgkapi.ObDuplicateObject(CurrentProcess,
      OldHandle,
      CurrentProcess,
      &msg->e.u.CreateProcessInfo.hFile,
      0,
      0,
      DUPLICATE_SAME_ACCESS,
      KernelMode);
    ObCloseHandle(OldHandle, KernelMode);
  }
  return msg;
}

PVOID HookDbgkApi::CreateModuleMessage(InputOutputData* data, PEPROCESS& eprocess, RTL_OSVERSIONINFOW& ver)
{
  InputOutputData temp = *data;
  KAPC_STATE apc;
  KeStackAttachProcess(eprocess, &apc);
  PVOID peb = nullptr;
  BOOLEAN IsWow64Process = util.IsWow64Process(eprocess);
  //定位peb
  if (IsWow64Process)
  {
    peb = util.PsGetProcessPebWow64(eprocess);
  }
  else
  {
    peb = util.PsGetProcessPeb64(eprocess);
  }

  //区分Wow64
  if (IsWow64Process)
  {
    ntdllnative::_LDR_DATA_TABLE_ENTRY_BASE32* ldr = nullptr;
    ntdllnative::_LDR_DATA_TABLE_ENTRY_BASE32* ldrhead, * ldrnext;
    ldr = (decltype(ldr)) & ((ntdllnative::_PEB_LDR_DATA232*)(((ntdllnative::_PEB32*)peb)->Ldr))->InLoadOrderModuleList;
    ldrhead = ldr;
    int i = 0;
    for (i = 0, ldrnext = (ntdllnative::_LDR_DATA_TABLE_ENTRY_BASE32*)ldrhead->InLoadOrderLinks.Flink;
      ldrnext != ldrhead && i < 200;
      ldrnext = (ntdllnative::_LDR_DATA_TABLE_ENTRY_BASE32*)ldrnext->InLoadOrderLinks.Flink, i++)//最多取200个
    {
      auto msg = new EventRecord;
      msg->e.dwDebugEventCode = LOAD_DLL_DEBUG_EVENT;
      msg->e.dwProcessId = temp.ParamDebugActiveProcess.dwProcessId;
      msg->e.dwThreadId = (DWORD)PsGetThreadId(dbgkapi.PsGetNextProcessThread(eprocess, NULL));

      ntdllnative::_LDR_DATA_TABLE_ENTRY_BASE32* entry = (ntdllnative::_LDR_DATA_TABLE_ENTRY_BASE32*)ldrnext;
      msg->e.u.LoadDll.lpBaseOfDll = (PVOID)entry->DllBase;
      PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)entry->DllBase;
      PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG64)dos);
      msg->e.u.LoadDll.dwDebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
      msg->e.u.LoadDll.nDebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
      UNICODE_STRING name;
      OBJECT_ATTRIBUTES oa;
      IO_STATUS_BLOCK iosb;

      auto status = dbgkapi.MmGetFileNameForAddress(NtHeaders, &name);
      if (NT_SUCCESS(status))
      {
        InitializeObjectAttributes(&oa, &name, OBJ_FORCE_ACCESS_CHECK | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        status = ZwOpenFile(&msg->e.u.LoadDll.hFile,
          GENERIC_READ | SYNCHRONIZE,
          &oa,
          &iosb,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
          FILE_SYNCHRONOUS_IO_NONALERT);
        if (!NT_SUCCESS(status)) {
          msg->e.u.LoadDll.hFile = NULL;
        }
        KeUnstackDetachProcess(&apc);//先停止附加，把文件对象转成句柄
        auto OldHandle = msg->e.u.LoadDll.hFile;
        if (OldHandle != NULL) {
          auto CurrentProcess = PsGetCurrentProcess();
          dbgkapi.ObDuplicateObject(CurrentProcess,
            OldHandle,
            CurrentProcess,
            &msg->e.u.LoadDll.hFile,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
            KernelMode);
          ObCloseHandle(OldHandle, KernelMode);
        }
        KeStackAttachProcess(eprocess, &apc);//恢复回去
        SendInitDebugMsg(eprocess, msg, data->ParamDebugActiveProcess.flags);
      }
    }
  }
  else
  {
    ntdllnative::_LDR_DATA_TABLE_ENTRY_BASE64* ldr = nullptr;
    ntdllnative::_LDR_DATA_TABLE_ENTRY_BASE64* ldrhead, * ldrnext;
    ldr = (decltype(ldr)) & ((ntdllnative::_PEB_LDR_DATA264*)(((ntdllnative::_PEB64*)peb)->Ldr))->InLoadOrderModuleList;
    int i = 0;
    ldrhead = ldr;
    for (i = 0, ldrnext = (ntdllnative::_LDR_DATA_TABLE_ENTRY_BASE64*)ldrhead->InLoadOrderLinks.Flink;
      ldrnext != ldrhead && i < 200;
      ldrnext = (ntdllnative::_LDR_DATA_TABLE_ENTRY_BASE64*)ldrnext->InLoadOrderLinks.Flink, i++)//最多取200个
    {
      auto msg = new EventRecord;
      msg->e.dwDebugEventCode = LOAD_DLL_DEBUG_EVENT;
      msg->e.dwProcessId = temp.ParamDebugActiveProcess.dwProcessId;
      msg->e.dwThreadId = (DWORD)PsGetThreadId(dbgkapi.PsGetNextProcessThread(eprocess, NULL));
      ddy::PLDR_DATA_TABLE_ENTRY entry = (ddy::PLDR_DATA_TABLE_ENTRY)ldrnext;
      msg->e.u.LoadDll.lpBaseOfDll = entry->DllBase;
      PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)entry->DllBase;
      PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(dos->e_lfanew + (ULONG64)dos);
      msg->e.u.LoadDll.dwDebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
      msg->e.u.LoadDll.nDebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
      UNICODE_STRING name;
      OBJECT_ATTRIBUTES oa;
      IO_STATUS_BLOCK iosb;
      auto status = dbgkapi.MmGetFileNameForAddress(NtHeaders, &name);
      if (NT_SUCCESS(status))
      {
        InitializeObjectAttributes(&oa, &name, OBJ_FORCE_ACCESS_CHECK | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        status = ZwOpenFile(&msg->e.u.LoadDll.hFile,
          GENERIC_READ | SYNCHRONIZE,
          &oa,
          &iosb,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
          FILE_SYNCHRONOUS_IO_NONALERT);
        if (!NT_SUCCESS(status)) {
          msg->e.u.LoadDll.hFile = NULL;
        }
        KeUnstackDetachProcess(&apc);//先停止附加，把文件对象转成句柄
        auto OldHandle = msg->e.u.LoadDll.hFile;
        if (OldHandle != NULL) {
          auto CurrentProcess = PsGetCurrentProcess();
          dbgkapi.ObDuplicateObject(CurrentProcess,
            OldHandle,
            CurrentProcess,
            &msg->e.u.LoadDll.hFile,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
            KernelMode);
          ObCloseHandle(OldHandle, KernelMode);
        }
        KeStackAttachProcess(eprocess, &apc);//恢复回去
        SendInitDebugMsg(eprocess, msg, data->ParamDebugActiveProcess.flags);
      }
    }
  }
  KeUnstackDetachProcess(&apc);
  return 0;
}

PVOID HookDbgkApi::CreateThreadMessage(InputOutputData* data, PEPROCESS& eprocess, RTL_OSVERSIONINFOW& ver)
{
  InputOutputData temp = *data;
  PETHREAD firstThread = dbgkapi.PsGetNextProcessThread(eprocess, NULL);
  int i = 0;
  for (PETHREAD Thread = firstThread;
    Thread != NULL && i < 100;
    Thread = dbgkapi.PsGetNextProcessThread(eprocess, Thread), i++)
  {
    if (Thread == firstThread)//第一个是进程消息
    {
      continue;
    }
    auto msg = new EventRecord;
    msg->e.dwDebugEventCode = CREATE_THREAD_DEBUG_EVENT;
    msg->e.dwProcessId = temp.ParamDebugActiveProcess.dwProcessId;
    msg->e.dwThreadId = (DWORD)PsGetThreadId(Thread);

    msg->e.u.CreateThread.lpStartAddress = (PVOID) * (PULONG64)((char*)Thread + dbgkapi.DataOffset.Win32StartAddress);//Win7x64会定位到这里
    msg->e.u.CreateThread.lpThreadLocalBase = 0;
    msg->e.u.CreateThread.hThread = nullptr;

    ObOpenObjectByPointer(Thread,
      0,
      NULL,
      DBGK_THREAD_ALL_ACCESS,
      *PsThreadType,
      KernelMode,
      &msg->e.u.CreateThread.hThread);

    SendInitDebugMsg(eprocess, msg, data->ParamDebugActiveProcess.flags);
  }

  return 0;
}



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


HookDbgkApi::HookDbgkApi()
{

}

HookDbgkApi::~HookDbgkApi()
{

}
