#pragma once
#include <ntifs.h>
#include "Stowaways.h"
#include <EASTL/map.h>
#include <EASTL/set.h>
#include <EASTL/vector.h>
#include "winbase.h"
using namespace eastl;
#define DBGK_PROCESS_ALL_ACCESS 0x00100000L|0x0020|0x0010|0x0008|0x0001|0x0800|0x0100|0x0200|0x1000|0x0400|0x0040|0x0002|0x0080
#define DBGK_THREAD_ALL_ACCESS  0x00100000L|0x0200|0x0008|0x0100|0x0040|0x0800|0x0010|0x0020|0x0400|0x0080|0x0002|0x0001

typedef class _EventRecord
{
public:
  DEBUG_EVENT e;
  //这个是发送消息后，需要等待的事件 每个消息开始时都要设置未信号状态
  KEVENT ContinueEvent;
  //返回的状态
  NTSTATUS ReturnStatus;

  _EventRecord() {
    //初始化调试器事件
    KeInitializeEvent(&this->ContinueEvent, SynchronizationEvent, FALSE);
    RtlZeroMemory(&e, sizeof(DEBUG_EVENT));
    this->ReturnStatus = DBG_EXCEPTION_NOT_HANDLED;
  };
  ~_EventRecord() {};
}EventRecord,*PEventRecord;

typedef struct _DEBUG_OBJECT {
  //
  // Event thats set when the EventList is populated.
  //
  KEVENT EventsPresent;
  //
  // Mutex to protect the structure
  //
  FAST_MUTEX Mutex;
  //
  // Queue of events waiting for debugger intervention
  //
  vector<PEventRecord> Event;
  //
  // Flags for the object
  //
  ULONG Flags;

} DEBUG_OBJECT, * PDEBUG_OBJECT;


class HookDbgkApi
{

public:
  HookDbgkApi();
  ~HookDbgkApi();


  static BOOLEAN HookDbgkForwardException(
      IN PEXCEPTION_RECORD ExceptionRecord,
      IN BOOLEAN DebugException,
      IN BOOLEAN SecondChance
    );

  static PVOID CreateProcessMessage(InputOutputData* data, PEPROCESS& eprocess, RTL_OSVERSIONINFOW& ver);

  static PVOID CreateModuleMessage(InputOutputData* data, PEPROCESS& eprocess, RTL_OSVERSIONINFOW& ver);

  static PVOID CreateThreadMessage(InputOutputData* data, PEPROCESS& eprocess, RTL_OSVERSIONINFOW& ver);

  static NTSTATUS SendInitDebugMsg(PEPROCESS& eprocess, const PVOID& msg, DWORD flags);

  static NTSTATUS SendExceptionMsg(PEPROCESS& eprocess, const PVOID& msg, DWORD flags);

private:

};
