#include "Stowaways.h"
#include <ntstrsafe.h>
#include <ddyutil.h>
#include "MemoryHide.h"
#include "DbgApi.h"
#include <cr3.h>
#include <Zydis/Zydis.h>
#include <hvpp/lib/log.h>
#include "HookDbgkApi.h"
#include "SsdtHook.h"
#include "ntimage.h"


#include "GrantManage.h"
#include "NoTraceBP.h"
#include "ntundoc/ntdllnative.h"
#include "../hvpp/hvpp/lib/mp.h"
#include "../hvpp/hvpp/hvpp.h"

extern map<PEPROCESS, PVOID> CEDebugPort;
extern map<PEPROCESS, PVOID> DbgDebugPort;
extern set<PEPROCESS> DebugerMainProcess;

ddy::Util util;
MemoryHide hide;
ddy::DbgkKernel dbgkapi;

NoTraceBP infbp;
InfEvent infevent;

set<PEPROCESS> AttachPreocess;
map<PVOID, PEventRecord> last_event;
map<PETHREAD, CONTEXT> threadcontext;
bool PassPged = 0;

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

extern "C"
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenThread(
  OUT PHANDLE             ThreadHandle,
  IN ACCESS_MASK          DesiredAccess,
  IN POBJECT_ATTRIBUTES   ObjectAttributes,
  IN PCLIENT_ID           ClientId
);




BOOL CheckApiModify()
{
  return false;
}

/// <summary>
/// 这个函数用来迷惑别人
/// </summary>
/// <param name="DeviceObject"></param>
/// <param name="Irp"></param>
/// <returns></returns>
NTSTATUS ControlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  NTSTATUS Status = STATUS_SUCCESS;
  ULONG_PTR Informaition = 0;
  PVOID InputData = NULL;
  ULONG InputDataLength = 0;
  PVOID OutputData = NULL;
  ULONG OutputDataLength = 0;
  ULONG IoControlCode = 0;
  PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);  // Irp堆栈
  IoControlCode = IoStackLocation->Parameters.DeviceIoControl.IoControlCode;
  InputData = Irp->AssociatedIrp.SystemBuffer;
  OutputData = Irp->AssociatedIrp.SystemBuffer;
  InputDataLength =
    IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
  OutputDataLength =
    IoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
  InputOutputData* data = (InputOutputData*)InputData;
  switch (IoControlCode) {
  case PROCESS_ADD_ANTIDEBUG:
  {
    if (data->ParamDebugActiveProcess.dwProcessId != -1)
    {
      auto eprocess = util.GetProcessEprocessByProcessId((HANDLE)data->ParamDebugActiveProcess.dwProcessId);
      if (eprocess)
      {
        DebugerMainProcess.insert(eprocess);
      }
    }
    else
    {
      auto eprocess = PsGetCurrentProcess();
      DebugerMainProcess.insert(eprocess);
    }
    break;
  }
  case PROCESS_GET_ANTIDEBUG:
  {
    //检测关键的函数是否被HOOK修改
    data->Anti.DebugCount = CheckApiModify();
    Informaition = 0x1000;
    break;
  }
  case PROCESS_OPENHANDLE:
  {//打开进程句柄
    auto targetProcessHandle = util.OpenProcess((HANDLE)data->Handle.pid);
    if (targetProcessHandle == 0)
    {
      Status = 10086;
    }
    data->Handle.phandle = targetProcessHandle;
    Informaition = 0x1000;
    break;
  }
  case THREAD_OPENHANDLE:
  {
    HANDLE ThreadHandle;
    CLIENT_ID ClientID;
    OBJECT_ATTRIBUTES ObjectAttributes;

    RtlZeroMemory(&ObjectAttributes, sizeof(OBJECT_ATTRIBUTES));

    Status = STATUS_SUCCESS;

    ClientID.UniqueProcess = 0;
    ClientID.UniqueThread = (HANDLE)data->Handle.pid;
    ThreadHandle = 0;

    __try
    {
      ThreadHandle = 0;
      Status = ZwOpenThread(&ThreadHandle, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientID);
    }
    __except (1)
    {
      Status = STATUS_UNSUCCESSFUL;
    }
    data->Handle.phandle = ThreadHandle;
    Informaition = 0x1000;
    break;
  }
  case PROCESS_CHANGE_HANDLE_ACCESS:
  {
    //提权
    HANDLE_GRANT_ACCESS handleAccess;
    handleAccess.access = 0x1fffff;
    handleAccess.handle = (ULONG64)data->HandleTable.hThread;
    handleAccess.pid = (ULONG)data->HandleTable.ProcessId;
    GrantManage gm;
    auto sss = gm.BBGrantAccess(&handleAccess);
    break;
  }
  
  case PROCESS_LOGIN_GET_API_OFFSET:
  {
    //获取API的偏移
    dbgkapi.InitVersionApi();
    break;
  }
  case PROCESS_MODIFY_API:
  {
    //隐藏offset
    dbgkapi.HideAll();
    break;
  }
  case PROCESS_DebugActiveProcess:
  {
    //模拟附加进程
    if (true)
    {
      DebugerMainProcess.insert(PsGetCurrentProcess());
      auto eprocess = util.GetProcessEprocessByProcessId(HANDLE(data->ParamDebugActiveProcess.dwProcessId));
      if (eprocess)
      {
        infevent.last_inf[eprocess] = false;
        infevent.debugevent[eprocess] = new DEBUG_EVENT;//构造被调试对象的无痕数据
        infevent.last_lock[eprocess] = false;
        AttachPreocess.insert(eprocess);
        RTL_OSVERSIONINFOW ver;
        RtlGetVersion(&ver);
        auto cedp = ((DEBUG_OBJECT*)CEDebugPort[eprocess]);
        auto dbgdp = ((DEBUG_OBJECT*)DbgDebugPort[eprocess]);
        auto dp = data->ParamDebugActiveProcess.flags ? dbgdp : cedp;
        if (dp == 0)
        {
          auto object = new DEBUG_OBJECT;//创建调试对象
          if (data->ParamDebugActiveProcess.flags == 0)
          {
            CEDebugPort[eprocess] = object;
          }
          else
          {
            DbgDebugPort[eprocess] = object;
          }
          //Init 信号和互斥体
          ExInitializeFastMutex(&object->Mutex);
          KeInitializeEvent(&object->EventsPresent, NotificationEvent, FALSE);
        }
        //暂停进程 发送消息
        dbgkapi.PsSuspendProcess(eprocess);

        //构造模块消息
        HookDbgkApi::CreateModuleMessage(data, eprocess, ver);

        //构造线程消息
        HookDbgkApi::CreateThreadMessage(data, eprocess, ver);

        //构造进程消息
        auto msg = HookDbgkApi::CreateProcessMessage(data, eprocess, ver);
        //通知调试器
        HookDbgkApi::SendInitDebugMsg(eprocess, msg, data->ParamDebugActiveProcess.flags);

        //通知调试器
        if (data->ParamDebugActiveProcess.flags == 0)
        {
          KeSetEvent(&((DEBUG_OBJECT*)CEDebugPort[eprocess])->EventsPresent, 1, FALSE);
        }
        else
        {
          KeSetEvent(&((DEBUG_OBJECT*)DbgDebugPort[eprocess])->EventsPresent, 1, FALSE);
        }

        //恢复进程
        dbgkapi.PsResumeProcess(eprocess);
      }
      Informaition = 0x1000;
    }
    break;
  }
  case PROCESS_WaitForDebugEvent:
  {
    if (true)
    {
      auto eprocess = util.GetProcessEprocessByProcessId(HANDLE(data->ParamWaitForDebugEvent.dwProcessId));
      data->ParamWaitForDebugEvent.OK = TRUE;
      DEBUG_OBJECT* o = (DEBUG_OBJECT*)(data->ParamWaitForDebugEvent.flags ? DbgDebugPort[eprocess] : CEDebugPort[eprocess]);
      if (o != 0)
      {
        ExAcquireFastMutex(&o->Mutex);
        if (o->Event.size())
        {
          LARGE_INTEGER timeout{ data->ParamWaitForDebugEvent.dwMilliseconds };
          NTSTATUS  status;
          if (data->ParamWaitForDebugEvent.dwMilliseconds != 0xFFFFFFFF)
          {
            status = KeWaitForSingleObject(&o->EventsPresent, Executive, KernelMode, FALSE, &timeout);
          }
          else
          {
            status = KeWaitForSingleObject(&o->EventsPresent, Executive, KernelMode, FALSE, NULL);
          }
          if (status != STATUS_TIMEOUT)
          {
            PEventRecord e = o->Event.back();
            last_event[o] = e;
            //及时移除数据
            o->Event.pop_back();
            data->ParamWaitForDebugEvent.DebugEvent = e->e;
            data->ParamWaitForDebugEvent.OK = TRUE;
          }
        }
        else
        {
          data->ParamWaitForDebugEvent.OK = FALSE;
        }
        ExReleaseFastMutex(&o->Mutex);
      }
      Informaition = 0x1000;
    }
    break;
  }
  case PROCESS_ContinueDebugEvent:
  {
    if (true)
    {
      auto eprocess = util.GetProcessEprocessByProcessId(HANDLE(data->ParamContinueDebugEvent.dwProcessId));
      data->ParamContinueDebugEvent.OK = FALSE;
      DEBUG_OBJECT* o = (DEBUG_OBJECT*)(data->ParamContinueDebugEvent.flags ? DbgDebugPort[eprocess] : CEDebugPort[eprocess]);
      if (o != 0)
      {
        ExAcquireFastMutex(&o->Mutex);
        last_event[o]->ReturnStatus = data->ParamContinueDebugEvent.dwContinueStatus;
        if (o->Event.size() == 0)
        {
          //告诉调试端口没有调试消息了
          KeClearEvent(&o->EventsPresent);
        }
        else
        {
          KeSetEvent(&o->EventsPresent, 1, FALSE);
        }
        data->ParamContinueDebugEvent.OK = TRUE;
        //当前异常记录处理完成
        KeSetEvent(&last_event[o]->ContinueEvent, 1, FALSE);
        ExReleaseFastMutex(&o->Mutex);
      }
      Informaition = 0x1000;
    }
    break;
  }
  case DebugSetBreakPoint:
  {
    //关闭之前的断点
    infbp.RemoveBp();
    mp::ipi_call([]()->void {
      HvppVmCall(VMCALLVALUE::DDYInfUnHook, (ULONG64)0, 0, 0);//
      });
    infbp.RemoveFromMonitor();

    auto eprocess = util.GetProcessEprocessByProcessId((HANDLE)data->BreakPoint.processid);
    if (!eprocess)
    {
      break;
    }
    BreakPoint bp;//创建断点
    bp.address = data->BreakPoint.address;
    bp.size = data->BreakPoint.size;

    infbp.AddBp(bp);

    PageMonitor pm;
    pm.eprocess = eprocess;
    pm.page_va = PAGE_ALIGN(bp.address);
    infbp.AddPmToMonitor(pm);

    //监视,就算这里重复EPT映射了 也没关系
    mp::ipi_call([]()->void {
      HvppVmCall(VMCALLVALUE::DDYInfHook, (ULONG64)0, 0, 0);//如果异常分发函数是#UD 那就是真的#UD了
      });

    Informaition = 0x1000;
    break;
  }
  case DebugRemoveBreakPoint:
  {
    BreakPoint bp;
    bp.address = data->BreakPoint.address;
    bp.size = data->BreakPoint.size;
    infbp.RemoveBp();

    mp::ipi_call([]()->void {
      HvppVmCall(VMCALLVALUE::DDYInfUnHook, (ULONG64)0, 0, 0);//
      });

    infbp.RemoveFromMonitor();

    //这里不能反MAP，只有等进程退出才能执行反MAP
    Informaition = 0x1000;
    break;
  }
  case PROCESS_IsWoW64:
  {
    auto eprocess = util.GetProcessEprocessByProcessId((HANDLE)data->ParamWaitForDebugEvent.dwProcessId);
    if (!eprocess)
    {
      data->ParamWaitForDebugEvent.OK = FALSE;
    }
    else
    {
      data->ParamWaitForDebugEvent.dwProcessId = util.PsGetProcessPebWow64(eprocess) == 0 ? 0 : 1;
      data->ParamWaitForDebugEvent.OK = TRUE;
    }
    Informaition = 0x1000;
    break;
  }

  case PROCESS_CONF:
  {
    Informaition = 0;
    break;
  }
  }
  Irp->IoStatus.Status = Status;            // Ring3 GetLastError();
  Irp->IoStatus.Information = Informaition;  //这个是返回的长度
  IoCompleteRequest(Irp, IO_NO_INCREMENT);  //将Irp返回给Io管理器
  return Status;                            // Ring3 DeviceIoControl()返回值
}




void MonitorProcessExit(PEPROCESS Process, HANDLE ProcessId,
  PPS_CREATE_NOTIFY_INFO CreateInfo) {
  UNREFERENCED_PARAMETER(ProcessId);
  if (CreateInfo == NULL) {//处理退出进程消息
    if (true)
    {
      auto eprocess = Process;
      if (AttachPreocess.count(eprocess))//是附加的进程
      {
        auto cemsg = new EventRecord;
        auto dbgmsg = new EventRecord;
        cemsg->e.dwDebugEventCode = EXIT_PROCESS_DEBUG_EVENT;
        cemsg->e.dwProcessId = (DWORD)ProcessId;
        cemsg->e.dwThreadId = (DWORD)0;
        cemsg->e.u.ExitProcess.dwExitCode = 0;
        *dbgmsg = *cemsg;
        if (CEDebugPort[eprocess] != 0)
        {
          HookDbgkApi::SendInitDebugMsg(eprocess, cemsg, 0);
        }
        else
        {
          delete cemsg;
        }
        if (DbgDebugPort[eprocess] != 0)
        {
          HookDbgkApi::SendInitDebugMsg(eprocess, dbgmsg, 1);
        }
        else
        {
          delete dbgmsg;
        }
      }
    }
    if (CEDebugPort.count(Process))
    {
      CEDebugPort[Process] = nullptr;
    }
    if (DbgDebugPort.count(Process))
    {
      DbgDebugPort[Process] = nullptr;
    }
    if (DebugerMainProcess.count(Process))
    {
      DebugerMainProcess.erase(Process);
    }
    if (AttachPreocess.count(Process))
    {
      //退出监视
      mp::ipi_call([](void* context)->void {
        HvppVmCall(DDYInfUnHook, 0, 0, 0);
        }, nullptr);
      //处理完进程退出消息后，Unlock 所有的页
      infbp.RemoveFromMonitor();
    }
  }
  else
  {
    CEDebugPort[Process] = nullptr;
    DbgDebugPort[Process] = nullptr;
  }
  return;
}

void MonitorThreadCreate(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
  if (Create)
  {
    auto eprocess = PsGetCurrentProcess();
    auto ethread = PsGetCurrentThread();
    if (AttachPreocess.count(eprocess))//是附加的进程
    {
      auto cemsg = new EventRecord;
      auto dbgmsg = new EventRecord;
      cemsg->e.dwDebugEventCode = CREATE_THREAD_DEBUG_EVENT;
      cemsg->e.dwProcessId = (DWORD)ProcessId;
      cemsg->e.dwThreadId = (DWORD)ThreadId;
      cemsg->e.u.CreateThread.lpStartAddress = 0;//不要了，我们只要线程句柄并得到它的getset权限
      cemsg->e.u.CreateThread.lpThreadLocalBase = 0;
      ObOpenObjectByPointer(ethread,
        0,
        NULL,
        DBGK_THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        &cemsg->e.u.CreateThread.hThread);

      cemsg->e.u.CreateThread.lpStartAddress = (PVOID) * (PULONG64)((char*)ethread + dbgkapi.DataOffset.Win32StartAddress);//Win7x64会定位到这里
      cemsg->e.u.CreateThread.lpThreadLocalBase = 0;
      cemsg->e.u.CreateThread.hThread = nullptr;

      dbgmsg->e = cemsg->e;
      if (CEDebugPort[eprocess] != 0)
      {
        HookDbgkApi::SendInitDebugMsg(eprocess, cemsg, 0);
      }
      else
      {
        delete cemsg;
      }
      if (DbgDebugPort[eprocess] != 0)
      {
        HookDbgkApi::SendInitDebugMsg(eprocess, dbgmsg, 1);
      }
      else
      {
        delete dbgmsg;
      }
    }
  }
  else
  {
    auto eprocess = PsGetCurrentProcess();
    auto ethread = PsGetCurrentThread();
    if (AttachPreocess.count(eprocess))//是附加的进程
    {
      auto cemsg = new EventRecord;
      auto dbgmsg = new EventRecord;
      cemsg->e.dwDebugEventCode = EXIT_THREAD_DEBUG_EVENT;
      cemsg->e.dwProcessId = (DWORD)ProcessId;
      cemsg->e.dwThreadId = (DWORD)ThreadId;
      cemsg->e.u.ExitThread.dwExitCode = 0;
      dbgmsg->e = cemsg->e;
      if (CEDebugPort[eprocess] != 0)
      {
        HookDbgkApi::SendInitDebugMsg(eprocess, cemsg, 0);
      }
      else
      {
        delete cemsg;
      }
      if (DbgDebugPort[eprocess] != 0)
      {
        HookDbgkApi::SendInitDebugMsg(eprocess, dbgmsg, 1);
      }
      else
      {
        delete dbgmsg;
      }
    }
  }
}
