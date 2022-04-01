#pragma once
#include <ntifs.h>
#include "MemoryHide.h"
#include <undocstruct.h>
#include "winbase.h"
#include <EASTL/map.h>
#include <EASTL/set.h>
using namespace eastl;


#define PROCESS_ADD_ANTIDEBUG \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x100+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_GET_ANTIDEBUG \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x101+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_CHANGE_HANDLE_ACCESS \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x201+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_DELETE_EXECUTE_MONITOR \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x202+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_HIDE_FILE \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x203+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_SHOW_FILE \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x204+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_DEBUG_STEPRET \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x205+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_DEBUG_STEPCONTINUE \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x206+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_IsWoW64 \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x102+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_OPENHANDLE \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x103+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define THREAD_OPENHANDLE \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x109+0x35, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_LOGIN_GET_API_OFFSET \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x104+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_PROTECT_HIDE_OB \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x105+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_REMOVE_PROTECT_HIDE_OB \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x106+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_MODIFY_API \
 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x151+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PROCESS_DebugActiveProcess \
 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x351+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PROCESS_WaitForDebugEvent \
 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x451+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PROCESS_ContinueDebugEvent \
 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x551+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DebugSetBreakPoint \
 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x651+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DebugRemoveBreakPoint \
 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x561+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PROCESS_CONF \
 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x566+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)



NTSTATUS ControlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void MonitorProcessExit(PEPROCESS Process, HANDLE ProcessId,
  PPS_CREATE_NOTIFY_INFO CreateInfo);
void MonitorThreadCreate(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);



union InputOutputData {
  char all[0x1000];
  struct {
    ULONG64 pid;
    PVOID va;
    char username[32];
    char password[32];
    int targetip;
  } Monitor;
  struct {
    int status_code;
  } Ret;
  struct {
    ULONG64 pid;
    HANDLE phandle;
  }Handle;
  struct
  {
    BOOLEAN protect;
  }Protect;
  struct
  {
    DWORD dwProcessId;
    DWORD flags;//0是ce；1是xdbg
  }ParamDebugActiveProcess;
  struct
  {
    DEBUG_EVENT DebugEvent;
    DWORD   dwMilliseconds;
    DWORD dwProcessId;
    DWORD flags;
    BOOLEAN OK;
  }ParamWaitForDebugEvent;
  struct
  {
    DWORD dwProcessId;
    DWORD dwThreadId;
    DWORD dwContinueStatus;
    DWORD flags;
    BOOLEAN OK;
  }ParamContinueDebugEvent;
  struct
  {
    DWORD64 hThread;
    DWORD ProcessId;
    CONTEXT *Context;
    BOOLEAN OK;
  }SetGetThreadContext;
  struct
  {
    DWORD32 DebugCount;
  }Anti;
  struct
  {
    DWORD64 hThread;
    DWORD ProcessId;
  }HandleTable;
  struct
  {
    LIST_ENTRY ListEntry;
    WCHAR File_Path[500];
    WCHAR File_Name[500];
  }RULE_FILE_PATH;
  struct
  {
    DWORD processid;
    ULONG64 address;
    int size;
    bool active;
    /*统一读写属性，没有执行*/
  }BreakPoint;
  struct
  {
    bool use_ept;
    bool use_mode;
    bool antireference;
    bool protectdebuger;
    bool performance;
    bool antihardware;
    bool disablethread;
    bool supercontext;
  }Conf;
};

class DeviceOBJ {
public:
  typedef struct HookData {
    EptCommonEntry po;//原来的代码段Ept
    PMDL mdl_o;
    PVOID va_o;     //原来的代码页的虚拟地址
    ULONG64 phy_o;  //原来的代码页物理地址
    PEPROCESS eprocess;  //当前锁定的页面是哪个进程的
  };
public:
  DeviceOBJ(PDRIVER_OBJECT DriverObject);
  ~DeviceOBJ();

private:
  const wchar_t* DEVICE_OBJECT_NAME = L"\\Device\\DDYBUFFERIO";
  const wchar_t* DEVICE_LINK_NAME = L"\\DosDevices\\DDYIOLINK";
  PDEVICE_OBJECT DeviceObject{ 0 };
};

inline DeviceOBJ::DeviceOBJ(PDRIVER_OBJECT DriverObject) {
  UNICODE_STRING DeviceObjectName;

  //创建设备对象名称
  RtlInitUnicodeString(&DeviceObjectName, DEVICE_OBJECT_NAME);

  //创建设备对象
  auto Status = IoCreateDevice(DriverObject, NULL, &DeviceObjectName,
    FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
  DeviceObject->Flags |= DO_BUFFERED_IO /*| DO_DIRECT_IO*/;
  if (!NT_SUCCESS(Status)) {
    return;
  }

  UNICODE_STRING DeviceLinkName;
  //创建设备连接名称
  RtlInitUnicodeString(&DeviceLinkName, DEVICE_LINK_NAME);
  //将设备连接名称与设备名称关联
  Status = IoCreateSymbolicLink(&DeviceLinkName, &DeviceObjectName);

  if (!NT_SUCCESS(Status)) {
    IoDeleteDevice(DeviceObject);
    return;
  }

  //关闭证书认证
  ddy::LDR_DATA_TABLE_ENTRY* ldr =
    (ddy::LDR_DATA_TABLE_ENTRY*)DriverObject->DriverSection;
  ldr->Flags |= 0x20;
  NT_SUCCESS(PsSetCreateProcessNotifyRoutineEx(MonitorProcessExit, FALSE));

  //PsSetCreateThreadNotifyRoutine(MonitorThreadCreate);

  for (size_t i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
    DriverObject->MajorFunction[i] = [](PDEVICE_OBJECT DeviceObject,
      PIRP Irp) -> NTSTATUS {
        Irp->IoStatus.Status = STATUS_SUCCESS;    // LastError()
        Irp->IoStatus.Information = 0;            // ReturnLength
        IoCompleteRequest(Irp, IO_NO_INCREMENT);  //将Irp返回给Io管理器
        return STATUS_SUCCESS;
    };
  }

  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ControlDispatch;

  return;
}

inline DeviceOBJ::~DeviceOBJ() {
  UNICODE_STRING DeviceLinkName;
  //创建设备连接名称
  RtlInitUnicodeString(&DeviceLinkName, DEVICE_LINK_NAME);
  IoDeleteSymbolicLink(&DeviceLinkName);
  IoDeleteDevice(DeviceObject);
  PsSetCreateProcessNotifyRoutineEx(MonitorProcessExit, TRUE);
  //PsRemoveCreateThreadNotifyRoutine(MonitorThreadCreate);
}
