#ifndef DBGAPI_H_
#define DBGAPI_H_
#pragma once
#include <ntifs.h>
#include <Zydis/Zydis.h>

namespace ddy
{
  class DbgkKernel
  {
  public:
    DbgkKernel();
    void InitVersionApi();
    void GetWindowsApiOffset();
    void GetWindowsStructOffset();
    ~DbgkKernel();
    void HideAll();
  public:
    BOOLEAN result = FALSE;
    PVOID kernelbase;
    ULONG kernelsize;
    ULONG64 BugNumber;
    RTL_OSVERSIONINFOW ver;
    ULONG ApiOffset[100] = { 0 };
    ULONG StructOffset[100] = { 0 };

    struct
    {
      ULONG Win32StartAddress;
      ULONG ObjectTable;
      ULONG SectionObject;
      ULONG SectionBaseAddress;
      ULONG PreviousMode;
    }DataOffset;


    BOOLEAN
    (*DbgkForwardException)(
      IN PEXCEPTION_RECORD ExceptionRecord,
      IN BOOLEAN DebugException,
      IN BOOLEAN SecondChance);

    NTSTATUS(*NtQueryInformationThread)(
      HANDLE          ThreadHandle,
      THREADINFOCLASS ThreadInformationClass,
      PVOID           ThreadInformation,
      ULONG           ThreadInformationLength,
      PULONG          ReturnLength);

    NTSTATUS(*NtDebugActiveProcess)(
      HANDLE ProcessHandle, HANDLE DebugObjectHandle);

    NTSTATUS(*NtSetContextThread)(
      __in HANDLE ThreadHandle,
      __in PCONTEXT ThreadContext);

    NTSTATUS(*NtSetInformationThread)(
      HANDLE threadHandle,
      THREADINFOCLASS threadInformationClass,
      PVOID threadInformation,
      ULONG threadInformationLength);

    NTSTATUS(*NtGetContextThread)(
      IN HANDLE ThreadHandle,
      IN OUT PCONTEXT Context);

    NTSTATUS(*NtQueryInformationProcess)(
      _In_ HANDLE ProcessHandle,
      _In_ PROCESSINFOCLASS ProcessInformationClass,
      _Out_ PVOID ProcessInformation,
      _In_ ULONG ProcessInformationLength,
      _Out_opt_ PULONG ReturnLength);

    NTSTATUS(*NtReadVirtualMemory)(
      _In_ HANDLE ProcessHandle,
      _In_opt_ PVOID BaseAddress,
      _Out_ PVOID Buffer,
      _In_ SIZE_T BufferSize,
      _Out_opt_ PSIZE_T NumberOfBytesRead);

    NTSTATUS(*NtWriteVirtualMemory)(
      HANDLE ProcessHandle,
      PVOID BaseAddress,
      VOID* Buffer,
      SIZE_T BufferSize,
      PSIZE_T NumberOfBytesWritten);

    PETHREAD(*PsGetNextProcessThread)(
      IN PEPROCESS Process,
      IN PETHREAD Thread);

    HANDLE(*DbgkpSectionToFileHandle)(
      IN PVOID SectionObject);

    NTSTATUS(*PsSuspendProcess)(
      PEPROCESS Process);

    NTSTATUS(*PsResumeProcess)(
      PEPROCESS Process);

    NTSTATUS(*PsSuspendThread)(
      PETHREAD Thread,
      OUT PULONG PreviousSuspendCount OPTIONAL);

    NTSTATUS(*PsResumeThread)(
      PETHREAD Thread,
      OUT PULONG PreviousSuspendCount OPTIONAL);

    NTSTATUS(*MmGetFileNameForAddress)(
      IN PVOID ProcessVa,
      OUT PUNICODE_STRING FileName);

    NTSTATUS(*ObDuplicateObject)(
      IN PEPROCESS SourceProcess,
      IN HANDLE SourceHandle,
      IN PEPROCESS TargetProcess OPTIONAL,
      OUT PHANDLE TargetHandle OPTIONAL,
      IN ACCESS_MASK DesiredAccess,
      IN ULONG HandleAttributes,
      IN ULONG Options,
      IN KPROCESSOR_MODE PreviousMode);

    int (*ZwFlushInstructionCache)(
      HANDLE Process,
      PVOID BaseAddress,
      SIZE_T size);

    void SuspenAllThreadWithoutThread(PETHREAD Thread);
    void ResumeAllThreadWithoutThread(PETHREAD Thread);

  private:

  };
}
#endif // !DBGAPI_H_
