#pragma once
#ifndef DDYLIB_UTIL_H_
#define DDYLIB_UTIL_H_
#include "undocfun.h"
#include "undocstruct.h"
#include "vt.h"
#include "utilenum.h"
#pragma comment(lib,"../lib/Zydis.lib")


namespace SSDT
{
	//structures
	struct SSDTStruct
	{
		LONG* pServiceTable;
		PVOID pCounterTable;
#ifdef _WIN64
		ULONGLONG NumberOfServices;
#else
		ULONG NumberOfServices;
#endif
		PCHAR pArgumentTable;
	};
};

namespace ddy
{
	using namespace SSDT;
	class Util
	{
	public:
		Util();
		~Util();

		void Sleep(unsigned int msec);

		bool IsSystemProcess();

		bool IsWow64Process(PEPROCESS eprocess);

		PEPROCESS GetProcessEprocessByProcessId(HANDLE id);

		PEPROCESS GetProcessEprocessByProcessName(PUCHAR imagename);

		PVOID GetKernelBase(PULONG pImageSize = NULL);

		HANDLE OpenProcess(IN HANDLE id);

		HANDLE OpenThread(HANDLE ThreadId);

		ULONG GetProcessIDFromProcessHandle(HANDLE ProcessHandle);

		ULONG GetProcessIDFromThreadHandle(HANDLE ThreadHandle);

		PETHREAD GetEthread(HANDLE threadid);

		VOID HideKernelModule(PDRIVER_OBJECT pDriverObject, LPWSTR md);

		NTSTATUS MmGetSystemModuleInfo(IN PCHAR modulename, PSYSTEM_MODULE info);

		NTSTATUS MmGetProcessModuleInfo(IN PEPROCESS eprocess, IN char* modulename, OUT PLDR_DATA_TABLE_ENTRY moduleinfo);

		PVOID64 GetSystemModuleBase(PDRIVER_OBJECT lpDriverObject, PUNICODE_STRING modulename, ULONG64 *size);

		NTSTATUS MmGetModuleNameForAddress(IN PVOID ProcessVa, OUT PCHAR FileNameBuff);

		PUCHAR GetProcessName(PEPROCESS eprocess);

		ddy::PPEB GetProcessPeb();

		ddy::PPEB GetProcessPebByEprocess(PEPROCESS eprocess);

		PVOID GetProcessModuleBase(PUCHAR imagename, PCWSTR modulename);

		HANDLE GetProcessHandleByEprocess(PEPROCESS peprocess);

		ZWQUERYINFORMATIONPROCESS ZwQueryInformationProcess;

		NTQUERYINFORMATIONTHREAD NtQueryInformationThread;

		NTQUERYOBJECT NtQueryObject;

		ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;

		NTQUERYSYSTEMINFORMATION NtQSI;

		NTCLOSE NtClose;

		NTSETCONTEXTTHREAD NtGetContextThread;

		NTSETCONTEXTTHREAD NtSetContextThread;

		NTCONTINUE NtContinue;

		NTDUPLICATEOBJECT NtDuplicateObject;

		KERAISEUSEREXCEPTION KeRaiseUserException;

		NTSETINFORMATIONTHREAD NtSetInformationThread;

		NTSETINFORMATIONPROCESS NtSetInformationProcess;

		NTQUERYINFORMATIONPROCESS NtQueryInformationProcess;

		NTSYSTEMDEBUGCONTROL NtSystemDebugControl;

		PfnPsGetProcessWow64Process PsGetProcessPebWow64;

		PfnPsGetProcessPeb PsGetProcessPeb64;


		SSDTStruct* ssdt_base_address = nullptr;
		SSDTStruct* get_ssdt_base_address();
		SSDTStruct* CalculateSsdtBase();

		PVOID GetKeServiceDescriptorTable();
		PVOID GetServiceApiAddress(ULONG64 id);
		PVOID GetFunctionAddress(const char* apiname);
		PVOID GetKeServiceDescriptorTableShadow64();
		PVOID GetServiceApiAddressShadow64(ULONG64 id);

		PVOID GetProcessDebugPort(_In_ PEPROCESS Process);
		PVOID GetProcessDebugPort_ExitTime(_In_ PEPROCESS Process);

		BOOLEAN __fastcall FormatString(char* buff, const char* format, ...);
	};
}
#endif // !DDYLIB_UTIL_H_
