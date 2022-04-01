#pragma once
#include "undocenum.h"
#include "undocstruct.h"
#ifndef DDYLIB_UNDOCFUN_H_
#define DDYLIB_UNDOCFUN_H_

namespace ddy {

	typedef NTSTATUS(NTAPI* ZWQUERYINFORMATIONPROCESS)(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);

	typedef NTSTATUS(NTAPI* NTQUERYINFORMATIONTHREAD)(
		IN HANDLE ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		IN OUT PVOID ThreadInformation,
		IN ULONG ThreadInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);

	typedef NTSTATUS(NTAPI* NTQUERYOBJECT)(
		IN HANDLE Handle OPTIONAL,
		IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
		OUT PVOID ObjectInformation OPTIONAL,
		IN ULONG ObjectInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);

	typedef NTSTATUS(NTAPI* ZWQUERYSYSTEMINFORMATION)(
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);

	typedef NTSTATUS(NTAPI* NTQUERYSYSTEMINFORMATION)(
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);

	typedef NTSTATUS(NTAPI* NTCLOSE)(
		IN HANDLE Handle
		);

	typedef NTSTATUS(NTAPI* NTGETCONTEXTTHREAD)(
		IN HANDLE ThreadHandle,
		IN OUT PCONTEXT Context
		);

	typedef NTSTATUS(NTAPI* NTSETCONTEXTTHREAD)(
		IN HANDLE ThreadHandle,
		IN PCONTEXT Context
		);

	typedef NTSTATUS(NTAPI* NTCONTINUE)(
		IN PCONTEXT Context,
		BOOLEAN RaiseAlert
		);

	typedef NTSTATUS(NTAPI* NTDUPLICATEOBJECT)(
		IN HANDLE SourceProcessHandle,
		IN HANDLE SourceHandle,
		IN HANDLE TargetProcessHandle,
		OUT PHANDLE TargetHandle,
		IN ACCESS_MASK DesiredAccess OPTIONAL,
		IN ULONG HandleAttributes,
		IN ULONG Options
		);

	typedef NTSTATUS(NTAPI* KERAISEUSEREXCEPTION)(
		IN NTSTATUS ExceptionCode
		);

	typedef NTSTATUS(NTAPI* NTSETINFORMATIONTHREAD)(
		IN HANDLE ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		IN PVOID ThreadInformation,
		IN ULONG ThreadInformationLength
		);

	typedef NTSTATUS(NTAPI* NTSETINFORMATIONPROCESS)(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		IN PVOID ProcessInformation,
		IN ULONG ProcessInformationLength
		);

	typedef NTSTATUS(NTAPI* NTQUERYINFORMATIONPROCESS)(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);

	typedef NTSTATUS(NTAPI* NTSYSTEMDEBUGCONTROL)(
		IN SYSDBG_COMMAND Command,
		IN PVOID InputBuffer OPTIONAL,
		IN ULONG InputBufferLength,
		OUT PVOID OutputBuffer OPTIONAL,
		IN ULONG OutputBufferLength,
		OUT PULONG ReturnLength OPTIONAL
		);

	typedef NTSTATUS(NTAPI* NTOPENPROCESS)(
		PHANDLE ProcessHandle,
		ACCESS_MASK DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PCLIENT_ID ClientId
		);

	typedef ULONG64 (NTAPI* USERQUERYWINDOW)(
		HANDLE hWnd, ULONG64 TypeInformation);

	/// <summary>
	/// 这个函数在win7以上是取Wow64Process的PEB XP取的是WOW64_PROCESS结构体指针
	/// </summary>
	typedef PPEB(NTAPI *PfnPsGetProcessWow64Process)(
		IN PEPROCESS Process);

	/// <summary>
	/// 取x64 Process的Peb
	/// </summary>
	typedef PPEB(NTAPI *PfnPsGetProcessPeb)(
		IN PEPROCESS Process);

	typedef NTSTATUS(NTAPI* PfnPsSuspendProcess)(
		PEPROCESS Process
		);
}

#endif // !DDYLIB_UNDOC_H_
