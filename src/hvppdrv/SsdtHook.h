#pragma once
#include <ntifs.h>
#include <EASTL/set.h>
#include <EASTL/map.h>
#include <ddyutil.h>
#include <cr3.h>
#include "MemoryHide.h"
#include <Zydis/Zydis.h>
using namespace eastl;

extern 	ddy::Util util;
extern 	MemoryHide hide;
NTKERNELAPI extern "C" UCHAR * NTAPI PsGetProcessImageFileName(_In_ PEPROCESS process);
extern "C" NTSTATUS NTAPI PreNtReadVirtualMemory(_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead);

extern "C" NTSTATUS NTAPI PreNtWriteVirtualMemory(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	CONST VOID * Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesWritten
);


extern "C" NTSTATUS NTAPI PreNtQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS NTAPI PreNtGetContextThread(
	IN HANDLE ThreadHandle,
	IN OUT PCONTEXT Context);

extern "C" NTSTATUS NTAPI PreNtSetContextThread(
	IN HANDLE ThreadHandle,
	IN OUT PCONTEXT Context);

extern "C" NTSTATUS NTAPI PreNtSetInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength);

extern "C" NTSTATUS PreNtDebugActiveProcess(IN HANDLE ProcessHandle, IN HANDLE DebugObjectHandle);

extern "C" NTSTATUS PreNtQueryInformationProcess(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_ PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
);

extern "C" void PreKiDispatchException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PKTRAP_FRAME TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance
);

extern "C" BOOLEAN PreDbgkForwardException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN BOOLEAN DebugException,
	IN BOOLEAN SecondChance
);

class SSDTHook
{
public:
	SSDTHook();
	void InitHook();
	void BeginHookSSDT();
	void ParseApi();
	void InstallHookApi(uint64_t& instructionPointer, const PVOID& api, const PVOID& detour, ZydisDecoder& decoder, ZydisDecodedInstruction& instruction);
	~SSDTHook();
public:
	map<PVOID, PVOID> ssdtpoint;
	map<PVOID, set<PVOID>> page_split;

private:

};

void SuperGetContext(const PCONTEXT& Context,PETHREAD ThreadObject);
