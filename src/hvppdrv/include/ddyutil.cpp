#include "ntifs.h"
#include <ddyutil.h>
#include "intrin.h"
#include <ntstrsafe.h>
#include <ntdll.h>
using namespace ddy::Ntdll;
using namespace SSDT;


ddy::Util::Util()
{
	UNICODE_STRING routineName;
	RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
	ZwQueryInformationProcess = (ZWQUERYINFORMATIONPROCESS)MmGetSystemRoutineAddress(&routineName);
	//************
	RtlInitUnicodeString(&routineName, L"NtQueryInformationThread");
	NtQueryInformationThread = (NTQUERYINFORMATIONTHREAD)MmGetSystemRoutineAddress(&routineName);
	//************
	RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&routineName);
	//************
	RtlInitUnicodeString(&routineName, L"NtClose");
	NtClose = (NTCLOSE)MmGetSystemRoutineAddress(&routineName);
	//************
	RtlInitUnicodeString(&routineName, L"NtDuplicateObject");
	NtDuplicateObject = (NTDUPLICATEOBJECT)MmGetSystemRoutineAddress(&routineName);
	//************
	RtlInitUnicodeString(&routineName, L"KeRaiseUserException");
	KeRaiseUserException = (KERAISEUSEREXCEPTION)MmGetSystemRoutineAddress(&routineName);
	//************
	RtlInitUnicodeString(&routineName, L"NtSetInformationThread");
	NtSetInformationThread = (NTSETINFORMATIONTHREAD)MmGetSystemRoutineAddress(&routineName);
	//************
	RtlInitUnicodeString(&routineName, L"NtSetInformationProcess");
	NtSetInformationProcess = (NTSETINFORMATIONPROCESS)MmGetSystemRoutineAddress(&routineName);
	//************
	RtlInitUnicodeString(&routineName, L"NtQueryInformationProcess");
	NtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS)MmGetSystemRoutineAddress(&routineName);
	//************
	RtlInitUnicodeString(&routineName, L"PsGetProcessWow64Process");
	PsGetProcessPebWow64 = (decltype(PsGetProcessPebWow64))MmGetSystemRoutineAddress(&routineName);
	//************
	RtlInitUnicodeString(&routineName, L"PsGetProcessPeb");
	PsGetProcessPeb64 = (decltype(PsGetProcessPeb64))MmGetSystemRoutineAddress(&routineName);

	NtQueryObject = (decltype(NtQueryObject))GetFunctionAddress("NtQueryObject");

	NtGetContextThread = (decltype(NtGetContextThread))GetFunctionAddress("NtGetContextThread");

	NtSetContextThread = (decltype(NtSetContextThread))GetFunctionAddress("NtSetContextThread");

	NtContinue = (decltype(NtContinue))GetFunctionAddress("NtContinue");

	NtSystemDebugControl = (decltype(NtSystemDebugControl))GetFunctionAddress("NtSystemDebugControl");
}
ddy::Util::~Util()
{
}
void ddy::Util::Sleep(unsigned int msec)
{
	LARGE_INTEGER time;
	/*原生的是100纳秒为单位，转成微秒*/
	time.QuadPart = -1000;
	time.QuadPart *= msec * 1000;
	time.QuadPart /= 100;
	KeDelayExecutionThread(KernelMode, FALSE, &time);
}

bool ddy::Util::IsSystemProcess()
{
	auto processname = (char*)GetProcessName(PsGetCurrentProcess());
	if (strstr(processname, "explorer") != nullptr ||
		strstr(processname, "csrss") != nullptr ||
		strstr(processname, "MsMpEng") != nullptr ||
		strstr(processname, "svchost") != nullptr ||
		strstr(processname, "Taskmgr") != nullptr ||
		strstr(processname, "WmiPrvSE") != nullptr ||
		strstr(processname, "services") != nullptr ||
		strstr(processname, "ChsIME") != nullptr||
		strstr(processname, "ddy") != nullptr||
		strstr(processname, "DDY") != nullptr)
	{
		return true;
	}
	return false;
}

bool ddy::Util::IsWow64Process(PEPROCESS eprocess)
{
	return this->PsGetProcessPebWow64(eprocess) != 0;
}

PEPROCESS ddy::Util::GetProcessEprocessByProcessId(HANDLE id)
{
	PEPROCESS pe = 0;
	if (NT_SUCCESS(PsLookupProcessByProcessId(id, &pe)))
	{
		ObDereferenceObject(pe);
	}
	return pe;
}

PEPROCESS ddy::Util::GetProcessEprocessByProcessName(PUCHAR imagename)
{
	PEPROCESS eprocess;
	for (size_t i = 4; i < 40000; i += 4)
	{
		_try
		{
			if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)i, &eprocess)))
			{
				if (strcmp(reinterpret_cast<const char*>(GetProcessName(eprocess)), reinterpret_cast<const char*>(imagename)) == 0)
				{
					return eprocess;
				}
				ObDereferenceObject(eprocess);
			}
		}
			__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return 0;
		}
	}
	return 0;
}

PVOID ddy::Util::GetKernelBase(PULONG pImageSize)
{
	PVOID pModuleBase = NULL;
	PSYSTEM_MODULE_INFORMATION pSystemInfoBuffer = NULL;

	ULONG SystemInfoBufferSize = 0;

	ZwQuerySystemInformation(SystemModuleInformation,
		&SystemInfoBufferSize,
		0,
		&SystemInfoBufferSize);

	if (!SystemInfoBufferSize)
	{
		DbgPrint("[TITANHIDE] ZwQuerySystemInformation (1) failed...\r\n");
		return NULL;
	}

	pSystemInfoBuffer = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, SystemInfoBufferSize * 2);

	if (!pSystemInfoBuffer)
	{
		DbgPrint("[TITANHIDE] ExAllocatePool failed...\r\n");
		return NULL;
	}

	memset(pSystemInfoBuffer, 0, SystemInfoBufferSize * 2);

	auto status = ZwQuerySystemInformation(SystemModuleInformation,
		pSystemInfoBuffer,
		SystemInfoBufferSize * 2,
		&SystemInfoBufferSize);

	if (NT_SUCCESS(status))
	{
		pModuleBase = pSystemInfoBuffer->Modules[0].ImageBase;
		if (pImageSize)
			*pImageSize = pSystemInfoBuffer->Modules[0].ImageSize;
	}
	else
		DbgPrint("[TITANHIDE] ZwQuerySystemInformation (2) failed...\r\n");

	ExFreePool(pSystemInfoBuffer);

	return pModuleBase;
}

HANDLE ddy::Util::OpenProcess(IN HANDLE id)
{
	__try
	{
		HANDLE ProcessHandle = 0;
		PEPROCESS selectedprocess;
		selectedprocess = this->GetProcessEprocessByProcessId(id);
		if (selectedprocess)
		{
			ObOpenObjectByPointer(
				selectedprocess,
				0,
				NULL,
				PROCESS_ALL_ACCESS,
				*PsProcessType,
				KernelMode, //UserMode,
				&ProcessHandle);
		}
		return ProcessHandle;
	}
	__except (1)
	{
		return 0;
	}
}

HANDLE ddy::Util::OpenThread(HANDLE ThreadId)
{
	NTSTATUS _status;
	PETHREAD Thread = NULL;

	HANDLE hThread = NULL;

	_status = PsLookupThreadByThreadId(ThreadId, &Thread);

	if (NT_SUCCESS(_status))
	{
		if (PsThreadType)
		{
			_status = ObOpenObjectByPointer(Thread, NULL, NULL, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &hThread);
			if (NT_SUCCESS(_status))
			{
				ObDereferenceObject(Thread);
				return hThread;
			}
		}
	}
	return NULL;
}

ULONG ddy::Util::GetProcessIDFromProcessHandle(HANDLE ProcessHandle)
{
	ULONG Pid = 0;
	PEPROCESS Process;
	if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID*)&Process, nullptr)))
	{
		Pid = (ULONG)(ULONG_PTR)PsGetProcessId(Process);
		ObDereferenceObject(Process);
	}
	return Pid;
}

ULONG ddy::Util::GetProcessIDFromThreadHandle(HANDLE ThreadHandle)
{
	ULONG Pid = 0;
	PETHREAD Thread;
	if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, 0, *PsThreadType, ExGetPreviousMode(), (PVOID*)&Thread, nullptr)))
	{
		Pid = (ULONG)(ULONG_PTR)PsGetProcessId(PsGetThreadProcess(Thread));
		ObDereferenceObject(Thread);
	}
	return Pid;
}

PETHREAD ddy::Util::GetEthread(HANDLE threadid)
{
	PETHREAD Thread = NULL;
	PETHREAD Result = NULL;

	if (PsLookupThreadByThreadId(threadid, &Thread) == STATUS_SUCCESS)
	{
		Result = Thread;
		ObDereferenceObject(Thread);
	}
	return Result;
}

VOID ddy::Util::HideKernelModule(PDRIVER_OBJECT pDriverObject, LPWSTR md)
{
	PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	PLDR_DATA_TABLE_ENTRY firstentry;
	UNICODE_STRING uniDriverName;

	firstentry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	entry = firstentry;
	RtlInitUnicodeString(&uniDriverName, md);

	while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry)
	{
		__try
		{
			if (FsRtlIsNameInExpression(&uniDriverName, &(entry->BaseDllName), TRUE, NULL))
			{
				// 修改 Flink 和 Blink 指针, 以跳过我们要隐藏的驱动
				*((ULONG64*)entry->InLoadOrderLinks.Blink) = (ULONG64)entry->InLoadOrderLinks.Flink;
				entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;
				entry->InLoadOrderLinks.Flink = (LIST_ENTRY*)&(entry->InLoadOrderLinks.Flink);
				entry->InLoadOrderLinks.Blink = (LIST_ENTRY*)&(entry->InLoadOrderLinks.Flink);

				break;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}
		// 链表往前走
		entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}
}

NTSTATUS ddy::Util::MmGetSystemModuleInfo(IN PCHAR modulename, PSYSTEM_MODULE info)
{
	ULONG need = 0;
	NTSTATUS status = STATUS_SUCCESS;
	ZwQuerySystemInformation(ddy::SYSTEM_INFORMATION_CLASS::SystemModuleInformation, 0, 0, &need);
	auto buff = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePool(NonPagedPool, need));
	if (!buff)
	{
		status = STATUS_UNSUCCESSFUL;
		return status;
	}
	status = ZwQuerySystemInformation(ddy::SYSTEM_INFORMATION_CLASS::SystemModuleInformation, buff, need, &need);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("status:%llx\n", status);
		ExFreePool(buff);
	}
	PSYSTEM_MODULE next;
	next = buff->Modules;
	for (size_t i = 0; i < buff->ModulesCount; i++)
	{
		if (strstr(next->ImageName, modulename) != nullptr)
		{
			*info = *next;
			delete buff;
			return STATUS_SUCCESS;
		}
		next++;
	}
	delete buff;
	return status;
}

NTSTATUS ddy::Util::MmGetProcessModuleInfo(IN PEPROCESS eprocess, IN char* modulename, OUT PLDR_DATA_TABLE_ENTRY moduleinfo)
{
	ddy::PPEB pebbase = GetProcessPebByEprocess(eprocess);
	KAPC_STATE apc;
	KeStackAttachProcess(eprocess, &apc);
	ddy::PPEB_LDR_DATA ldr = pebbase->LoaderData;
	ddy::PLDR_DATA_TABLE_ENTRY next, head;
	next = head = (ddy::PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
	do
	{
		UNICODE_STRING tem;
		RtlInitUnicodeString(&tem, (PCWSTR)modulename);
		if (RtlEqualUnicodeString(&next->BaseDllName, &tem, TRUE))
		{
			*moduleinfo = *next;
			return STATUS_SUCCESS;
		}
		next = (ddy::PLDR_DATA_TABLE_ENTRY)next->InLoadOrderLinks.Flink;
	} while (next != head);
	KeUnstackDetachProcess(&apc);
	return STATUS_UNSUCCESSFUL;
}

PVOID64 ddy::Util::GetSystemModuleBase(PDRIVER_OBJECT lpDriverObject, PUNICODE_STRING modulename, ULONG64* size)
{
	UNICODE_STRING ntos;
	if (lpDriverObject == NULL)
	{
		return 0;
	}
	if (modulename == NULL)
	{
		RtlInitUnicodeString(&ntos, L"ntoskrnl.exe");
		modulename = &ntos;
	}
	PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)lpDriverObject->DriverSection;
	//系统模块链表的链表头
	PLDR_DATA_TABLE_ENTRY PsLoadedModuleList = NULL, ListEntry = NULL;
	PsLoadedModuleList = (PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderLinks.Flink;
	ListEntry = (PLDR_DATA_TABLE_ENTRY)PsLoadedModuleList->InLoadOrderLinks.Flink;
	while (ListEntry != PsLoadedModuleList)
	{
		if (&ListEntry->BaseDllName.Buffer != 0) {
			if (RtlCompareUnicodeString(&ListEntry->BaseDllName, modulename, TRUE) == 0)
			{
				*size = ListEntry->SizeOfImage;
				return ListEntry->DllBase;
			}
			//DbgPrint("Nt Module Fileis %wZ\n", &ListEntry->BaseDllName);
		}
		//指向下一个链表
		ListEntry = (PLDR_DATA_TABLE_ENTRY)ListEntry->InLoadOrderLinks.Flink;
	}
	*size = 0;
	return 0;
}

NTSTATUS ddy::Util::MmGetModuleNameForAddress(IN PVOID ProcessVa, OUT PCHAR FileNameBuff)
{
	NTSTATUS status = STATUS_SUCCESS;
	if (FileNameBuff == nullptr)
	{
		return STATUS_UNSUCCESSFUL;
	}
	if (NT_SUCCESS(status))
	{
		ULONG need = 0;
		ZwQuerySystemInformation(ddy::SYSTEM_INFORMATION_CLASS::SystemModuleInformation, 0, 0, &need);
		auto buff = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePool(NonPagedPool, need));
		if (!buff)
		{
			status = STATUS_UNSUCCESSFUL;
			return status;
		}
		status = ZwQuerySystemInformation(ddy::SYSTEM_INFORMATION_CLASS::SystemModuleInformation, buff, need, &need);
		if (!NT_SUCCESS(status))
		{
			ExFreePool(buff);
		}
		PSYSTEM_MODULE next;
		next = buff->Modules;
		for (size_t i = 0; i < buff->ModulesCount; i++)
		{
			if (ProcessVa >= next->ImageBase && (next->ImageSize + (ULONG64)next->ImageBase) >= (ULONG64)ProcessVa)
			{
				strcpy(FileNameBuff, next->ImageName);
				delete buff;
				return STATUS_SUCCESS;
			}
			next++;
		}
		FileNameBuff[0] = '\0';
		delete buff;
		return STATUS_UNSUCCESSFUL;
	}
	return status;
}

NTKERNELAPI extern "C" UCHAR * NTAPI PsGetProcessImageFileName(_In_ PEPROCESS process);

PUCHAR ddy::Util::GetProcessName(PEPROCESS eprocess)
{
	return PsGetProcessImageFileName(eprocess);
}


ddy::PPEB ddy::Util::GetProcessPeb()
{
	ULONG64 sysProc;
	sysProc = (ULONG64)PsGetCurrentProcess();
	/*6.x版本的Peb在+0x338*/
#if WINVER==0x601
	sysProc += 0x338;
#elif WINVER==0xa00
	sysProc += 0x03F8;
#endif // WINVER==0x601
	return (ddy::PPEB)(*(PULONG64)sysProc);
}

ddy::PPEB ddy::Util::GetProcessPebByEprocess(PEPROCESS eprocess)
{
	ULONG64 sysProc;
	sysProc = (ULONG64)eprocess;
	/*6.x版本的Peb在+0x338*/
#if WINVER==0x601
	sysProc += 0x338;
#elif WINVER==0xa00
	sysProc += 0x03F8;
#endif // WINVER==0x601
	return (ddy::PPEB)(*(PULONG64)sysProc);
}

PVOID ddy::Util::GetProcessModuleBase(PUCHAR imagename, PCWSTR modulename)
{
	UNICODE_STRING tem;
	PEPROCESS eprocess = GetProcessEprocessByProcessName(imagename);
	if (!eprocess)
	{
		return 0;
	}
	RtlInitUnicodeString(&tem, modulename);
	PKAPC_STATE apc = static_cast<PKAPC_STATE>(ExAllocatePool(NonPagedPool, sizeof(KAPC_STATE)));
	KeStackAttachProcess(eprocess, apc);
	PPEB peb = (PPEB)GetProcessPebByEprocess(eprocess);
	PPEB_LDR_DATA ldr = peb->LoaderData;
	PLDR_DATA_TABLE_ENTRY next, head;
	PVOID64 ret = 0;
	next = head = (PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;
	do
	{
		if (RtlEqualUnicodeString(&next->BaseDllName, &tem, TRUE))
		{
			ret = next->DllBase;
			break;
		}
		next = (PLDR_DATA_TABLE_ENTRY)next->InLoadOrderLinks.Flink;
	} while (next != head);
	KeUnstackDetachProcess(apc);
	ExFreePool(apc);
	return ret;
}

HANDLE ddy::Util::GetProcessHandleByEprocess(PEPROCESS peprocess)
{
	HANDLE handle = 0;
	ObOpenObjectByPointer(peprocess,
		0,
		0,
		0,
		NULL,
		KernelMode,
		&handle);
	return handle;
}

PVOID ddy::Util::GetKeServiceDescriptorTable()
{
	static SSDTStruct* SSDT = 0;
	if (!SSDT)
	{
#ifndef _WIN64
		//x86 code
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
		SSDT = (SSDTStruct*)MmGetSystemRoutineAddress(&routineName);
#else
		//x64 code
		ULONG kernelSize;
		ULONG_PTR kernelBase = (ULONG_PTR)this->GetKernelBase(&kernelSize);
		if (kernelBase == 0 || kernelSize == 0)
			return NULL;

		// Find KiSystemServiceStart
		const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
		const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
		bool found = false;
		ULONG KiSSSOffset;
		for (KiSSSOffset = 0; KiSSSOffset < kernelSize - signatureSize; KiSSSOffset++)
		{
			if (RtlCompareMemory(((unsigned char*)kernelBase + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
			{
				found = true;
				break;
			}
		}
		if (!found)
			return NULL;

		// lea r10, KeServiceDescriptorTable
		ULONG_PTR address = kernelBase + KiSSSOffset + signatureSize;
		LONG relativeOffset = 0;
		if ((*(unsigned char*)address == 0x4c) &&
			(*(unsigned char*)(address + 1) == 0x8d) &&
			(*(unsigned char*)(address + 2) == 0x15))
		{
			relativeOffset = *(LONG*)(address + 3);
		}
		if (relativeOffset == 0)
			return NULL;

		SSDT = (SSDTStruct*)(address + relativeOffset + 7);
#endif
	}
	return SSDT;
}

PVOID ddy::Util::GetServiceApiAddress(ULONG64 id)
{
	/*
	23h:nt!NtOpenProcess
	ssdt_base+(ssdt_base[id]>>4);
	*/
	PULONG ssdt_base;
	ULONG64 offset;
	SSDTStruct* table = (SSDTStruct*)GetKeServiceDescriptorTable();
	ssdt_base = (PULONG)table->pServiceTable;
	offset = ssdt_base[id] >> 4;
	return (PUCHAR)ssdt_base + offset;
}

PVOID ddy::Util::GetFunctionAddress(const char* apiname)
{
	//read address from SSDT
	SSDTStruct* SSDT = get_ssdt_base_address();
	if (!SSDT)
	{
		DbgPrint("[TITANHIDE] SSDT not found...\r\n");
		return 0;
	}
	ULONG_PTR SSDTbase = (ULONG_PTR)SSDT->pServiceTable;
	if (!SSDTbase)
	{
		DbgPrint("[TITANHIDE] ServiceTable not found...\r\n");
		return 0;
	}
	ULONG readOffset = GetExportSsdtIndex(apiname);
	if (readOffset == -1)
		return 0;
	if (readOffset >= SSDT->NumberOfServices)
	{
		DbgPrint("[TITANHIDE] Invalid read offset...\r\n");
		return 0;
	}
#ifdef _WIN64
	return (PVOID)((SSDT->pServiceTable[readOffset] >> 4) + SSDTbase);
#else
	return (PVOID)SSDT->pServiceTable[readOffset];
#endif
	}

PVOID ddy::Util::GetKeServiceDescriptorTableShadow64()
{
	PUCHAR StartSearchAddress = (PUCHAR)(__readmsr(ddy::IntelMsr::kIa32Lstar));
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	ULONGLONG addr = 0;
	for (i = StartSearchAddress; i < EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x1d) //4c8d1d
			{
				memcpy(&templong, i + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				return (PVOID64)addr;
			}
		}
	}
	return 0;
}


PVOID ddy::Util::GetServiceApiAddressShadow64(ULONG64 id)
{
	PKAPC_STATE apc;
	ULONG64 W32pServiceTable = 0, qwTemp = 0;
	LONG dwTemp = 0;
	SSDTStruct* pWin32k;
	PEPROCESS eprocess = GetProcessEprocessByProcessName((PUCHAR)("csrss.exe"));
	apc = reinterpret_cast<PKAPC_STATE>(ExAllocatePool(NonPagedPool, sizeof(PKAPC_STATE)));
	KeStackAttachProcess(eprocess, apc);
	pWin32k = (SSDTStruct*)((ULONG64)GetKeServiceDescriptorTableShadow64() + sizeof(SSDTStruct));
	W32pServiceTable = (ULONGLONG)(pWin32k->pServiceTable);
	qwTemp = W32pServiceTable + 4 * (id - 0x1000);
	dwTemp = *(PLONG)qwTemp;
	dwTemp = dwTemp >> 4;
	qwTemp = W32pServiceTable + (LONG64)dwTemp;
	KeUnstackDetachProcess(apc);
	ExFreePool(apc);
	return (PVOID64)qwTemp;
}


extern "C"
NTKERNELAPI
PVOID
PsGetProcessDebugPort(
	_In_ PEPROCESS Process
);
PVOID ddy::Util::GetProcessDebugPort(_In_ PEPROCESS Process)
{
	return PsGetProcessDebugPort(Process);
}

PVOID ddy::Util::GetProcessDebugPort_ExitTime(PEPROCESS Process)
{
	return (PVOID) * (ULONG64*)(ULONG64(Process) + 0x170);
}

//必须提供一个大于412字节的buff
BOOLEAN __fastcall ddy::Util::FormatString(char* buff, const char* format, ...)
{
	va_list args;
	va_start(args, format);
	char log_message[412];
	RtlStringCbVPrintfA(log_message, 412, format, args);
	va_end(args);
	if (log_message[0] == '\0')
	{
		return FALSE;
	}
	strcpy(buff, log_message);
	return TRUE;
}

SSDTStruct* ddy::Util::get_ssdt_base_address()
{
	if (ssdt_base_address != nullptr)
	{
		return ssdt_base_address;
	}
	ssdt_base_address = CalculateSsdtBase();
	return ssdt_base_address;
}

//Based on: https://github.com/hfiref0x/WinObjEx64
SSDTStruct* ddy::Util::CalculateSsdtBase()
{
	static SSDTStruct* SSDT = 0;
	if (!SSDT)
	{
#ifndef _WIN64
		//x86 code
		UNICODE_STRING routineName;
		RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
		SSDT = (SSDTStruct*)MmGetSystemRoutineAddress(&routineName);
#else
		//x64 code
		ULONG kernelSize;

		ULONG_PTR kernelBase = (ULONG_PTR)GetKernelBase(&kernelSize);
		if (kernelBase == 0 || kernelSize == 0)
			return NULL;

		// Find KiSystemServiceStart
		const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
		const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
		bool found = false;
		ULONG KiSSSOffset;
		for (KiSSSOffset = 0; KiSSSOffset < kernelSize - signatureSize; KiSSSOffset++)
		{
			if (RtlCompareMemory(((unsigned char*)kernelBase + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
			{
				found = true;
				break;
			}
		}
		if (!found)
			return NULL;

		// lea r10, KeServiceDescriptorTable
		ULONG_PTR address = kernelBase + KiSSSOffset + signatureSize;
		LONG relativeOffset = 0;
		if ((*(unsigned char*)address == 0x4c) &&
			(*(unsigned char*)(address + 1) == 0x8d) &&
			(*(unsigned char*)(address + 2) == 0x15))
		{
			relativeOffset = *(LONG*)(address + 3);
		}
		if (relativeOffset == 0)
			return NULL;
		SSDT = (SSDTStruct*)(address + relativeOffset + 7);
#endif
	}
	return SSDT;
}
