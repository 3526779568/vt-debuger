#include "DbgApi.h"

#include <ddyutil.h>

#include <cr3.h>

#include <EASTL/set.h>
#include <EASTL/map.h>
//#include <intrin.h>

#include <Zydis/Zydis.h>
#include "SsdtHook.h"
#include <ntstrsafe.h>
#include "MemoryHide.h"
#include "../hvpp/hvpp/lib/mp.h"
using namespace eastl;
using namespace ddy;
extern MemoryHide hide;
extern ddy::Util util;
map<PEPROCESS, PVOID> CEDebugPort;
map<PEPROCESS, PVOID> DbgDebugPort;
SSDTHook* ssdthook = nullptr;


extern "C"
{

	DbgkKernel::DbgkKernel()
	{
	}
	void DbgkKernel::InitVersionApi()
	{
		kernelbase = util.GetKernelBase(&kernelsize);
		RtlGetVersion(&ver);
    this->GetWindowsApiOffset();
    this->GetWindowsStructOffset();
	}

	void DbgkKernel::GetWindowsApiOffset()
	{
		//填充API
    //自己按特定操作系统修改
		this->DbgkForwardException = decltype(this->DbgkForwardException)(0);
		this->NtQueryInformationThread = decltype(this->NtQueryInformationThread)(0);
		this->NtGetContextThread = decltype(this->NtGetContextThread)(0);
		this->NtSetContextThread = decltype(this->NtSetContextThread)(0);
		this->NtSetInformationThread = decltype(this->NtSetInformationThread)(0);
		this->NtQueryInformationProcess = decltype(this->NtQueryInformationProcess)(0);
		this->NtReadVirtualMemory = decltype(this->NtReadVirtualMemory)(0);
		this->NtWriteVirtualMemory = decltype(this->NtWriteVirtualMemory)(0);
		this->NtDebugActiveProcess = decltype(this->NtDebugActiveProcess)(0);
		this->PsSuspendProcess = decltype(this->PsSuspendProcess)(0);
		this->PsResumeProcess = decltype(this->PsResumeProcess)(0);
		this->ZwFlushInstructionCache = decltype(this->ZwFlushInstructionCache)(0);
		this->PsGetNextProcessThread = decltype(this->PsGetNextProcessThread)(0);
		this->DbgkpSectionToFileHandle = decltype(this->DbgkpSectionToFileHandle)(0);
		this->ObDuplicateObject = decltype(this->ObDuplicateObject)(0);
		this->MmGetFileNameForAddress = decltype(this->MmGetFileNameForAddress)(0);
		this->PsSuspendThread = decltype(this->PsSuspendThread)(0);
		this->PsResumeThread = decltype(this->PsResumeThread)(0);
	}

	void DbgkKernel::GetWindowsStructOffset()
	{
    //自己按特定操作系统修改
		this->DataOffset.ObjectTable = 0;
		this->DataOffset.SectionBaseAddress = 0;
		this->DataOffset.SectionObject = 0;
		this->DataOffset.Win32StartAddress = 0;
		this->DataOffset.PreviousMode = 0;
	}

	DbgkKernel::~DbgkKernel()
	{
	}

	KIRQL WPOFFx64()
	{
		KIRQL irql = KeRaiseIrqlToDpcLevel();
		UINT64 cr0 = __readcr0();
		cr0 &= 0xfffffffffffeffff;
		__writecr0(cr0);
		_disable();
		return irql;
	}

	void WPONx64(KIRQL irql)
	{
		UINT64 cr0 = __readcr0();
		cr0 |= 0x10000;
		_enable();
		__writecr0(cr0);
		KeLowerIrql(irql);
	}


	void DbgkKernel::HideAll()
	{
		//SSDT hook在调试流程hook后
		ssdthook = new SSDTHook;
		ssdthook->BeginHookSSDT();
	}
	/// <summary>
	/// 把当前进程的所有线程都给暂停了，但是保留参数指定的线程
	/// </summary>
	/// <param name="Thread">活动线程</param>
	void DbgkKernel::SuspenAllThreadWithoutThread(PETHREAD Thread)
	{
		PEPROCESS eprocess = (PEPROCESS)PsGetCurrentProcess();
		PETHREAD firstThread = this->PsGetNextProcessThread(eprocess, NULL);
		for (auto FindThread = firstThread;
			FindThread != NULL;
			FindThread = this->PsGetNextProcessThread(eprocess, FindThread))
		{
			if (FindThread == Thread || IoIsSystemThread(FindThread))
			{
				//这个不要暂停了
				continue;
			}
			this->PsSuspendThread(FindThread, NULL);
		}
	}
	/// <summary>
	/// 把当前进程的所有线程都给恢复了，但是保留参数指定的线程
	/// </summary>
	/// <param name="Thread">活动线程</param>
	void DbgkKernel::ResumeAllThreadWithoutThread(PETHREAD Thread)
	{
    PEPROCESS eprocess = (PEPROCESS)PsGetCurrentProcess();
		PETHREAD firstThread = this->PsGetNextProcessThread(eprocess, NULL);
		for (auto FindThread = firstThread;
			FindThread != NULL;
			FindThread = this->PsGetNextProcessThread(eprocess, FindThread))
		{
			if (FindThread == Thread || IoIsSystemThread(FindThread))
			{
				//这个不要处理了
				continue;
			}
			this->PsResumeThread(FindThread, NULL);
		}
	}
}
