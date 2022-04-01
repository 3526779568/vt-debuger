#pragma once
#include "ntddk.h"
#ifndef DDYLIB_UNDOCSTRUCT_H_
#define DDYLIB_UNDOCSTRUCT_H_
namespace ddy
{
	//structures
	typedef struct _OBJECT_TYPE_INFORMATION
	{
		UNICODE_STRING TypeName;
		ULONG TotalNumberOfHandles;
		ULONG TotalNumberOfObjects;
	} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

	typedef struct _OBJECT_ALL_INFORMATION
	{
		ULONG NumberOfObjects;
		OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
	} OBJECT_ALL_INFORMATION, *POBJECT_ALL_INFORMATION;

	typedef struct _SYSTEM_THREAD_INFORMATION
	{
		LARGE_INTEGER KernelTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER CreateTime;
		ULONG WaitTime;
		PVOID StartAddress;
		CLIENT_ID ClientId;
		KPRIORITY Priority;
		LONG BasePriority;
		ULONG ContextSwitches;
		ULONG ThreadState;
		KWAIT_REASON WaitReason;
	}SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

	typedef struct _SYSTEM_PROCESS_INFO
	{
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		LARGE_INTEGER WorkingSetPrivateSize;
		ULONG HardFaultCount;
		ULONG NumberOfThreadsHighWatermark;
		ULONGLONG CycleTime;
		LARGE_INTEGER CreateTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER KernelTime;
		UNICODE_STRING ImageName;
		KPRIORITY BasePriority;
		HANDLE UniqueProcessId;
		HANDLE InheritedFromUniqueProcessId;
		ULONG HandleCount;
		ULONG SessionId;
		ULONG_PTR UniqueProcessKey;
		SIZE_T PeakVirtualSize;
		SIZE_T VirtualSize;
		ULONG PageFaultCount;
		SIZE_T PeakWorkingSetSize;
		SIZE_T WorkingSetSize;
		SIZE_T QuotaPeakPagedPoolUsage;
		SIZE_T QuotaPagedPoolUsage;
		SIZE_T QuotaPeakNonPagedPoolUsage;
		SIZE_T QuotaNonPagedPoolUsage;
		SIZE_T PagefileUsage;
		SIZE_T PeakPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER ReadOperationCount;
		LARGE_INTEGER WriteOperationCount;
		LARGE_INTEGER OtherOperationCount;
		LARGE_INTEGER ReadTransferCount;
		LARGE_INTEGER WriteTransferCount;
		LARGE_INTEGER OtherTransferCount;
		SYSTEM_THREAD_INFORMATION Threads[1];
	}SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

	typedef struct _RTL_PROCESS_MODULE_INFORMATION {
		HANDLE Section;                 // Not filled in
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR  ImageName[MAXIMUM_FILENAME_LENGTH];
	} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES {
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

	typedef struct _SYSTEM_MODULE
	{
		HANDLE Section;
		PVOID  MappedBase;
		PVOID  ImageBase;
		ULONG  ImageSize;
		ULONG  Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		CHAR   ImageName[256];
	} SYSTEM_MODULE, *PSYSTEM_MODULE;

	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG         ModulesCount;
		SYSTEM_MODULE Modules[1];
	} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

	typedef struct _PEB_LDR_DATA {
		ULONG32 Length;
		UCHAR Initialized[4];
		PVOID64 SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID64 EntryInProgress;
		UCHAR ShutdownInProgress[8];
		PVOID64 ShutdownThreadId;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;
	static_assert(sizeof(PEB_LDR_DATA) == 0x58, "");

	typedef struct _PEB {
		CHAR Reserved1[2];
		CHAR BeingDebugged;
		CHAR Reserved2[21];
		PPEB_LDR_DATA LoaderData;
		PVOID64 ProcessParameters;
		CHAR Reserved3[520];
		ULONG PostProcessInitRoutine;
		CHAR Reserved4[136];
		ULONG SessionId;
	}PEB, *PPEB;


	typedef struct _PROCESS_BASIC_INFORMATION {
		NTSTATUS ExitStatus;
		PPEB PebBaseAddress;
		ULONG_PTR AffinityMask;
		KPRIORITY BasePriority;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR InheritedFromUniqueProcessId;
	} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

	typedef struct _PROCESS_EXTENDED_BASIC_INFORMATION {
		SIZE_T Size;    // Ignored as input, written with structure size on output
		PROCESS_BASIC_INFORMATION BasicInfo;
		union {
			ULONG Flags;
			struct {
				ULONG IsProtectedProcess : 1;
				ULONG IsWow64Process : 1;
				ULONG IsProcessDeleting : 1;
				ULONG IsCrossSessionCreate : 1;
				ULONG IsFrozen : 1;
				ULONG IsBackground : 1;
				ULONG IsStronglyNamed : 1;
				ULONG IsSecureProcess : 1;
				ULONG IsSubsystemProcess : 1;
				ULONG SpareBits : 23;
			};
		};
	} PROCESS_EXTENDED_BASIC_INFORMATION, *PPROCESS_EXTENDED_BASIC_INFORMATION;

	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID64 DllBase;
		PVOID64 EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		UINT32 Flags;
		UINT16 LoadCount;
		UINT16 TlsIndex;
		union
		{
			LIST_ENTRY HashLinks;
			PVOID64 SectionPointer;
		};
		ULONG32 CheckSum;
		union
		{
			ULONG32 TimeDateStamp;
			PVOID64 LoadedImports;
		};
		PVOID64 EntryPointActivationContext;
		PVOID64 PatchInformation;
		LIST_ENTRY ForwarderLinks;
		LIST_ENTRY ServiceTagLinks;
		LIST_ENTRY StaticLinks;
		PVOID64 ContextInformation;
		ULONG64 OriginalBase;
		LARGE_INTEGER LoadTime;
	}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


	// WOW64_CONTEXT is not undocumented, but it's missing from the WDK
#define WOW64_SIZE_OF_80387_REGISTERS 80
#define WOW64_MAXIMUM_SUPPORTED_EXTENSION 512

	typedef struct _WOW64_FLOATING_SAVE_AREA
	{
		ULONG ControlWord;
		ULONG StatusWord;
		ULONG TagWord;
		ULONG ErrorOffset;
		ULONG ErrorSelector;
		ULONG DataOffset;
		ULONG DataSelector;
		UCHAR RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
		ULONG Cr0NpxState;
	} WOW64_FLOATING_SAVE_AREA, *PWOW64_FLOATING_SAVE_AREA;

#pragma pack(push, 4)

	typedef struct _WOW64_CONTEXT
	{
		ULONG ContextFlags;

		ULONG Dr0;
		ULONG Dr1;
		ULONG Dr2;
		ULONG Dr3;
		ULONG Dr6;
		ULONG Dr7;

		WOW64_FLOATING_SAVE_AREA FloatSave;

		ULONG SegGs;
		ULONG SegFs;
		ULONG SegEs;
		ULONG SegDs;

		ULONG Edi;
		ULONG Esi;
		ULONG Ebx;
		ULONG Edx;
		ULONG Ecx;
		ULONG Eax;

		ULONG Ebp;
		ULONG Eip;
		ULONG SegCs;
		ULONG EFlags;
		ULONG Esp;
		ULONG SegSs;

		UCHAR ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];

	} WOW64_CONTEXT;
#pragma pack(pop)
	typedef WOW64_CONTEXT* PWOW64_CONTEXT;

	struct _OBJECT_TYPE_INITIALIZER
	{
		unsigned char unknow1[0x1c];
		unsigned int ValidAccessMask;
		unsigned char unknow2[0x50];
	};
	static_assert(sizeof(_OBJECT_TYPE_INITIALIZER) == 0x70, "aaa");

	struct _OBJECT_TYPE
	{
		unsigned char unknow1[0x040];
		_OBJECT_TYPE_INITIALIZER obj_type;
		unsigned char unknow2[0x20];
	};
	typedef _OBJECT_TYPE *P_OBJECT_TYPE;
	static_assert(sizeof(_OBJECT_TYPE) == 0xd0, "aaa");

	typedef struct KPRCB__
	{
		UCHAR reserved1[0x8];
		PKTHREAD CurrentThread;
		PKTHREAD NextThread;
		PKTHREAD IdleThread;
		UCHAR reserved2[0x4714];
		USHORT KeExceptionDispatchCount;
		UCHAR reserved3[0x490];
		ULONG FeatureBits;
		UCHAR reservid4[0x134];
	}KPRCB__, *PKPRCB__;
	static_assert(sizeof(KPRCB__) == 0x4d00, "no eq");

	typedef struct
	{
		UCHAR reserved1[0x180];
		KPRCB__ prcb;
	}KPCR_, *PKPCR_;

	typedef struct
	{
		char pcb[0x160];
	}KPROCESS_;
	typedef struct
	{
		KPROCESS_ pcb;
		char reserved1[0x90];
		PVOID64 DebugPort;
		char reserved2[0x140];
		PVOID64 peb;
		char reservid3[0x190];
	}EPROCESS_, *PEPROCESS_;
	static_assert(sizeof(EPROCESS_) == 0x4d0, "no eq");

	typedef struct ETHREAD_
	{
		char Tcb[0x360];
		char reserved1[0xE8];
		ULONG64 CrossThreadFlags;
		char reserved2[0x498 - 0x448 - 8];
	}ETHREAD_, *PETHREAD_;
	static_assert(sizeof(ETHREAD_) == 0x498, "no eq");

	typedef struct _CALLBACK_ENTRY
	{
		ULONG64 Unknow;
		ULONG64 Unknow1;
		UNICODE_STRING AltitudeString;
		LIST_ENTRY NextEntryItemList; //(callbacklist) 跟上面开头的那个一样 存储下一个callbacklist
		ULONG64 Operations;
		PVOID ObHandle; //存储详细的数据 版本号 POB_OPERATION_REGISTRATION AltitudeString 也就是本身节点CALL_BACK_INFO 注销时也使用这个 注意是指针 //CALL_BACK_INFO
		PVOID ObjectType;
		ULONG64 PreCallbackAddr;
		ULONG64 PostCallbackAddr;
	}CALLBACK_ENTRY, *PCALLBACK_ENTRY;

	typedef struct _CALLBACK_ENTRY_ITEM {
		LIST_ENTRY EntryItemList;
		OB_OPERATION Operations;
		PCALLBACK_ENTRY CallbackEntry;
		POBJECT_TYPE ObjectType;
		POB_PRE_OPERATION_CALLBACK PreOperation;
		POB_POST_OPERATION_CALLBACK PostOperation;
		__int64 unk;
	}CALLBACK_ENTRY_ITEM, *PCALLBACK_ENTRY_ITEM;

	typedef struct _OBCALLBACK
	{
		LIST_ENTRY nextcallback;
		POB_PRE_OPERATION_CALLBACK PreOperation;
	}OBCALLBACK, *POBCALLBACK;
}
#endif // !DDYLIB_UNDOCSTRUCT_H_
