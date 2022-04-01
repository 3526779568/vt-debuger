#pragma once
#pragma warning(disable:4267)
#pragma warning(disable:4075)
#pragma comment(lib,"../lib/Zydis.lib")

#define ZYAN_NO_LIBC
#define ZYDIS_NO_LIBC
#define ZYCORE_STATIC_DEFINE
#define ZYDIS_STATIC_DEFINE

#include "ddyutil.h"
#include "cr3.h"
#include "undocfun.h"
#include "intel_code.h"


#include "Zydis/Zydis.h"
#include "EASTL/vector.h"
#include "EASTL/map.h"
using namespace eastl;

#ifndef DDYLIB_HOOK_H_
#define DDYLIB_HOOK_H_
namespace ddy
{
#pragma pack(push,1)
	struct FarJmp
	{
		unsigned char mov[2] = { 0x48,0xB8 };
		unsigned long long rip = 0;
		unsigned char push = 0x50;
		unsigned char ret = 0xC3;
	};

	struct RetJmp
	{
		unsigned char sub_rsp[4] = { 0x48,0x83,0xEC,0x08 };
		struct
		{
			unsigned char mov_rsp[3] = { 0xC7,0x04,0x24 };
			unsigned int value;
		}L;
		struct
		{
			unsigned char mov_rsp[4] = { 0xC7,0x44,0x24,0x04 };
			unsigned int value;
		}H;
		char ret = 0xC3;
	};
	static_assert(sizeof(RetJmp) == 20, "error size");
#pragma pack(pop)

	struct VtMTF
	{
		void * pte;
		bool is_code;
		bool is_data;
	};

	struct InstructionInfo {
		ZydisDecodedInstruction instruction;
		unsigned long offset;
		ZyanU64 runtime_address;
		unsigned char origin_code[20];
	};

	class Hook
	{
	public:
		Hook(void* origin_fun, void * new_fun);
		~Hook();
		void UnHook();
	public:
		void print_intel_asm(void * origin_fun);

	private:
		bool WeatherCanHook();
		void SaveOriginCode();
		unsigned long GetDisasmCodesLength();
		void InitTrampoline();
		void ResumeOriginFun();

	private:
		vector<InstructionInfo*> instruction;
		ZyanISize instrction_count;
		void *origin_address;
		void * trampol;
		unsigned char origin_code[256];
	public:
		void * old_fun;
		void * new_fun;
		static map<ULONG64, Hook*> hookinstaller;
		ZyanStatus status;
	};

	class InsertHook
	{
	public:
		InsertHook(void* origin_fun, void * new_fun,size_t size);
		~InsertHook();
		void SaveOriginCode();
		unsigned long GetDisasmCodesLength();
	private:
		vector<InstructionInfo*> instruction;
		unsigned char origin_code[256];
		ULONG64 hook_point;
		ZyanStatus status;
	};

	class VtHook
	{
	public:
		VtHook(void* origin_fun, void * new_fun);
		~VtHook();
	public:
		static vector<VtHook*> hooklist;
		ZyanStatus status;
		char trampol_fun[50];
		ULONG64 new_fun;
		ULONG64 origin_fun;
		ULONG64 origin_page_address;
		char origin_page[PAGE_SIZE];
		unsigned char origin_code[50];
		unsigned int code_length;
	};
}
#endif // !DDYLIB_HOOK_H_
