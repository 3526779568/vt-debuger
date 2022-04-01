#pragma once
#include <EASTL/map.h>
#include <EASTL/set.h>

enum VMCALLVALUE :ULONG64
{
	DDYMemoryHide=100,
	DDYRemoveMemoryHide,
	DDYInfHook = 777777,
	DDYInfUnHook = 888888,
};

/// A structure made up of mutual fields across all EPT entry types
union EptCommonEntry {
	ULONG64 all;
	struct {
		ULONG64 read_access : 1;       //!< [0]
		ULONG64 write_access : 1;      //!< [1]
		ULONG64 execute_access : 1;    //!< [2]
		ULONG64 memory_type : 3;       //!< [3:5]
		ULONG64 reserved1 : 6;         //!< [6:11]
		ULONG64 physial_address : 36;  //!< [12:48-1]
		ULONG64 reserved2 : 16;        //!< [48:63]
	} fields;
};
static_assert(sizeof(EptCommonEntry) == 8, "Size check");

struct HookData
{
	PVOID rw_page_va;
	PVOID rw_page_pa;
	PVOID e_page_va;
	PVOID e_page_pa;
	PMDL rwe_mdl;
};

class MemoryHide
{
public:
	MemoryHide() {};
	~MemoryHide();
public:
	eastl::set<PVOID> runpoint;
	eastl::map<PVOID, HookData*> memoryhide;
	BOOLEAN Hide(PVOID rw_va, PVOID e_va);
	void RemoveHide(PVOID rw_va);
};
