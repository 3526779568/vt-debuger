#include "../include/hook.h"
#include "../include/ddylog.h"
using namespace ddy::Cr3;

map<ULONG64, ddy::Hook*> ddy::Hook::hookinstaller = map<ULONG64, ddy::Hook*>();
ddy::Hook::Hook(void* origin_fun, void * new_fun):
	instrction_count(0)
{
	KIRQL irql;
	KeRaiseIrql(APC_LEVEL, &irql);
	ZydisDecoder decoder;
	ZydisFormatter formater;
	this->origin_address = origin_fun;
	this->new_fun = new_fun;
	if (!this->WeatherCanHook())
	{
		DDYPRINT("Api不支持hook\n");
		this->status = ZYAN_FALSE;
		return;
	}
	if (!ZYAN_SUCCESS(ZydisDecoderInit(
		&decoder, ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64,
		ZydisAddressWidth::ZYDIS_ADDRESS_WIDTH_64))) {
		this->status = ZYAN_FALSE;
		return;
	}
	if (!ZYAN_SUCCESS(ZydisFormatterInit(
		&formater, ZydisFormatterStyle::ZYDIS_FORMATTER_STYLE_INTEL))) {
		this->status = ZYAN_FALSE;
		return;
	}
	ZydisDecodedInstruction ins;
	ZyanU32 offset = 0;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
		&decoder,
		(void*)((ZyanU64)this->origin_address + offset),
		1000 - offset,
		&ins))) {
		InstructionInfo* t = (InstructionInfo*)new char[sizeof(InstructionInfo)];
		t->instruction = ins;
		t->offset = offset;
		t->runtime_address = (ZyanU64)this->origin_address + offset;
		memcpy(t->origin_code, (char*)this->origin_address + offset, ins.length);
		this->instruction.push_back(t);
		offset += ins.length;

		if (offset >= 12) {
			break;
		}
	}
	/**/
	this->SaveOriginCode();
	this->InitTrampoline();
	/*安装hook*/
	Hook::hookinstaller[(ULONG64)this->origin_address] = this;
	this->status = ZYAN_TRUE;
	KeLowerIrql(irql);
}

ddy::Hook::~Hook() {}

void ddy::Hook::UnHook()
{
	KIRQL irql;
	KeRaiseIrql(APC_LEVEL, &irql);
	if (this->trampol)
	{
		delete this->trampol;
		this->trampol = 0;
	}
	this->ResumeOriginFun();
	this->instruction.clear();
	KeLowerIrql(irql);
}

void ddy::Hook::print_intel_asm(void * origin_fun) {
	ZydisDecoder decoder;
	ZydisFormatter formater;
	if (!ZYAN_SUCCESS(ZydisDecoderInit(
		&decoder, ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64,
		ZydisAddressWidth::ZYDIS_ADDRESS_WIDTH_64))) {
		return;
	}
	if (!ZYAN_SUCCESS(ZydisFormatterInit(
		&formater, ZydisFormatterStyle::ZYDIS_FORMATTER_STYLE_INTEL))) {
		return;
	}

	ZydisDecodedInstruction ins;
	ZyanU32 offset = 0;
	ZyanU64 runtime_address = (ZyanU64)origin_fun;
	char buff[100];
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
		&decoder,
		(void*)((ZyanU64)origin_fun + offset),
		100 - offset,
		&ins))) {
		ZydisFormatterFormatInstruction(&formater, &ins, buff, 100, runtime_address);
		offset += ins.length;
		runtime_address += ins.length;
	}
}


unsigned long ddy::Hook::GetDisasmCodesLength()
{
	unsigned long len = 0;
	for (auto ins : this->instruction)
	{
		len += ins->instruction.length;
	}
	return len;
}

void ddy::Hook::InitTrampoline()
{
	DWORD32 p;
	this->trampol = new char[0x1000];
#ifdef __kernel_code
	SetPageAccessRight((ULONG64)this->trampol, true);
#else
	VirtualProtect(this->detours, 0x1000, p, &p);
#endif // __kernel_code

	memset(this->trampol, 0, 0x1000);
	FarJmp jmp;
	jmp.rip = (ZyanU64)this->new_fun;
#ifdef __kernel_code
	SetPageAccessRight((ULONG64)this->origin_address, true);
#else
	VirtualProtect(this->origin_address, 0x1000, PAGE_EXECUTE_READWRITE, &p);
#endif // __kernel_code

	memcpy(this->origin_address, &jmp, sizeof(FarJmp));
	/*处理old_fun*/
	ZyanU64 next_ins_offset = 0, result_address;
	for (auto dire : this->instruction)
	{
		if (strcmp(ZydisMnemonicGetString(dire->instruction.mnemonic), "jmp") == 0)
		{
			ZydisCalcAbsoluteAddress(&dire->instruction, dire->instruction.operands, dire->runtime_address, &result_address);
			FarJmp jmp;
			jmp.rip = result_address;
			memcpy((PCHAR)this->trampol + next_ins_offset, &jmp, sizeof(FarJmp));
			next_ins_offset += sizeof(FarJmp);
		}
		else if (dire->instruction.raw.disp.value)/*指令存在偏移值*/
		{
			ZydisCalcAbsoluteAddress(&dire->instruction, dire->instruction.operands, dire->runtime_address, &result_address);
			long disp = result_address - ((ZyanU64)this->trampol + next_ins_offset + dire->instruction.length);
			memcpy((PCHAR)this->trampol + next_ins_offset, dire->origin_code, dire->instruction.length);
			*(PLONG)((ZyanI64)this->trampol + next_ins_offset + dire->instruction.raw.disp.offset) = disp;
			next_ins_offset += dire->instruction.length;
		}
		else
		{
			memcpy((PCHAR)this->trampol + next_ins_offset, dire->origin_code, dire->instruction.length);
			next_ins_offset += dire->instruction.length;
		}
	}
	/*最后加上一个跳转*/
	RetJmp jmp_back;
	auto jmp_rip = (ZyanU64)this->origin_address + this->GetDisasmCodesLength();
	jmp_back.L.value = (int)jmp_rip;
	jmp_back.H.value = (int)(jmp_rip >> 32);
	memcpy((PCHAR)this->trampol + next_ins_offset, &jmp_back, sizeof(RetJmp));
	this->old_fun = this->trampol;

	//#ifdef __kernel_code
	//	page.SetPageAccessRight((ULONG64)this->origin_address, false);
	//#else
	//	VirtualProtect(this->origin_address, 0x1000, p, &p);
	//#endif // __kernel_code
}

void ddy::Hook::ResumeOriginFun()
{
	DWORD32 p;
#ifdef __kernel_code
	SetPageAccessRight((ULONG64)this->origin_address, true);
#else
	VirtualProtect(this->origin_address, 0x1000, PAGE_EXECUTE_READWRITE, &p);
#endif // __kernel_code
	memcpy(this->origin_address, this->origin_code, this->GetDisasmCodesLength());
#ifdef __kernel_code
	SetPageAccessRight((ULONG64)this->origin_address, false);
#else
	VirtualProtect(this->origin_address, 0x1000, p, &p);
#endif // __kernel_code
}

bool ddy::Hook::WeatherCanHook()
{
	ZydisDecoder decoder;
	ZydisFormatter formater;
	if (!ZYAN_SUCCESS(ZydisDecoderInit(
		&decoder, ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64,
		ZydisAddressWidth::ZYDIS_ADDRESS_WIDTH_64))) {
		return false;
	}
	if (!ZYAN_SUCCESS(ZydisFormatterInit(
		&formater, ZydisFormatterStyle::ZYDIS_FORMATTER_STYLE_INTEL))) {
		return false;
	}

	ZydisDecodedInstruction ins;
	ZyanU32 offset = 0;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
		&decoder,
		(void*)((ZyanU64)this->origin_address + offset),
		1000 - offset,
		&ins))) {
		if (ins.raw.disp.value)/*有值说明存在偏移*/
		{
			return false;
		}
		offset += ins.length;
		if (offset >= 12) {
			break;
		}
	}
	return true;
}

void ddy::Hook::SaveOriginCode()
{
	memcpy(this->origin_code, this->origin_address, this->GetDisasmCodesLength());
}

ddy::InsertHook::InsertHook(void* origin_fun, void * new_fun, size_t size)
{
	KIRQL irql;
	KeRaiseIrql(APC_LEVEL, &irql);
	ZydisDecoder decoder;
	ZydisFormatter formatter;
	if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64, ZydisAddressWidth::ZYDIS_ADDRESS_WIDTH_64)))
	{
		this->status = FALSE;
		return;
	}
	if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZydisFormatterStyle::ZYDIS_FORMATTER_STYLE_INTEL)))
	{
		this->status = FALSE;
	}
	ZydisDecodedInstruction ins;
	ZyanU32 offset = 0;
	char buff[256];
	ZyanU32 find_instruction_len = 0;
	ZyanU64 runtime_address = (ZyanU64)origin_fun;
	/*遍历地址，找到hook点*/
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (char*)origin_fun + offset, size - offset, &ins)))
	{
		offset += ins.length;
		runtime_address += ins.length;
		if (ins.raw.disp.value)
		{
			find_instruction_len = 0;
			for (size_t i = 0; i < this->instruction.size(); i++)
			{
				auto item = this->instruction.back();
				this->instruction.pop_back();
				delete item;
			}
			this->instruction.clear();
			continue;
		}
		auto item = new InstructionInfo;
		item->instruction = ins;
		item->offset = offset - ins.length;
		item->runtime_address = runtime_address - ins.length;
		memcpy(item->origin_code, (void*)item->runtime_address, ins.length);
		this->instruction.push_back(item);
		find_instruction_len += ins.length;
		if (find_instruction_len >= 20)
		{
			this->hook_point = this->instruction[0]->runtime_address;
			break;
		}
	}
	if (find_instruction_len < 20)
	{
		this->status = FALSE;
		return;
	}
	this->SaveOriginCode();
	/*找到了，开始Hook*/
	RetJmp jmp;
	jmp.L.value = (int)new_fun;
	jmp.H.value = (int)((ULONG64)new_fun >> 32);
	SetPageAccessRight(this->hook_point, true);
	memcpy((void*)this->hook_point, &jmp, sizeof(jmp));
	/*填写new的Jmp*/
	offset = 0;
	runtime_address = (ULONG64)new_fun;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (char*)new_fun + offset, size - offset, &ins)))
	{
		DbgBreakPoint();
		ZydisFormatterFormatInstruction(&formatter, &ins, buff, 256, runtime_address);
		if (strcmp(buff, "int 3") == 0)
		{
			break;
		}
		offset += ins.length;
		runtime_address += ins.length;
	}
	RetJmp jmp_back;
	auto rip = this->hook_point + this->GetDisasmCodesLength();
	jmp_back.L.value = (int)rip;
	jmp_back.H.value = (int)((ULONG64)rip >> 32);
	SetPageAccessRight(runtime_address, true);
	memcpy((void*)runtime_address, &jmp_back, sizeof(jmp_back));
	KeLowerIrql(irql);
}

void ddy::InsertHook::SaveOriginCode()
{
	memcpy(this->origin_code, (void*)this->hook_point, this->GetDisasmCodesLength());
}

unsigned long ddy::InsertHook::GetDisasmCodesLength()
{
	unsigned long len = 0;
	for (auto ins : this->instruction)
	{
		len += ins->instruction.length;
	}
	return len;
}

vector<ddy::VtHook*> ddy::VtHook::hooklist;
ddy::VtHook::VtHook(void * origin_fun, void * new_fun)
{
	ZydisDecoder decoder;
	ZydisFormatter formatter;
	this->origin_fun = (ULONG64)origin_fun;
	this->origin_page_address = (ULONG64)PAGE_ALIGN(origin_fun);
	this->new_fun = (ULONG64)new_fun;
	if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64, ZydisAddressWidth::ZYDIS_ADDRESS_WIDTH_64)))
	{
		this->status = FALSE;
		return;
	}
	if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZydisFormatterStyle::ZYDIS_FORMATTER_STYLE_INTEL)))
	{
		this->status = FALSE;
	}
	ZydisDecodedInstruction ins;
	ZyanU32 offset = 0;
	ZyanU32 find_instruction_len = 0;
	ZyanU64 runtime_address = (ZyanU64)origin_fun;
	ZydisDecoderDecodeBuffer(&decoder, origin_fun, 50, &ins);
	memcpy(this->origin_code, origin_fun, ins.length);
	this->code_length = ins.length;
	memcpy(this->origin_page, (void*)this->origin_page_address, PAGE_SIZE);
	/*设置跳板函数*/
	memcpy((void*)this->trampol_fun, this->origin_code, this->code_length);
	RetJmp jmp;
	jmp.L.value = (int)(this->origin_fun + this->code_length);
	jmp.H.value = (int)((this->origin_fun + this->code_length) >> 32);
	memcpy((void*)((ULONG64)this->trampol_fun + this->code_length), &jmp, sizeof(jmp));
	this->hooklist.push_back(this);
}

ddy::VtHook::~VtHook()
{
}
