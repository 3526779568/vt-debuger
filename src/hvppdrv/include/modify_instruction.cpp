#include "modify_instruction.h"

void ddy::ModifyInstr::DirectionNearJmp(ULONG64 vad, ULONG64 jmp_to)
{
	/*本地跳转指令长度是5*/
	ULONG64 offset = jmp_to - vad - 5;
	PUCHAR rex = (PUCHAR)vad;
	PULONG32 relative = (PULONG32)(vad + 1);
	*relative = offset;
	*rex = 0xe9;
}

void ddy::ModifyInstr::DirectionFarJmp(ULONG64 vad, ULONG64 jmp_to)
{
	/*远跳转12字节*/
	PUSHORT rex = (PUSHORT)vad;
	PULONG64 rip = (PULONG64)(vad + 2);
	*rex = 0xb848;
	*rip = jmp_to;
	rex = (PUSHORT)(vad + 10);
	*rex = 0xe0ff;
}
