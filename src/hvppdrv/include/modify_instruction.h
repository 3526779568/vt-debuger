#pragma once
#ifndef DDYLIB_MODIFY_H_
#define DDYLIB_MODIFY_H_
#include "ntddk.h"
namespace ddy
{
	class ModifyInstr
	{
	public:
		void DirectionNearJmp(ULONG64 vad, ULONG64 jmp_to);
		void DirectionFarJmp(ULONG64 vad, ULONG64 jmp_to);
	private:

	};
}
#endif // !DDYLIB_MODIFY_H_
