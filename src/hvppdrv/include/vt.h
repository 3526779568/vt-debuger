#pragma once
#ifndef DDY_VT_H_
#define DDY_VT_H_
#include "ntddk.h"
#include <intrin.h>
namespace ddy
{
	class Vt
	{
	public:
		Vt() {};
		~Vt() {};
		static void SetMsrBitMap(void * map, unsigned long long msr,bool flag);
	private:

	};
	inline void Vt::SetMsrBitMap(void * map, unsigned long long msr, bool flag)
	{
		LONG64 *base = (LONG64 *)map;
		if (flag)
		{
			if (msr >= 0xC0000000)
			{
				_bittestandset64(base + 1024, msr & 0x00001FFF);/*���˳�*/
				_bittestandset64(base + 3072, msr & 0x00001FFF);/*д�˳�*/
			}
			else
			{
				_bittestandset64(base, msr);/*���˳�*/
				_bittestandset64(base + 2048, msr);/*д�˳�*/
			}
		}
		else//�ָ�
		{
			if (msr >= 0xC0000000)
			{
				_bittestandreset64(base + 1024, msr & 0x00001FFF);
				_bittestandreset64(base + 3072, msr & 0x00001FFF);
			}
			else
			{
				_bittestandreset64(base, msr);
				_bittestandreset64(base + 2048, msr);
			}
		}
		
	}
}
#endif // !DDY_VT_H_
