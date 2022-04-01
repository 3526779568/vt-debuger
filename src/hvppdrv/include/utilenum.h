#pragma once
#ifndef DDYLIB_UTILENUM_H_
#define DDYLIB_UTILENUM_H_
namespace ddy
{

	/// See: MODEL-SPECIFIC REGISTERS (MSRS)
	enum  IntelMsr : unsigned long {
		kIa32ApicBase = 0x01B,

		kIa32FeatureControl = 0x03A,

		kIa32SysenterCs = 0x174,
		kIa32SysenterEsp = 0x175,
		kIa32SysenterEip = 0x176,

		kIa32Debugctl = 0x1D9,

		kIa32MtrrCap = 0xFE,
		kIa32MtrrDefType = 0x2FF,
		kIa32MtrrPhysBaseN = 0x200,
		kIa32MtrrPhysMaskN = 0x201,
		kIa32MtrrFix64k00000 = 0x250,
		kIa32MtrrFix16k80000 = 0x258,
		kIa32MtrrFix16kA0000 = 0x259,
		kIa32MtrrFix4kC0000 = 0x268,
		kIa32MtrrFix4kC8000 = 0x269,
		kIa32MtrrFix4kD0000 = 0x26A,
		kIa32MtrrFix4kD8000 = 0x26B,
		kIa32MtrrFix4kE0000 = 0x26C,
		kIa32MtrrFix4kE8000 = 0x26D,
		kIa32MtrrFix4kF0000 = 0x26E,
		kIa32MtrrFix4kF8000 = 0x26F,

		kIa32VmxBasic = 0x480,
		kIa32VmxPinbasedCtls = 0x481,
		kIa32VmxProcBasedCtls = 0x482,
		kIa32VmxExitCtls = 0x483,
		kIa32VmxEn,
		Ctls = 0x484,
		kIa32VmxMisc = 0x485,
		kIa32VmxCr0Fixed0 = 0x486,
		kIa32VmxCr0Fixed1 = 0x487,
		kIa32VmxCr4Fixed0 = 0x488,
		kIa32VmxCr4Fixed1 = 0x489,
		kIa32VmxVmcsEnum = 0x48A,
		kIa32VmxProcBasedCtls2 = 0x48B,
		kIa32VmxEptVpidCap = 0x48C,
		kIa32VmxTruePinbasedCtls = 0x48D,
		kIa32VmxTrueProcBasedCtls = 0x48E,
		kIa32VmxTrueExitCtls = 0x48F,
		kIa32VmxTrueEntryCtls = 0x490,
		kIa32VmxVmfunc = 0x491,

		kIa32Efer = 0xC0000080,
		kIa32Star = 0xC0000081,
		kIa32Lstar = 0xC0000082,

		kIa32Fmask = 0xC0000084,

		kIa32FsBase = 0xC0000100,
		kIa32GsBase = 0xC0000101,
		kIa32KernelGsBase = 0xC0000102,
		kIa32TscAux = 0xC0000103,
	};
}
#endif // !DDYLIB_UTILENUM_H_
