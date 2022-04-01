#include "AobScan.h"

ULONGLONG AobScan::Search(ULONGLONG VirtualAddress, ULONGLONG VirtualLength, PUCHAR SigPattern, ULONG SigPatternLength)
{
    //Do SigMask
	PCHAR SigMask = (PCHAR)ExAllocatePool(NonPagedPool, PAGE_SIZE);
    if (!SigMask)
    {
        return 0;
    }
    auto length = SigPatternLength - 1;
	for (size_t i = 0; i < length; i++)
    {
        SigMask[i] = 'x';
		SigMask[i + 1] = 0;
        if (SigPattern[i]=='\?')
        {
            SigPattern[i] = '\x00';
            SigMask[i] = '\?';
        }
    }
    SigMask[length] = '\0';//字符串是\0结尾

    // 常规变量
    PUCHAR MaxAddress = (PUCHAR)(VirtualAddress + VirtualLength);
    PUCHAR BaseAddress;
    PUCHAR CurrAddress;
    PUCHAR CurrPattern;
    PCHAR CurrMask;
    BOOLEAN CurrEqual;
    register UCHAR CurrUChar;

    // SSE 加速相关变量
    __m128i SigHead = _mm_set1_epi8((CHAR)SigPattern[0]);
    __m128i CurHead, CurComp;
    ULONG MskComp, IdxComp;
    ULONGLONG i, j;
    //
    // 第一层遍历使用 SSE 将逐字节加速为逐 16 字节每次（最终加速 12 倍获益主要来源与此）
    //
    // 第二层子串匹配不能使用 SSE 加速，原因有四
    //     1. SSE 虽为单指令多数据，但单个指令 CPU 周期比常规指令要高
    //
    //     2. 从概率上来说，子串匹配时第一个字节命中失败与 SSE 一次性对比 16 个字节命中失败在概率上几乎相等
    //
    //     3. 根据实验采用 SSE 优化第二层子串匹配将显著降低最终查找速度
    //
    //     4. 理论上，即使 SSE 单条指令与常规指令具有同样的CPU周期，最高也只能加速 16 倍
    //
    for (i = 0; i <= VirtualLength - 16; i += 16)
    {
        if (!MmIsAddressValid(PAGE_ALIGN(VirtualAddress + i)))
        {
            continue;
        }
        if (!MmIsAddressValid(PAGE_ALIGN(VirtualAddress + i + 16)))
        {
            continue;
        }
        CurHead = _mm_loadu_si128((__m128i*)(VirtualAddress + i));
        CurComp = _mm_cmpeq_epi8(SigHead, CurHead);
        MskComp = _mm_movemask_epi8(CurComp);

        BaseAddress = (PUCHAR)(VirtualAddress + i);
        j = 0;
        while (_BitScanForward(&IdxComp, MskComp))
        {
            CurrAddress = BaseAddress + j + IdxComp;
            CurrPattern = SigPattern;
            CurrMask = SigMask;
            for (; CurrAddress <= MaxAddress; CurrAddress++, CurrPattern++, CurrMask++)
            {
                // 因为是暴力搜索整个系统的物理内存，而本函数自身的堆栈区当然也属于整个物理内存的一部分
                // 因此为了避免匹配到参数 SigPattern 本身，对其做了相应过滤操作，如不需要可以自行简化 2 行
                CurrUChar = *CurrPattern;

                if (MmIsAddressValid(CurrAddress))
                {
                    // *CurrPattern = CurrUChar + 0x1;
                    CurrEqual = (*CurrAddress == CurrUChar);
                    // *CurrPattern = CurrUChar;
                    if (!CurrEqual) { if (*CurrMask == 'x') break; }
                    if (*CurrMask == 0) { return (ULONGLONG)(BaseAddress + j + IdxComp); }
                }
                else
                {
                    break;
                }
            }

            ++IdxComp;
            MskComp = MskComp >> IdxComp;
            j += IdxComp;
        }
    }
    ExFreePool(SigMask);
    return 0x0;
}

ULONGLONG AobScan::Search(ULONGLONG VirtualAddress, ULONGLONG VirtualLength, PCHAR SigPattern, PCHAR SigMask)
{
    if (SigMask==nullptr)
    {
        return 0;
    }
    // 常规变量
    PUCHAR MaxAddress = (PUCHAR)(VirtualAddress + VirtualLength);
    PUCHAR BaseAddress;
    PUCHAR CurrAddress;
    PUCHAR CurrPattern;
    PCHAR CurrMask;
    BOOLEAN CurrEqual;
    register UCHAR CurrUChar;

    // SSE 加速相关变量
    __m128i SigHead = _mm_set1_epi8((CHAR)SigPattern[0]);
    __m128i CurHead, CurComp;
    ULONG MskComp, IdxComp;
    ULONGLONG i, j;

    //
    // 第一层遍历使用 SSE 将逐字节加速为逐 16 字节每次（最终加速 12 倍获益主要来源与此）
    //
    // 第二层子串匹配不能使用 SSE 加速，原因有四
    //     1. SSE 虽为单指令多数据，但单个指令 CPU 周期比常规指令要高
    //
    //     2. 从概率上来说，子串匹配时第一个字节命中失败与 SSE 一次性对比 16 个字节命中失败在概率上几乎相等
    //
    //     3. 根据实验采用 SSE 优化第二层子串匹配将显著降低最终查找速度
    //
    //     4. 理论上，即使 SSE 单条指令与常规指令具有同样的CPU周期，最高也只能加速 16 倍
    //
    for (i = 0; i <= VirtualLength - 16; i += 16)
    {
        if (!MmIsAddressValid(PAGE_ALIGN(VirtualAddress + i)))
        {
            continue;
        }
		if (!MmIsAddressValid(PAGE_ALIGN(VirtualAddress + i + 16)))
        {
            continue;
        }
		CurHead = _mm_loadu_si128((__m128i*)(VirtualAddress + i));
        CurComp = _mm_cmpeq_epi8(SigHead, CurHead);
        MskComp = _mm_movemask_epi8(CurComp);

        BaseAddress = (PUCHAR)(VirtualAddress + i);
        j = 0;
        while (_BitScanForward(&IdxComp, MskComp))
        {
            CurrAddress = BaseAddress + j + IdxComp;
            CurrPattern = (PUCHAR)SigPattern;
            CurrMask = SigMask;
            for (; CurrAddress <= MaxAddress; CurrAddress++, CurrPattern++, CurrMask++)
            {
                // 因为是暴力搜索整个系统的物理内存，而本函数自身的堆栈区当然也属于整个物理内存的一部分
                // 因此为了避免匹配到参数 SigPattern 本身，对其做了相应过滤操作，如不需要可以自行简化 2 行
                CurrUChar = *CurrPattern;
                
                if (MmIsAddressValid(CurrAddress))
                {
                    // *CurrPattern = CurrUChar + 0x1;
                    CurrEqual = (*CurrAddress == CurrUChar);
                    // *CurrPattern = CurrUChar;
                    if (!CurrEqual) { if (*CurrMask == 'x') break; }
                    if (*CurrMask == 0) { return (ULONGLONG)(BaseAddress + j + IdxComp); }
                }
                else
                {
                    break;
                }
            }

            ++IdxComp;
            MskComp = MskComp >> IdxComp;
            j += IdxComp;
        }
    }

    return 0x0;
}
