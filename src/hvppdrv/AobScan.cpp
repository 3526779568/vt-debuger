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
    SigMask[length] = '\0';//�ַ�����\0��β

    // �������
    PUCHAR MaxAddress = (PUCHAR)(VirtualAddress + VirtualLength);
    PUCHAR BaseAddress;
    PUCHAR CurrAddress;
    PUCHAR CurrPattern;
    PCHAR CurrMask;
    BOOLEAN CurrEqual;
    register UCHAR CurrUChar;

    // SSE ������ر���
    __m128i SigHead = _mm_set1_epi8((CHAR)SigPattern[0]);
    __m128i CurHead, CurComp;
    ULONG MskComp, IdxComp;
    ULONGLONG i, j;
    //
    // ��һ�����ʹ�� SSE �����ֽڼ���Ϊ�� 16 �ֽ�ÿ�Σ����ռ��� 12 ��������Ҫ��Դ��ˣ�
    //
    // �ڶ����Ӵ�ƥ�䲻��ʹ�� SSE ���٣�ԭ������
    //     1. SSE ��Ϊ��ָ������ݣ�������ָ�� CPU ���ڱȳ���ָ��Ҫ��
    //
    //     2. �Ӹ�������˵���Ӵ�ƥ��ʱ��һ���ֽ�����ʧ���� SSE һ���ԶԱ� 16 ���ֽ�����ʧ���ڸ����ϼ������
    //
    //     3. ����ʵ����� SSE �Ż��ڶ����Ӵ�ƥ�佫�����������ղ����ٶ�
    //
    //     4. �����ϣ���ʹ SSE ����ָ���볣��ָ�����ͬ����CPU���ڣ����Ҳֻ�ܼ��� 16 ��
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
                // ��Ϊ�Ǳ�����������ϵͳ�������ڴ棬������������Ķ�ջ����ȻҲ�������������ڴ��һ����
                // ���Ϊ�˱���ƥ�䵽���� SigPattern ��������������Ӧ���˲������粻��Ҫ�������м� 2 ��
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
    // �������
    PUCHAR MaxAddress = (PUCHAR)(VirtualAddress + VirtualLength);
    PUCHAR BaseAddress;
    PUCHAR CurrAddress;
    PUCHAR CurrPattern;
    PCHAR CurrMask;
    BOOLEAN CurrEqual;
    register UCHAR CurrUChar;

    // SSE ������ر���
    __m128i SigHead = _mm_set1_epi8((CHAR)SigPattern[0]);
    __m128i CurHead, CurComp;
    ULONG MskComp, IdxComp;
    ULONGLONG i, j;

    //
    // ��һ�����ʹ�� SSE �����ֽڼ���Ϊ�� 16 �ֽ�ÿ�Σ����ռ��� 12 ��������Ҫ��Դ��ˣ�
    //
    // �ڶ����Ӵ�ƥ�䲻��ʹ�� SSE ���٣�ԭ������
    //     1. SSE ��Ϊ��ָ������ݣ�������ָ�� CPU ���ڱȳ���ָ��Ҫ��
    //
    //     2. �Ӹ�������˵���Ӵ�ƥ��ʱ��һ���ֽ�����ʧ���� SSE һ���ԶԱ� 16 ���ֽ�����ʧ���ڸ����ϼ������
    //
    //     3. ����ʵ����� SSE �Ż��ڶ����Ӵ�ƥ�佫�����������ղ����ٶ�
    //
    //     4. �����ϣ���ʹ SSE ����ָ���볣��ָ�����ͬ����CPU���ڣ����Ҳֻ�ܼ��� 16 ��
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
                // ��Ϊ�Ǳ�����������ϵͳ�������ڴ棬������������Ķ�ջ����ȻҲ�������������ڴ��һ����
                // ���Ϊ�˱���ƥ�䵽���� SigPattern ��������������Ӧ���˲������粻��Ҫ�������м� 2 ��
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
