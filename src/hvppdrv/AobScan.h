#pragma once
#include <emmintrin.h>
#ifdef WIN32
#    ifndef WIN32_LEAN_AND_MEAN
#        define WIN32_LEAN_AND_MEAN
#    endif
#    include <windows.h>
#    ifndef PAGE_SIZE
#        define PAGE_SIZE 0x1000
#    endif
#else
#    include <ntifs.h>
#    ifndef MAX_PATH
#        define MAX_PATH 260
#    endif
#endif

// 1�������ַ���
//    SigPattern = "This is a null terminated string."
//    SigMask = NULL or "xxxxxxxxxxx" or "x?xx????xxx"
//
// 2���������롢����������
//    SigPattern = "\x8B\xCE\xE8\x00\x00\x00\x00\x8B"
//    SigMask = "xxxxxxxx" or "xxx????x"
//
// Mask �е� ? ������ģ��ƥ�䣬�ڱ���������Ƭ�����ж�̬�仯������ʱʹ��(��ָ������ĵ�ַ�����ݵ�)
//
// ���������������ڴ��Ӧ���Ӻ����������ڴ�������棬�����и��˵ķ�������������޹ؾ�ʡ����
//
class AobScan
{
public:
	ULONGLONG Search(ULONGLONG VirtualAddress, ULONGLONG VirtualLength, PUCHAR SigPattern,ULONG SigPatternLength);
	ULONGLONG Search(ULONGLONG VirtualAddress, ULONGLONG VirtualLength, PCHAR SigPattern, PCHAR SigMask);
};

