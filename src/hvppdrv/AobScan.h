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

// 1、搜索字符串
//    SigPattern = "This is a null terminated string."
//    SigMask = NULL or "xxxxxxxxxxx" or "x?xx????xxx"
//
// 2、搜索代码、函数或数据
//    SigPattern = "\x8B\xCE\xE8\x00\x00\x00\x00\x8B"
//    SigMask = "xxxxxxxx" or "xxx????x"
//
// Mask 中的 ? 可用于模糊匹配，在被搜索代码片段中有动态变化的内容时使用(如指令操作的地址、数据等)
//
// 这里是搜索虚拟内存对应的子函数，物理内存操作方面，各人有各人的方法，与此主题无关就省略了
//
class AobScan
{
public:
	ULONGLONG Search(ULONGLONG VirtualAddress, ULONGLONG VirtualLength, PUCHAR SigPattern,ULONG SigPatternLength);
	ULONGLONG Search(ULONGLONG VirtualAddress, ULONGLONG VirtualLength, PCHAR SigPattern, PCHAR SigMask);
};

