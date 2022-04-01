#pragma once
#include <ntddk.h>
#include <ntstrsafe.h>

#undef _vsnprintf
#pragma comment(lib,"../lib/ucrtd.lib")
#ifndef DDYLIB_LOG_H_
#define DDYLIB_LOG_H_
namespace ddy {
	namespace Log
	{
		void _cdecl DdyPrint(const char* format, ...);
#define DDYPRINT(format,...) DbgPrint("DDY::"##format,__VA_ARGS__)
	}
}

#endif // !DDYLIB_LOG_H_
