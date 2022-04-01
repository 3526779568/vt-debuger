#pragma once
#include <ntifs.h>
#undef _vsnprintf
#include <ntstrsafe.h>
#pragma comment(lib,"../lib/ucrtd.lib")
#ifndef DDYLIB_LOG_H_
#define DDYLIB_LOG_H_
namespace ddy {
	class Log
	{
	public:
		Log();
		~Log();
		void _cdecl DdyPrint(const char* format, ...);

	private:

	};
#define DDYPRINT(format,...) DbgPrint("DDY::"##format,__VA_ARGS__)
}
#endif // !DDYLIB_LOG_H_
