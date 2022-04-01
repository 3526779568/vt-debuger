#include "ddylog.h"
using namespace ddy::Log;


void _cdecl ddy::Log::DdyPrint(const char * format, ...)
{
	char msg[412] = "DDY::\0";
	va_list vl;
	va_start(vl, format);
	//RtlStringCchVPrintfA(msg + strlen(msg), 1024 - strlen(msg), format, vl);
	_vsnprintf(msg + strlen(msg), 412 - strlen(msg), format, vl);
	va_end(format);
	DbgPrint(msg);
}
