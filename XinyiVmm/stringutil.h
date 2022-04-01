#pragma once
#include <string>
#include <Windows.h>
using namespace std;
#ifndef UTIL_H_
#define UTIL_H_
class StringUtil
{
public:
  StringUtil();
  ~StringUtil();
  static string wide_ansi(const wchar_t* widePointer);
  static wstring ansi_wide(const char* ansiPointer);

private:

};
#endif // !UTIL_H_
