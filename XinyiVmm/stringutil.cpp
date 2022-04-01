#include "stringutil.h"


StringUtil::StringUtil()
{
}

StringUtil::~StringUtil()
{
}

string StringUtil::wide_ansi(const wchar_t* widePointer)
{
  int char_num;
  char* outBuf;
  string outastr = "";
  char_num = WideCharToMultiByte(CP_ACP, NULL, widePointer, -1, NULL, 0, NULL, NULL);
  if (char_num < 1)
    return 0;

  outBuf = new char[char_num];
  WideCharToMultiByte(CP_ACP, NULL, widePointer, -1, outBuf, char_num, NULL, NULL);
  outastr = outBuf;
  delete[]outBuf;
  return outastr;
}
wstring StringUtil::ansi_wide(const char* ansiPointer)
{
  int Wchar_num;
  wchar_t* outBuf;
  wstring outwstr = L"";
  Wchar_num = MultiByteToWideChar(CP_ACP, NULL, ansiPointer, -1, NULL, 0);
  if (Wchar_num < 1)
    return 0;
  outBuf = new wchar_t[Wchar_num];
  MultiByteToWideChar(CP_ACP, NULL, ansiPointer, -1, outBuf, Wchar_num);
  outwstr = outBuf;
  delete[]outBuf;
  return outwstr;
}
