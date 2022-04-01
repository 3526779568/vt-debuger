#include <Windows.h>
#include "regedit.h"


RegEdit::RegEdit(void)
{
  m_hKey = HKEY_CURRENT_USER;
}


RegEdit::~RegEdit(void)
{

}

void RegEdit::selectRootKey(int nKey)
{
  switch (nKey)
  {
  case 0:
    m_hKey = HKEY_CLASSES_ROOT;
    break;
  case 1:
    m_hKey = HKEY_CURRENT_USER;
    break;
  case 2:
    m_hKey = HKEY_LOCAL_MACHINE;
    break;
  case 3:
    m_hKey = HKEY_USERS;
    break;
  case 4:
    m_hKey = HKEY_CURRENT_CONFIG;
    break;
  default:
    m_hKey = HKEY_CURRENT_USER;
    break;
  }

  return;
}

bool RegEdit::createSubKey(char* chPath, char* chName)
{
  HKEY hKey;
  HKEY hNextKey;
  TCHAR path[128] = { 0 };
  TCHAR name[128] = { 0 };

  //多字节转宽字节
  int iLength1 = MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, path, iLength1);

  int iLength2 = MultiByteToWideChar(CP_ACP, 0, chName, strlen(chName) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chName, strlen(chName) + 1, name, iLength2);

  //打开注册表
  if (ERROR_SUCCESS != ::RegOpenKeyEx(m_hKey, path, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey))
  {
    return false;
  }
  else
  {
    if (ERROR_SUCCESS == ::RegCreateKey(hKey, name, &hNextKey))
    {
      ::RegCloseKey(hKey);
      return true;
    }
    else
    {
      ::RegCloseKey(hKey);
      return false;
    }
  }
}

bool RegEdit::createKeyValue(char* chPath, char* chKey, char* chValue)
{
  HKEY hKey;
  TCHAR path[128] = { 0 };
  TCHAR key[128] = { 0 };
  TCHAR value[128] = { 0 };


  //多字节转宽字节
  int iLength1 = MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, path, iLength1);

  int iLength2 = MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, key, iLength2);

  int iLength3 = MultiByteToWideChar(CP_ACP, 0, chValue, strlen(chValue) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chValue, strlen(chValue) + 1, value, iLength3);

  //打开注册表
  if (ERROR_SUCCESS != ::RegOpenKeyEx(m_hKey, path, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey))
  {
    return false;
  }
  else
  {
    if (ERROR_SUCCESS == ::RegSetValueEx(hKey, key, 0, REG_SZ, (const BYTE*)value, MAX_PATH))
    {
      ::RegCloseKey(hKey);
      return true;
    }
    else
    {
      ::RegCloseKey(hKey);
      return false;
    }
  }
}

bool RegEdit::createKeyValue(char* chPath, char* chKey, DWORD dwValue)
{
  HKEY hKey;
  TCHAR path[128] = { 0 };
  TCHAR key[128] = { 0 };

  //多字节转宽字节
  int iLength1 = MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, path, iLength1);

  int iLength2 = MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, key, iLength2);

  //打开注册表
  if (ERROR_SUCCESS != ::RegOpenKeyEx(m_hKey, path, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey))
  {
    return false;
  }
  else
  {
    if (ERROR_SUCCESS == ::RegSetValueEx(hKey, key, 0, REG_DWORD, (const BYTE*)&dwValue, sizeof(DWORD)))
    {
      ::RegCloseKey(hKey);
      return true;
    }
    else
    {
      ::RegCloseKey(hKey);
      return false;
    }
  }
}

bool RegEdit::createKeyValue(char* chPath, char* chKey, BYTE btValue[])
{
  HKEY hKey;
  TCHAR path[128] = { 0 };
  TCHAR key[128] = { 0 };

  //多字节转宽字节
  int iLength1 = MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, path, iLength1);

  int iLength2 = MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, key, iLength2);

  //打开注册表
  if (ERROR_SUCCESS != ::RegOpenKeyEx(m_hKey, path, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey))
  {
    return false;
  }
  else
  {
    if (ERROR_SUCCESS == ::RegSetValueEx(hKey, key, 0, REG_DWORD, (const BYTE*)btValue, sizeof(btValue)))
    {
      ::RegCloseKey(hKey);
      return true;
    }
    else
    {
      ::RegCloseKey(hKey);
      return false;
    }
  }
}

bool RegEdit::deleteKeyValue(char* chPath, char* chKey)
{
  HKEY hKey;
  TCHAR path[128] = { 0 };
  TCHAR key[128] = { 0 };

  //多字节转宽字节
  int iLength1 = MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, path, iLength1);

  int iLength2 = MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, key, iLength2);

  //打开注册表
  if (ERROR_SUCCESS != ::RegOpenKeyEx(m_hKey, path, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey))
  {
    return false;
  }
  else
  {
    if (ERROR_SUCCESS == ::RegDeleteValue(hKey, key))
    {
      ::RegCloseKey(hKey);
      return true;
    }
    else
    {
      ::RegCloseKey(hKey);
      return false;
    }
  }
}

bool RegEdit::getKeyValue(char* chPath, char* chKey, DWORD& dwValue)
{
  HKEY hKey;
  TCHAR path[128] = { 0 };
  TCHAR key[128] = { 0 };

  //多字节转宽字节
  int iLength1 = MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, path, iLength1);

  int iLength2 = MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, key, iLength2);

  //打开注册表
  if (ERROR_SUCCESS != ::RegOpenKeyEx(m_hKey, path, 0, KEY_READ | KEY_WOW64_64KEY, &hKey))
  {
    return false;
  }
  else
  {
    DWORD dwGetValue = 0;
    DWORD dwSize = sizeof(DWORD);
    DWORD dwType = REG_DWORD;
    if (ERROR_SUCCESS == ::RegQueryValueEx(hKey, key, 0, &dwType, (LPBYTE)&dwGetValue, &dwSize))
    {
      dwValue = dwGetValue;
      ::RegCloseKey(hKey);
      return true;
    }
    else
    {
      ::RegCloseKey(hKey);
      return false;
    }
  }
}

bool RegEdit::getKeyValue(char* chPath, char* chKey, std::string& value)
{
  HKEY hKey;
  TCHAR path[128] = { 0 };
  TCHAR key[128] = { 0 };
  TCHAR data[128] = { 0 };
  char result[1024] = { 0 };

  //多字节转宽字节
  int iLength1 = MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, path, iLength1);

  int iLength2 = MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, key, iLength2);

  //打开注册表
  if (ERROR_SUCCESS != ::RegOpenKeyEx(m_hKey, path, 0, KEY_READ | KEY_WOW64_64KEY, &hKey))
  {
    return false;
  }
  else
  {
    DWORD dwSize = 1024;
    DWORD dwType = REG_SZ;
    if (ERROR_SUCCESS == ::RegQueryValueEx(hKey, key, 0, &dwType, (LPBYTE)&data, &dwSize))
    {
      DWORD bufferSize = WideCharToMultiByte(CP_OEMCP, 0, data, -1, NULL, 0, NULL, NULL);
      WideCharToMultiByte(CP_OEMCP, 0, data, -1, result, bufferSize, NULL, NULL);
      value = std::string(result);
      ::RegCloseKey(hKey);
      return true;
    }
    else
    {
      ::RegCloseKey(hKey);
      return false;
    }
  }
}

bool RegEdit::getKeyValue(char* chPath, char* chKey, BYTE value[])
{
  HKEY hKey;
  TCHAR path[128] = { 0 };
  TCHAR key[128] = { 0 };

  //多字节转宽字节
  int iLength1 = MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, path, iLength1);

  int iLength2 = MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, key, iLength2);

  //打开注册表
  if (ERROR_SUCCESS != ::RegOpenKeyEx(m_hKey, path, 0, KEY_READ | KEY_WOW64_64KEY, &hKey))
  {
    return false;
  }
  else
  {
    DWORD dwKeyValueSize = 1024;
    LPBYTE lpbKeyValueData = new BYTE[1024];
    DWORD dwType = REG_BINARY;
    if (ERROR_SUCCESS == ::RegQueryValueEx(hKey, key, 0, &dwType, (LPBYTE)lpbKeyValueData, &dwKeyValueSize))
    {
      for (DWORD i = 0; i < dwKeyValueSize; i++)
      {
        value[i] = lpbKeyValueData[i];
      }
      ::RegCloseKey(hKey);
      return true;
    }
    else
    {
      ::RegCloseKey(hKey);
      return false;
    }
  }
  return true;
}

bool RegEdit::getKeyValueEx(char* chPath, char* chKey, std::string& value)
{
  HKEY hKey;
  TCHAR path[128] = { 0 };
  TCHAR key[128] = { 0 };

  //多字节转宽字节
  int iLength1 = MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, path, iLength1);

  int iLength2 = MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chKey, strlen(chKey) + 1, key, iLength2);


  //打开注册表
  if (ERROR_SUCCESS != ::RegOpenKeyEx(m_hKey, path, 0, KEY_READ | KEY_WOW64_64KEY, &hKey))
  {
    ::RegCloseKey(hKey);
    return false;
  }
  else
  {
    DWORD dwKeyValueSize = 1024;
    LPBYTE lpbKeyValueData = new BYTE[1024];
    DWORD dwType = REG_BINARY;
    if (ERROR_SUCCESS == ::RegQueryValueEx(hKey, key, 0, &dwType, (LPBYTE)lpbKeyValueData, &dwKeyValueSize))
    {
      for (DWORD i = 0; i < dwKeyValueSize; i++)
      {
        char buffer[4] = { 0 };
        sprintf_s(buffer, sizeof(buffer), "%02x", lpbKeyValueData[i]);
        //sprintf(buffer, "%02x", lpbKeyValueData[i]);
        value.append(buffer);
      }
      ::RegCloseKey(hKey);
      return true;
    }
    else
    {
      ::RegCloseKey(hKey);
      return false;
    }
  }
  return true;

}

bool RegEdit::backupKey(char* chPath, char* chfileName)
{
  HKEY hKey;
  TCHAR path[128] = { 0 };
  TCHAR filename[128] = { 0 };

  //多字节转宽字节
  int iLength1 = MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, path, iLength1);

  int iLength2 = MultiByteToWideChar(CP_ACP, 0, chfileName, strlen(chfileName) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chfileName, strlen(chfileName) + 1, filename, iLength2);

  //申请权限
  HANDLE hToken;
  TOKEN_PRIVILEGES tkp;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
  {
    return false;
  }

  LookupPrivilegeValue(NULL, SE_BACKUP_NAME, &tkp.Privileges[0].Luid);
  tkp.PrivilegeCount = 1;
  tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
  int b = GetLastError();


  if (ERROR_SUCCESS != ::RegOpenKeyEx(m_hKey, path, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey))
  {
    return false;
  }
  else
  {
    //保存
    if (ERROR_SUCCESS != ::RegSaveKey(hKey, filename, NULL))
    {
      ::RegCloseKey(hKey);
      return false;
    }
    else
    {
      ::RegCloseKey(hKey);
      return true;
    }
  }
}

bool RegEdit::restoreKey(char* chPath, char* fileName, bool isSure)
{

  HKEY hKey;
  TCHAR path[128] = { 0 };
  TCHAR filename[128] = { 0 };

  //多字节转宽字节
  int iLength1 = MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, path, iLength1);

  int iLength2 = MultiByteToWideChar(CP_ACP, 0, fileName, strlen(fileName) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, fileName, strlen(fileName) + 1, filename, iLength2);

  //申请权限
  HANDLE hToken;
  TOKEN_PRIVILEGES tkp;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
  {
    return false;
  }

  LookupPrivilegeValue(NULL, SE_RESTORE_NAME, &tkp.Privileges[0].Luid);
  tkp.PrivilegeCount = 1;
  tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

  if (ERROR_SUCCESS != ::RegOpenKeyEx(m_hKey, path, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey))
  {
    return false;
  }
  else
  {
    DWORD dwFlag;
    if (isSure)
    {
      dwFlag = REG_FORCE_RESTORE;
    }
    else
    {
      dwFlag = REG_WHOLE_HIVE_VOLATILE;
    }

    //还原
    if (ERROR_SUCCESS != ::RegRestoreKey(hKey, filename, dwFlag))
    {
      ::RegCloseKey(hKey);
      return false;
    }
    else
    {
      ::RegCloseKey(hKey);
      return true;
    }
  }
}

bool RegEdit::deleteSubKey(char* chPath, char* chName)
{
  HKEY hKey;
  TCHAR path[128] = { 0 };
  TCHAR name[128] = { 0 };

  //多字节转宽字节
  int iLength1 = MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chPath, strlen(chPath) + 1, path, iLength1);

  int iLength2 = MultiByteToWideChar(CP_ACP, 0, chName, strlen(chName) + 1, NULL, 0);
  MultiByteToWideChar(CP_ACP, 0, chName, strlen(chName) + 1, name, iLength2);

  //打开注册表
  if (ERROR_SUCCESS != ::RegOpenKeyEx(m_hKey, path, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey))
  {
    return false;
  }
  else
  {
    if (ERROR_SUCCESS == ::RegDeleteKey(hKey, name))
    {
      ::RegCloseKey(hKey);
      return true;
    }
    else
    {
      ::RegCloseKey(hKey);
      return false;
    }
  }
}
