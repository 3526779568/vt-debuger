#pragma once
#ifndef REGEDIT_H_
#define REGEDIT_H_

#include<iostream>
class RegEdit
{
public:
  RegEdit(void);
  ~RegEdit(void);

  //选择根键
  void selectRootKey(int nKey);
  //创建子键
  bool createSubKey(char* chPath, char* chName);
  //删除子键
  bool deleteSubKey(char* chPath, char* chName);
  //创建字符键值对
  bool createKeyValue(char* chPath, char* chKey, char* chValue);
  //创建DWORD键值对
  bool createKeyValue(char* chPath, char* chKey, DWORD dwValue);
  //创建BINARY键值对
  bool createKeyValue(char* chPath, char* chKey, BYTE btValue[]);
  //删除键值对
  bool deleteKeyValue(char* chPath, char* chKey);
  //获取DWORD键值
  bool getKeyValue(char* chPath, char* chKey, DWORD& dwValue);
  //获取字符键值
  bool getKeyValue(char* chPath, char* chKey, std::string& value);
  //获取BINARY键值，返回二进制数据
  bool getKeyValue(char* chPath, char* chKey, BYTE value[]);
  //获取BINARY键值，返回string类型
  bool getKeyValueEx(char* chPath, char* chKey, std::string& value);
  //备份键值对
  bool backupKey(char* chPath, char* fileName);
  //还原键值对
  bool restoreKey(char* chPath, char* fileName, bool isSure);
private:
  HKEY m_hKey;

};

#endif // !REGEDIT_H_
