#pragma once
#include "qstring.h"
#include "Stowaways.h"
class User
{
public:
  User(QString username, QString password);
  ~User();
public:
  QString username;
  QString password;
  QString sysinfo;
  QString targetip;
  QString Qtip;
  QString currentpath;
  QString currentpathwildcard;
  QString hdinfo;
  bool logined;
  bool use_ept;
  bool use_mode;
  bool antireference;
  bool protectdebuger;
  bool performance;
  bool antihardware;
  bool disablethread;
  bool supercontext;
  Stowaways* stw;
public:
  void XinyiUserLogin();
  void InitHostConfig(bool& retflag);
  void XinyiCheckAndLockUser();
  void XinyiLoadDriver();
private:
  
};
