#include "User.h"
#include <Windows.h>
#include "qcoreapplication.h"
#include "qmessagebox.h"
#include "qfile.h"
#include "IsBeingDebuged.h"

User::User(QString username, QString password)
{
  this->currentpath = QCoreApplication::applicationDirPath();
  this->username = username;
  this->password = password;
  this->logined = false;
  this->use_ept = false;
  this->use_mode = false;
  this->antireference = false;
  this->protectdebuger = false;
  this->performance = false;
  this->stw = nullptr;
}

User::~User()
{
}

void User::XinyiUserLogin()
{
  if (this->logined)
  {
    return;
  }
  WSADATA wsaData;
  int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  char filename[256];

  if (this->username.isEmpty() || this->password.isEmpty())
  {
    QMessageBox::warning(nullptr, "警告", "用户名或密码为空");
    return;
  }
  bool retflag;
  InitHostConfig(retflag);
  if (retflag)
  {
    return;
  }
  //创建Socket
  auto sid = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  sockaddr_in sin = { 0 };
  sin.sin_family = AF_INET;
  sin.sin_addr.S_un.S_addr = targetip.toInt();
  sin.sin_port = htons(7222);
  //连接远程
  auto error = connect(sid, (sockaddr*)&sin, sizeof(sin));
  if (error)
  {
    return;
  }
  //发送的数据
  QString data;
  data += username;
  data += ",";
  data += password;
  data += ",";
  data += "1";
  data += ",";
  data += this->hdinfo;

  //登录
  char bf[256] = { 0 };
  send(sid, data.toStdString().c_str(), data.length(), 0);
  recv(sid, bf, 256, 0);
  closesocket(sid);
  if (QString::fromStdString("success").compare(bf) == 0)
  {
    this->logined = true;
  }
  else
  {
    QMessageBox::information(nullptr, "警告", "登录失败");
    return;
  }
}

void User::InitHostConfig(bool& retflag)
{
  retflag = true;
  QFile conffile(this->currentpath + "\\conf.ini");
  if (!conffile.open(QIODevice::OpenModeFlag::ReadOnly))
  {
    QMessageBox::warning(nullptr, "警告", "请先下载配置文件");
    return;
  }
  auto context = conffile.readAll();
  auto iplist = context.split('|');
  targetip = QString::number((iplist[3].toInt() << 24) | (iplist[2].toInt() << 16) | (iplist[1].toInt() << 8) | (iplist[0].toInt()));
  Qtip = iplist[0] + "." + iplist[1] + "." + iplist[2] + "." + iplist[3];
  retflag = false;
}

void User::XinyiCheckAndLockUser()
{
  while (true)
  {
    auto debuged = CheckDebugALL();
    auto Bitcount = stw->GetFromAntiDebug();
    if (Bitcount || debuged)
    {
      //发送的数据
      QString data;
      data += username;
      data += ",";
      data += password;
      data += ",";
      data += "2";
      //封号处理
      //创建Socket
      auto sid = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      sockaddr_in sin = { 0 };
      sin.sin_family = AF_INET;
      sin.sin_addr.S_un.S_addr = targetip.toInt();
      sin.sin_port = htons(7222);
      auto error = connect(sid, (sockaddr*)&sin, sizeof(sin));
      send(sid, data.toStdString().c_str(), data.length(), 0);
      closesocket(sid);
    }
    Sleep(5000);
  }
  return;
}

void User::XinyiLoadDriver()
{
  //登录成功,加载驱动
  QString driverpath = this->currentpath + "/CheatVMM.sys";
  auto sc_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  auto server_handle = CreateService(sc_handle, L"CheatVMM", L"CheatVMM", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
    SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driverpath.toStdWString().c_str(), NULL, NULL, NULL, NULL, NULL);
  if (!server_handle && GetLastError() != ERROR_SERVICE_EXISTS)
  {
    QMessageBox::warning(nullptr, "错误", "异常代码:1001");
    return;
  }
  if (server_handle == 0)
  {
    server_handle = OpenService(sc_handle, L"CheatVMM", SERVICE_ALL_ACCESS);
    if (server_handle == 0)
    {
      QMessageBox::warning(nullptr, "错误", "异常代码:1002");
      return;
    }
  }
  ChangeServiceConfig(server_handle, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
    driverpath.toStdWString().c_str(), NULL, NULL, NULL, NULL, NULL, L"CheatVMM");
  if (StartService(server_handle, NULL, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
  {
    this->stw = new Stowaways();
    //【配置
    this->stw->SetConf(use_ept, use_mode, antireference, protectdebuger, performance, antihardware, disablethread, supercontext);
    this->stw->LoginDebuger((char*)this->username.toStdString().c_str(), (char*)this->password.toStdString().c_str(), this->targetip.toInt());
    this->stw->AddToAntiDebug(-1);
    this->stw->HideDebuger();
    return;
  }
}
