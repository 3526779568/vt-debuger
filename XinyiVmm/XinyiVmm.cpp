#include "XinyiVmm.h"
#include "qt_windows.h"
#include "qsysinfo.h"
#include "basicinfo.h"
#include "qthread.h"
#include "qfiledialog.h"
#include "qmessagebox.h"
#include "qsettings.h"
#include "QtNetwork/qtcpsocket.h"
#include "qprocess.h"
#include "qsettings.h"
#include "qcryptographichash.h"
#include "quuid.h"
#include "libpe/libpe.h"


XinyiVmm::XinyiVmm(QWidget* parent)
  : QMainWindow(parent)
{
  ui.setupUi(this);
  this->setWindowFlag(Qt::WindowMaximizeButtonHint, false);
  this->setFixedSize(this->width(), this->height());
  auto sysinfo = QSysInfo::kernelVersion();
  this->ui.sysinfo->setText(sysinfo);
  BasicSystemInfo basicinfo;
  bool intel = true;
  this->ui.cpuinfo->setText(QString::fromStdString(basicinfo.GetCpuInfo(intel)).trimmed());
  this->user = nullptr;

  //采集系统版本
  auto silist = sysinfo.split(".");
  auto major = silist[0];
  auto minjor = silist[2];
  auto bugnum = 0;
  if (major == "10")
  {
    QSettings reg("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", QSettings::NativeFormat);
    auto Var = reg.value("UBR");
    bugnum = Var.toInt();
  }
  else
  {
    QSettings reg("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", QSettings::NativeFormat);
    auto Var = reg.value("BuildLabEx");
    bugnum = Var.toString().split(".")[1].toInt();
  }
  //校验是否支持
  QString hostip;
  QFile conffile(QCoreApplication::applicationDirPath() + "\\conf.ini");
  if (!conffile.open(QIODevice::OpenModeFlag::ReadOnly))
  {
    QMessageBox::warning(nullptr, "警告", "请先下载配置文件");
    return;
  }
  auto context = conffile.readAll();
  auto iplist = context.split('|');
  hostip = iplist[0] + "." + iplist[1] + "." + iplist[2] + "." + iplist[3];
  QTcpSocket client;
  client.connectToHost(hostip, 7222);
  client.write(QString().sprintf("%d,%d,%d,3", major.toInt(), minjor.toInt(), bugnum).toUtf8());
  client.waitForReadyRead();
  auto text = QString(client.readAll().toStdString().c_str());

  //自动填写账号密码
  QString pwd(QCoreApplication::applicationDirPath() + "\\pwd.conf");
  QSettings settings(pwd, QSettings::IniFormat);
  settings.value("pwd", "");
  this->ui.username->setText(settings.value("user", "").toString());
  this->ui.password->setText(settings.value("pwd", "").toString());

}

void XinyiVmm::LoginClicked()
{
  user = new User(this->ui.username->text(), this->ui.password->text());
  user->hdinfo = this->hdinfo;
  user->XinyiUserLogin();
  if (this->user->logined)
  {
    //保存当前账号密码
    QString pwd(QCoreApplication::applicationDirPath() + "\\pwd.conf");
    QSettings settings(pwd, QSettings::IniFormat);
    settings.setValue("user", this->ui.username->text());
    settings.setValue("pwd", this->ui.password->text());

    //this->user->use_ept = this->ui.use_ept->isChecked();
    this->user->use_ept = true;
    //this->user->use_mode = this->ui.use_mode->isChecked();
    this->user->use_mode = false;
    this->user->antireference = this->ui.AntiInterference->isChecked();
    this->user->protectdebuger = this->ui.ProtectDebuger->isChecked();
    this->user->performance = this->ui.Performance->isChecked();
    this->user->antihardware = this->ui.antihardware->isChecked();
    this->user->disablethread = this->ui.disablethread->isChecked();
    this->user->supercontext = this->ui.supercontext->isChecked();
    this->user->XinyiLoadDriver();
    this->ui.Login->setEnabled(false);
    this->ui.Open1->setEnabled(true);
    this->ui.Open2->setEnabled(true);
    this->ui.Open3->setEnabled(true);
    this->ui.Open4->setEnabled(true);
    this->ui.use_ept->setEnabled(false);
    this->ui.unuse_ept->setEnabled(false);
    this->ui.use_mode->setEnabled(false);
    this->ui.unuse_mode->setEnabled(false);

    this->setWindowTitle("登录成功");
  }
}

void XinyiVmm::RunDebuger(int id)
{
  auto filepath = QFileDialog::getOpenFileName(
    this, "选择调试器打开", nullptr, "exe(*.exe)"
  );
  if (filepath.isEmpty())
  {
    return;
  }
  if (!filepath.isEmpty())
  {
    switch (id)
    {
    case 1:
      this->ui.DebugPath1->setText(filepath);
      break;
    case 2:
      this->ui.DebugPath2->setText(filepath);
      break;
    case 3:
      this->ui.DebugPath3->setText(filepath);
      break;
    case 4:
      this->ui.DebugPath4->setText(filepath);
      break;
    }
    auto pathlist = filepath.toUpper().split('/');
    QString partten = "*";
    for (size_t i = 0; i < pathlist.size(); i++)
    {
      if (i == 0 || i + 1 == pathlist.size())
      {
        continue;
      }
      partten += pathlist[i];
      partten += "*";
    }
    SHELLEXECUTEINFO se{ 0 };
    se.cbSize = sizeof(SHELLEXECUTEINFO);
    se.lpVerb = L"runas";
    se.lpFile = new wchar_t[256];
    wcscpy((LPWSTR)se.lpFile, filepath.toStdWString().c_str());
    se.fMask = SEE_MASK_NOCLOSEPROCESS;
    se.nShow = SW_SHOWNORMAL;
    ShellExecuteEx(&se);
    if (!se.hProcess)
    {
      return;
    }
    auto pid = GetProcessId(se.hProcess);
    if (pid)
    {
      this->user->stw->AddToAntiDebug(pid);
    }
  }
}

void XinyiVmm::Open1Clicked()
{
  this->RunDebuger(1);
}

void XinyiVmm::Open2Clicked()
{
  this->RunDebuger(2);
}

void XinyiVmm::Open3Clicked()
{
  this->RunDebuger(3);
}

void XinyiVmm::Open4Clicked()
{
  this->RunDebuger(4);
}

void XinyiVmm::ClickConf()
{
  if (!this->user)
  {
    return;
  }
  this->user->use_ept = this->ui.use_ept->isChecked();
  this->user->use_mode = this->ui.use_mode->isChecked();
  this->user->antireference = this->ui.AntiInterference->isChecked();
  this->user->protectdebuger = this->ui.ProtectDebuger->isChecked();
  this->user->performance = this->ui.Performance->isChecked();
  this->user->antihardware = this->ui.antihardware->isChecked();
  this->user->disablethread = this->ui.disablethread->isChecked();
  this->user->supercontext = this->ui.supercontext->isChecked();
  if (this->user->stw)
  {
    this->user->stw->SetConf(this->user->use_ept,
      this->user->use_mode,
      this->user->antireference,
      this->user->protectdebuger,
      this->user->performance,
      this->user->antihardware,
      this->user->disablethread,
      this->user->supercontext);
  }
}
