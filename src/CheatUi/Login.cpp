// Login.cpp: 实现文件
//

#include "pch.h"
#include "CheatUi.h"
#include "Login.h"
#include "afxdialogex.h"
#include <Winsvc.h>
#include "MemoryModule.h"
#include <vector>
#include "Stowaways.h"
#include "IsBeingDebuged.h"
#include <vector>
#include <array>
#include "basicinfo.h"
#include "util.h"
using namespace std;



// Login 对话框

IMPLEMENT_DYNAMIC(Login, CDialogEx)

Login::Login(CWnd* pParent /*=nullptr*/)
  : CDialogEx(IDD_LOGIN, pParent)
{

}

Login::~Login()
{
}

void Login::DoDataExchange(CDataExchange* pDX)
{
  CDialogEx::DoDataExchange(pDX);
  DDX_Control(pDX, IDC_ID, UserName);
  DDX_Control(pDX, IDC_PASSWORD, PassWord);
}


BEGIN_MESSAGE_MAP(Login, CDialogEx)
  ON_BN_CLICKED(IDC_LOGIN, &Login::UserLogin)
  ON_BN_CLICKED(IDC_DEBUG_OPEN1, &Login::OnBnClickedDebugOpen1)
  ON_BN_CLICKED(IDC_DEBUG_OPEN2, &Login::OnBnClickedDebugOpen2)
  ON_BN_CLICKED(IDC_DEBUG_OPEN3, &Login::OnBnClickedDebugOpen3)
  ON_BN_CLICKED(IDC_DEBUG_OPEN4, &Login::OnBnClickedDebugOpen4)
  ON_BN_CLICKED(IDC_NOEPT, &Login::OnBnClickedNoept)
  ON_BN_CLICKED(IDC_USEEPT, &Login::OnBnClickedUseept)
  ON_BN_CLICKED(IDC_READ1, &Login::OnBnClickedRead1)
  ON_BN_CLICKED(IDC_READ2, &Login::OnBnClickedRead2)
END_MESSAGE_MAP()


// Login 消息处理程序
char username[256], password[256];
FILE* fh;
char conf[256];
int targetip = 0;
Stowaways* stw = nullptr;
void Login::UserLogin()
{
  // TODO: 在此添加控件通知处理程序代码
  if (!IsUserAnAdmin())
  {
    this->EndDialog(0);
  }
  char filename[256];
  //判断当前文件名
  ::GetModuleFileNameA(NULL, filename, 256);
  if (strstr(filename, "CheatUi") == NULL)
  {
    this->EndDialog(0);
  }

  CString buff;
  UserName.GetWindowTextW(buff);
  memcpy(username, Util::wide_ansi(buff.GetString()).c_str(), buff.GetLength() + 1);
  username[buff.GetLength() + 1] = 0;
  PassWord.GetWindowTextW(buff);
  memcpy(password, Util::wide_ansi(buff.GetString()).c_str(), buff.GetLength() + 1);
  password[buff.GetLength() + 1] = 0;
  if (strlen(username) == 0 || strlen(password) == 0)
  {
    MessageBox(L"Input Error");
  }
  auto token = strtok(conf, "|"); // C4996
  vector<int> key;
  // Note: strtok is deprecated; consider using strtok_s instead
  while (token != NULL)
  {
    // While there are tokens in "string"
    key.push_back(atoi(token));

    // Get next token:
    token = strtok(NULL, "|"); // C4996
  }
  targetip = (key[3] << 24) | (key[2] << 16) | (key[1] << 8) | (key[0]);
  //创建Socket
  auto sid = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  sockaddr_in sin = { 0 };
  sin.sin_family = AF_INET;
  sin.sin_addr.S_un.S_addr = targetip;
  sin.sin_port = htons(7222);
  //连接远程
  auto error = connect(sid, (sockaddr*)&sin, sizeof(sin));
  if (error)
  {
    this->EndDialog(0);
  }
  //发送的数据
  string data;
  data += username;
  data += ",";
  data += password;
  data += ",";
  data += "1";

  CString dirpath = L"*";
  //切割当前运行目录字符串
  WCHAR currentdir[260];
  ::GetCurrentDirectory(sizeof(currentdir), currentdir);
  auto cstr = Util::wide_ansi(CString(currentdir).MakeUpper().GetString());
  token = strtok((char*)cstr.c_str(), "\\"); // C4996
  vector<string> strlist;
  // Note: strtok is deprecated; consider using strtok_s instead
  while (token != NULL)
  {
    // While there are tokens in "string"
    strlist.push_back(token);
    // Get next token:
    token = strtok(NULL, "\\"); // C4996
  }
  //拼接成文件路径
  for (size_t i = 0; i < strlist.size(); i++)
  {
    if (i == 0 || i + 1 == strlist.size())
    {
      continue;
    }
    dirpath.Append(Util::ansi_wide(strlist[i].c_str()).c_str());
    dirpath.Append(L"*");
  }

  //登录
  char bf[256] = { 0 };
  send(sid, data.c_str(), data.length(), 0);
  recv(sid, bf, 256, 0);
  closesocket(sid);
  if (strstr(bf, "unsuccess") == NULL && strstr(bf, "success") != NULL)
  {

    //登录成功,加载驱动
    this->GetDlgItem(IDC_LOGIN)->EnableWindow(FALSE);
    TCHAR szpath[MAX_PATH];
    ::GetModuleFileName(NULL, szpath, MAX_PATH);
    CString PathName(szpath);
    auto th(PathName.Left(PathName.ReverseFind(_T('\\')) + 1));
    th.Append(L"CheatVMM.sys");
    auto sc_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    auto server_handle = CreateService(sc_handle, L"CheatVMM", L"CheatVMM", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
      SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, th.GetString(), NULL, NULL, NULL, NULL, NULL);
    if (!server_handle && GetLastError() != ERROR_SERVICE_EXISTS)
    {
      MessageBox(L"Admin Run");
      return;
    }
    if (server_handle == 0)
    {
      server_handle = OpenService(sc_handle, L"CheatVMM", SERVICE_ALL_ACCESS);
      if (server_handle == 0)
      {
        MessageBox(L"Admin Run");
        return;
      }
    }
    ChangeServiceConfig(server_handle, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
      th.GetString(), NULL, NULL, NULL, NULL, NULL, L"CheatVMM");
    if (StartService(server_handle, NULL, NULL) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
    {
      stw = new Stowaways;

      this->GetDlgItem(IDC_LOGIN)->EnableWindow(FALSE);
      //【配置
      bool use_ept = ((CButton*)this->GetDlgItem(IDC_USEEPT))->GetCheck();
      bool use_mode = ((CButton*)this->GetDlgItem(IDC_READ2))->GetCheck();

      this->GetDlgItem(IDC_USEEPT)->EnableWindow(FALSE);
      this->GetDlgItem(IDC_NOEPT)->EnableWindow(FALSE);
      this->GetDlgItem(IDC_READ1)->EnableWindow(FALSE);
      this->GetDlgItem(IDC_READ2)->EnableWindow(FALSE);
      this->GetDlgItem(IDC_DEBUG_OPEN1)->EnableWindow(TRUE);
      this->GetDlgItem(IDC_DEBUG_OPEN2)->EnableWindow(TRUE);
      this->GetDlgItem(IDC_DEBUG_OPEN3)->EnableWindow(TRUE);
      this->GetDlgItem(IDC_DEBUG_OPEN4)->EnableWindow(TRUE);

      stw->SetConf(use_ept, use_mode);

      stw->LoginDebuger();
      stw->AddToAntiDebug(-1);
      stw->HideDebuger();
      //stw->HideFile((wchar_t*)dirpath.GetString());

      OutputDebugString(_T("开启成功，请尽情调试"));
      this->SetWindowTextW(_T("登录成功"));

      //起线程监视
      /*AfxBeginThread([](PVOID param)->UINT {
        auto login = (Login*)param;
        login->AntiDebugerAndLockUser();
        exit(0);
        return 0;
        }, this);*/
      return;
    }
  }
}

void Login::AntiDebugerAndLockUser()
{
  while (true)
  {
    auto debuged = CheckDebugALL();
    auto Bitcount = stw->GetFromAntiDebug();
    if (Bitcount || debuged)
    {
      //发送的数据
      string data;
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
      sin.sin_addr.S_un.S_addr = targetip;
      sin.sin_port = htons(7222);
      auto error = connect(sid, (sockaddr*)&sin, sizeof(sin));
      send(sid, data.c_str(), data.length(), 0);
      closesocket(sid);
    }
    Sleep(5000);
  }
  return;
}

CString Login::OpenDebugFile()
{
  //AFX_MANAGE_STATE(AfxGetAppModuleState());
  //BOOL isOpen = TRUE;		//是否打开(否则为保存)
  //CString defaultDir = L"C:\\";	//默认打开的文件路径
  //CString fileName = L"";			//默认打开的文件名
  //CString filter = L"文件 (*.exe)|*.exe||";	//文件过虑的类型
  //CFileDialog openFileDlg(isOpen, defaultDir, fileName, OFN_HIDEREADONLY | OFN_READONLY, filter);
  //INT_PTR result = openFileDlg.DoModal();
  OPENFILENAME ofn;       // common dialog box structure
  char szFile[260];       // buffer for file name
  HWND hwnd;              // owner window
  HANDLE hf;              // file handle

  // Initialize OPENFILENAME
  ZeroMemory(&ofn, sizeof(ofn));
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = nullptr;
  //
  // Set lpstrFile[0] to '\0' so that GetOpenFileName does not 
  // use the contents of szFile to initialize itself.
  //
  ofn.nMaxFile = sizeof(szFile);
  ofn.lpstrFilter = L"exe\0*.exe\0";
  ofn.nFilterIndex = 1;
  ofn.lpstrFileTitle = NULL;
  ofn.nMaxFileTitle = 0;
  ofn.lpstrInitialDir = NULL;
  ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
  CString filePath;
  // Display the Open dialog box. 
  try
  {
    if (GetOpenFileName(&ofn) == TRUE)
    {
      filePath = ofn.lpstrFile;
    }
  }
  catch (const std::exception& e)
  {
    MessageBoxA(0, e.what(), 0, 0);
  }
  MessageBox(0, filePath, 0);
  return filePath;
}

BOOL Login::OnInitDialog()
{
  CDialogEx::OnInitDialog();
  // TODO:  在此添加额外的初始化
  //判断管理员登录
  if (!IsUserAnAdmin())
  {
    this->EndDialog(0);
  }

  // Initialize Winsock
  WSADATA wsaData;
  int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (iResult != NO_ERROR) {
    this->EndDialog(1);
  }
  //加载配置文件
  auto error = fopen_s(&fh, "conf.ini", "r");
  if (!fh)
  {
    MessageBox(L"缺少配置文件");
    this->EndDialog(1);
  }
  fgets(conf, 100, fh);
  fclose(fh);
  bool IsIntel = false;
  //this->SetDlgItemTextW(IDC_CPUInfo, slt.ansi_wide(cinfo.c_str()).c_str());
  BasicSystemInfo binfo;
  string cuinfo, sysinfo;
  binfo.GetCpuInfo(cuinfo);
  auto buildNumber = binfo.GetOsInfo(sysinfo);
  if (!cuinfo.empty())
  {
    cuinfo.erase(0, cuinfo.find_first_not_of(" "));
    cuinfo.erase(cuinfo.find_last_not_of(" ") + 1);
  }
  this->SetDlgItemTextW(IDC_CPUInfo, Util::ansi_wide(cuinfo.c_str()).c_str());
  this->SetDlgItemTextW(IDC_SysInfo, Util::ansi_wide(sysinfo.c_str()).c_str());

  //设置提示语
  Edit_SetCueBannerText(this->GetDlgItem(IDC_ID)->GetSafeHwnd(), L"用户名");
  Edit_SetCueBannerText(this->GetDlgItem(IDC_PASSWORD)->GetSafeHwnd(), L"密码");
  ((CButton*)this->GetDlgItem(IDC_NOEPT))->SetCheck(true);
  ((CButton*)this->GetDlgItem(IDC_READ1))->SetCheck(true);

  return TRUE;  // return TRUE unless you set the focus to a control
          // 异常: OCX 属性页应返回 FALSE
}

BOOL Login::DestroyWindow()
{
  //// TODO: 在此添加专用代码和/或调用基类
  return CDialogEx::DestroyWindow();
}



void Login::RunDebuger(int id)
{
  stw->ShowFile();
  CString filepath = OpenDebugFile();
  if (!filepath.IsEmpty())
  {
    this->SetDlgItemTextW(id, filepath);
    CString dirpath = L"*";
    //切割字符串
    auto cstr = Util::wide_ansi(filepath.MakeUpper().GetString());
    auto token = strtok((char*)cstr.c_str(), "\\"); // C4996
    vector<string> strlist;
    // Note: strtok is deprecated; consider using strtok_s instead
    while (token != NULL)
    {
      // While there are tokens in "string"
      strlist.push_back(token);
      // Get next token:
      token = strtok(NULL, "\\"); // C4996
    }
    //拼接成文件路径
    for (size_t i = 0; i < strlist.size(); i++)
    {
      if (i == 0 || i + 1 == strlist.size())
      {
        continue;
      }
      dirpath.Append(Util::ansi_wide(strlist[i].c_str()).c_str());
      dirpath.Append(L"*");//通配符
    }
    SHELLEXECUTEINFO se{ 0 };
    se.cbSize = sizeof(SHELLEXECUTEINFO);
    se.lpVerb = L"runas";
    se.lpFile = filepath;
    se.fMask = SEE_MASK_NOCLOSEPROCESS;
    se.nShow = SW_SHOW;
    ShellExecuteEx(&se);
    auto pid = ::GetProcessId(se.hProcess);
    if (pid)
    {
      stw->AddToAntiDebug(pid);
      //取父文件夹
      //\Device\HarddiskVolume1\Users\Z\Desktop
      //\Device\HarddiskVolume2
      stw->HideDebuger();
      stw->HideFile((wchar_t*)dirpath.GetString());
    }
  }
}

void Login::OnBnClickedDebugOpen1()
{
  // TODO: 在此添加控件通知处理程序代码
  RunDebuger(IDC_DEBUG_PATH1);
}


void Login::OnBnClickedDebugOpen2()
{
  // TODO: 在此添加控件通知处理程序代码
  RunDebuger(IDC_DEBUG_PATH2);
}


void Login::OnBnClickedDebugOpen3()
{
  // TODO: 在此添加控件通知处理程序代码
  RunDebuger(IDC_DEBUG_PATH3);
}


void Login::OnBnClickedDebugOpen4()
{
  // TODO: 在此添加控件通知处理程序代码
  RunDebuger(IDC_DEBUG_PATH4);
}


void Login::OnBnClickedNoept()
{
  // TODO: 在此添加控件通知处理程序代码
  ((CButton*)this->GetDlgItem(IDC_NOEPT))->SetCheck(true);
}


void Login::OnBnClickedUseept()
{
  // TODO: 在此添加控件通知处理程序代码
  ((CButton*)this->GetDlgItem(IDC_USEEPT))->SetCheck(true);
}


void Login::OnBnClickedRead1()
{
  // TODO: 在此添加控件通知处理程序代码
  ((CButton*)this->GetDlgItem(IDC_READ1))->SetCheck(true);
}


void Login::OnBnClickedRead2()
{
  // TODO: 在此添加控件通知处理程序代码
  ((CButton*)this->GetDlgItem(IDC_READ2))->SetCheck(true);
}
