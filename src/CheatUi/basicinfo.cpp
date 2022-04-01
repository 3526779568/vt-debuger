#include "afxdialogex.h"
#include "basicinfo.h"
#include <Shlwapi.h>
#include <windows.h>
#include <string>
#include <Iphlpapi.h>
#include <array>
#include "regedit/regedit.h"
#pragma comment(lib,"Iphlpapi.lib") 
#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "Shlwapi.lib")
using namespace std;


BasicSystemInfo::BasicSystemInfo()
{
  m_Query = NULL;
  m_CpuTotal = NULL;
  m_DiskRead = NULL;
  m_DiskWrite = NULL;
  m_NetDownload = NULL;
  m_NetUpload = NULL;
  //SystemInit();
}

BasicSystemInfo::~BasicSystemInfo()
{
  if (m_CpuTotal) {
    PdhRemoveCounter(m_CpuTotal);
    m_CpuTotal = NULL;
  }
  if (m_CpuTotal) {
    PdhRemoveCounter(m_CpuTotal);
    m_CpuTotal = NULL;
  }
  if (m_DiskRead) {
    PdhRemoveCounter(m_DiskRead);
    m_DiskRead = NULL;
  }
  if (m_DiskWrite) {
    PdhRemoveCounter(m_DiskWrite);
    m_DiskWrite = NULL;
  }
  if (m_NetDownload)
  {
    PdhRemoveCounter(m_NetDownload);
    m_NetDownload = NULL;
  }
  if (m_NetUpload)
  {
    PdhRemoveCounter(m_NetUpload);
    m_NetUpload = NULL;
  }
  if (m_Query) {
    PdhCloseQuery(m_Query);
    m_Query = NULL;
  }
  //SystemUnInit();
}


//初始化
void BasicSystemInfo::SystemInit(DWORD object)
{
  PDH_STATUS state;
  state = PdhOpenQuery(NULL, NULL, &m_Query);

  if (object & SYSSTATE_CPU_USAGE)	//CPU使用率
    state = PdhAddCounter(m_Query, _T("\\Processor(_Total)\\% Processor Time"), NULL, &m_CpuTotal);
  if (object & SYSSTATE_DISK_READ)	//磁盘读速度
    state = PdhAddCounter(m_Query, _T("\\PhysicalDisk(_Total)\\Disk Read Bytes/sec"), NULL, &m_DiskRead);
  if (object & SYSSTATE_DISK_WRITE)	//磁盘写速度
    state = PdhAddCounter(m_Query, _T("\\PhysicalDisk(_Total)\\Disk Write Bytes/sec"), NULL, &m_DiskWrite);
  if (object & SYSSTATE_NET_DOWNLOAD)//网络下载速度
    state = PdhAddCounter(m_Query, _T("\\Network Interface(killer E2200 Gigabit Ethernet Controller)\\Bytes Received/sec"), NULL, &m_NetDownload);
  if (object & SYSSTATE_NET_UPLOAD)	//网络上传速度
    state = PdhAddCounter(m_Query, _T("\\Network Interface(killer E2200 Gigabit Ethernet Controller)\\Bytes Sent/sec"), NULL, &m_NetUpload);

  state = PdhCollectQueryData(m_Query);
  Sleep(500);             //这里要有延时不然结果相当不准确  
  state = PdhCollectQueryData(m_Query);
}

//获取网络下载速度（K/s）
double BasicSystemInfo::GetSystemNetDownloadRate()
{
  PDH_FMT_COUNTERVALUE counterVal;
  PDH_STATUS lStatus = PdhGetFormattedCounterValue(m_NetDownload, PDH_FMT_DOUBLE, NULL, &counterVal);
  if (ERROR_SUCCESS != lStatus)  return -1;
  double dbVal = counterVal.doubleValue;
  double NetDownload = (double)((dbVal / (1024 * 1.0f)));
  return NetDownload;
}

//获取网络上传速度
double BasicSystemInfo::GetSystemNetUploadRate()
{
  PDH_FMT_COUNTERVALUE counterVal;
  PDH_STATUS lStatus = PdhGetFormattedCounterValue(m_NetUpload, PDH_FMT_DOUBLE, NULL, &counterVal);
  if (ERROR_SUCCESS != lStatus)  return -1;
  double dbVal = counterVal.doubleValue;
  double NetUpload = (double)((dbVal / (1024 * 1.0f)));
  return NetUpload;
}

//获取系统当前磁盘读速率(K/s)
double BasicSystemInfo::GetSystemDiskReadRate()
{
  PDH_FMT_COUNTERVALUE counterVal;
  PDH_STATUS lStatus = PdhGetFormattedCounterValue(m_DiskRead, PDH_FMT_DOUBLE, NULL, &counterVal);
  if (ERROR_SUCCESS != lStatus)  return -1;
  double dbVal = counterVal.doubleValue;
  double dbDiskRead = (double)((dbVal / (1024 * 1.0f)));
  return dbDiskRead;
}

//获取系统当前磁盘写速率
double BasicSystemInfo::GetSystemDiskWriteRate()
{
  PDH_FMT_COUNTERVALUE counterVal;
  PDH_STATUS lStatus = PdhGetFormattedCounterValue(m_DiskWrite, PDH_FMT_DOUBLE, NULL, &counterVal);
  if (ERROR_SUCCESS != lStatus)  return -1;
  double dbVal = counterVal.doubleValue;
  double dbDiskWrite = (double)((dbVal / (1024 * 1.0f)));
  return dbDiskWrite;
}

//获取CPU使用值
double BasicSystemInfo::GetSystemCpuCurrentUsage()
{
  PDH_FMT_COUNTERVALUE counterVal;
  // CPU时间，注意必须加上PDH_FMT_NOCAP100参数，否则多核CPU会有问题
  PDH_STATUS lStatus = PdhGetFormattedCounterValue(m_CpuTotal, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, NULL, &counterVal);
  if (ERROR_SUCCESS != lStatus)  return -1;
  return counterVal.doubleValue;//PDH_INVALID_ARGUMENT PDH_INVALID_DATA 
}

//反初始化
void BasicSystemInfo::SystemUnInit()
{
  if (m_CpuTotal) {
    PdhRemoveCounter(m_CpuTotal);
    m_CpuTotal = NULL;
  }
  if (m_DiskRead) {
    PdhRemoveCounter(m_DiskRead);
    m_DiskRead = NULL;
  }
  if (m_DiskWrite) {
    PdhRemoveCounter(m_DiskWrite);
    m_DiskWrite = NULL;
  }
  if (m_NetDownload)
  {
    PdhRemoveCounter(m_NetDownload);
    m_NetDownload = NULL;
  }
  if (m_NetUpload)
  {
    PdhRemoveCounter(m_NetUpload);
    m_NetUpload = NULL;
  }
  if (m_Query) {
    PdhCloseQuery(m_Query);
    m_Query = NULL;
  }
}

// 获取系统所有硬盘使用情况		
void BasicSystemInfo::GetSystemDiskStatus(ULONGLONG& AllDiskTotal, ULONGLONG& AllDiskFree)
{
  int DType = 0;
  int si = 0;
  BOOL bResult = FALSE;
  int DiskCount = 0;
  ULONGLONG nTempTotal = 0;
  ULONGLONG nTempFree = 0;

  ULONGLONG i64FreeBytesToCaller;
  ULONGLONG i64TotalBytes;
  ULONGLONG i64FreeBytes;

  //枚举磁盘数量
  DWORD DiskInfo = GetLogicalDrives();
  while (DiskInfo) {
    if (DiskInfo & 1) {
      ++DiskCount;
    }
    DiskInfo = DiskInfo >> 1;
  }
  int test = DiskCount;
  int DSLength = GetLogicalDriveStrings(0, NULL);

  TCHAR* DStr = NULL;
  while (!DStr) {
    DStr = new TCHAR[DSLength];
  }
  if (NULL == DStr) {
    return;
  }
  int nRet = GetLogicalDriveStrings(DSLength, (LPTSTR)DStr);

  //枚举磁盘名称
  for (int i = 0; i < DSLength / 4; i++) {
    TCHAR strDisk[3] = { 0 };
    _stprintf(strDisk, _T("%c:"), DStr[si]);
    DType = GetDriveType(DStr + i * 4);
    bResult = GetDiskFreeSpaceEx(
      strDisk,
      (PULARGE_INTEGER)&i64FreeBytesToCaller,
      (PULARGE_INTEGER)&i64TotalBytes,
      (PULARGE_INTEGER)&i64FreeBytes);

    if (bResult) {
      nTempTotal += (ULONGLONG)i64TotalBytes / 1024 / 1024 / 1024;
      nTempFree += (ULONGLONG)i64FreeBytesToCaller / 1024 / 1024 / 1024;
    }
    else {
      OutputDebugString(_T("设备未准备..."));
    }
    si += 4;
  }
  AllDiskTotal = nTempTotal;
  AllDiskFree = nTempFree;

  delete[] DStr;
}

// 获取系统各个硬盘使用情况		
void BasicSystemInfo::GetSystemDiskStatus(std::vector<EACHDISKSTATUS>& vectorDisk)
{
  int DType = 0;
  int si = 0;
  BOOL bResult = FALSE;
  int DiskCount = 0;
  ULONGLONG nTempTotal = 0;
  ULONGLONG nTempFree = 0;

  ULONGLONG i64FreeBytesToCaller;
  ULONGLONG i64TotalBytes;
  ULONGLONG i64FreeBytes;

  //枚举磁盘数量
  DWORD DiskInfo = GetLogicalDrives();
  while (DiskInfo) {
    if (DiskInfo & 1) {
      ++DiskCount;
    }
    DiskInfo = DiskInfo >> 1;
  }
  int test = DiskCount;
  int DSLength = GetLogicalDriveStrings(0, NULL);

  TCHAR* DStr = NULL;
  while (!DStr) {
    DStr = new TCHAR[DSLength];
  }
  if (NULL == DStr) {
    return;
  }
  int nRet = GetLogicalDriveStrings(DSLength, (LPTSTR)DStr);

  EACHDISKSTATUS diskstatus;
  //枚举磁盘名称
  for (int i = 0; i < DSLength / 4; i++) {
    TCHAR strDisk[3] = { 0 };
    _stprintf(strDisk, _T("%c:"), DStr[si]);
    DType = GetDriveType(DStr + i * 4);
    bResult = GetDiskFreeSpaceEx(
      strDisk,
      (PULARGE_INTEGER)&i64FreeBytesToCaller,
      (PULARGE_INTEGER)&i64TotalBytes,
      (PULARGE_INTEGER)&i64FreeBytes);

    if (bResult)
    {
      diskstatus._strdir = strDisk[0];
      double total = ((i64TotalBytes / 1024 / 1024) * 100) / 1024;
      diskstatus._Total = total / 100.0f;
      double OfFree = ((i64FreeBytesToCaller / 1024 / 1024) * 100) / 1024;
      diskstatus._OfFree = OfFree / 100.0f;
      vectorDisk.push_back(diskstatus);
    }
    else
    {
      OutputDebugString(_T("设备未准备..."));
    }
    si += 4;
  }

  delete[] DStr;
}

//获取系统当前磁盘状态
void BasicSystemInfo::GetSystemCurrentDiskStatus(ULONGLONG& TatolMB, ULONGLONG& FreeCaller)
{
  BOOL bResult = FALSE;
  ULONGLONG nTempTotal = 0;
  ULONGLONG nTempFree = 0;

  ULONGLONG ui64FreeBytesToCaller;
  ULONGLONG ui64TotalBytes;
  ULONGLONG ui64FreeBytes;

  TCHAR szModule[MAX_PATH * 2] = { 0 };
  GetModuleFileName(NULL, szModule, MAX_PATH * 2);
#ifdef _UNICODE
  wstring strPath(szModule);
  wstring strDirve = strPath.substr(0, 1);
#else
  std::string strPath(szModule);
  std::string strDirve = strPath.substr(0, 1);
#endif
  TCHAR szDisk[3] = { 0 };
  _stprintf(szDisk, _T("%c:"), strDirve[0]);
  bResult = GetDiskFreeSpaceEx(
    szDisk,
    (PULARGE_INTEGER)&ui64FreeBytesToCaller,	//用户可用的磁盘空间
    (PULARGE_INTEGER)&ui64TotalBytes,			//磁盘总共的空间
    (PULARGE_INTEGER)&ui64FreeBytes);			//磁盘空闲的空间.以上都是字节为单位。
  if (bResult) {
    nTempTotal = ui64TotalBytes / 1024 / 1024 / 1024;
    nTempFree = ui64FreeBytesToCaller / 1024 / 1024 / 1024;
    TatolMB = nTempTotal;
    FreeCaller = nTempFree;
  }
}

//获取系统当前磁盘使用率
double BasicSystemInfo::GetSystemCurrentDiskUsage()
{
  BOOL bResult = FALSE;
  ULONGLONG ui64FreeBytesToCaller;
  ULONGLONG ui64TotalBytes;
  ULONGLONG ui64FreeBytes;

  TCHAR szModule[MAX_PATH * 2] = { 0 };
  GetModuleFileName(NULL, szModule, MAX_PATH * 2);
  ::PathRemoveFileSpec(szModule);
#ifdef _UNICODE
  wstring strPath(szModule);
  wstring strDirve = strPath.substr(0, 1);
#else
  std::string strPath(szModule);
  std::string strDirve = strPath.substr(0, 1);
#endif

  TCHAR szDisk[3] = { 0 };
  _stprintf(szDisk, _T("%c:"), strDirve[0]);
  bResult = GetDiskFreeSpaceEx(
    szDisk,
    (PULARGE_INTEGER)&ui64FreeBytesToCaller,	//用户可用的磁盘空间
    (PULARGE_INTEGER)&ui64TotalBytes,			//磁盘总共的空间
    (PULARGE_INTEGER)&ui64FreeBytes);			//磁盘空闲的空间.以上都是字节为单位。
  if (bResult) {
    double TempNum = ((ui64TotalBytes / 1024 / 1024 / 1024) - (ui64FreeBytesToCaller / 1024 / 1024 / 1024)) * 100.0 / (ui64TotalBytes / 1024 / 1024 / 1024);
    return TempNum;
  }
  return 0;
}

//物理内存和使用
BOOL BasicSystemInfo::GetPhysicalMemoryState(ULONGLONG& totalPhysMem, ULONGLONG& physMemUsed)
{
  MEMORYSTATUSEX memInfo;
  memInfo.dwLength = sizeof(MEMORYSTATUSEX);
  GlobalMemoryStatusEx(&memInfo);
  totalPhysMem = memInfo.ullTotalPhys;
  physMemUsed = memInfo.ullTotalPhys - memInfo.ullAvailPhys;
  return TRUE;
}

//机器物理内存容量(总可用内存)
double BasicSystemInfo::GetTotalPhysicalMemory()
{
  MEMORYSTATUSEX memInfo;
  memInfo.dwLength = sizeof(MEMORYSTATUSEX);
  GlobalMemoryStatusEx(&memInfo);
  double totalPhysMem = ((memInfo.ullTotalPhys / 1024 / 1024) * 100) / 1024;
  double fTemptotal = totalPhysMem / 100.0;
  return fTemptotal;
}

//机器物理内存容量(空闲内存)
double BasicSystemInfo::GetTotalPhysicalMemoryFree()
{
  MEMORYSTATUSEX memInfo;
  memInfo.dwLength = sizeof(MEMORYSTATUSEX);
  GlobalMemoryStatusEx(&memInfo);
  double physMemFree = (((memInfo.ullAvailPhys) / 1024 / 1024) * 100) / 1024;;
  double fTemMemFree = physMemFree / 100.0;
  return fTemMemFree;
}

//机器物理内存使用(已使用内存)
double BasicSystemInfo::GetTotalPhysicalMemoryUsed()
{
  MEMORYSTATUSEX memInfo;
  memInfo.dwLength = sizeof(MEMORYSTATUSEX);
  GlobalMemoryStatusEx(&memInfo);
  double physMemUsed = (((memInfo.ullTotalPhys - memInfo.ullAvailPhys) / 1024 / 1024) * 100) / 1024;;
  double fTemMemUsed = physMemUsed / 100.0;
  return fTemMemUsed;
}

//机器物理内存使用率 
double BasicSystemInfo::GetPhysicalMemoryUsage()
{
  MEMORYSTATUSEX memInfo;
  memInfo.dwLength = sizeof(MEMORYSTATUSEX);
  GlobalMemoryStatusEx(&memInfo);
  double MemUsage = memInfo.dwMemoryLoad;
  return MemUsage;
}

//获取网卡信息（在获取网速时需要用到网卡描述）
void BasicSystemInfo::GetNetCardInfo(std::vector<NETCARDINFO>& vectorNetCard)
{

  NETCARDINFO NetCardInfo;

  PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
  //得到结构体大小,用于GetAdaptersInfo参数
  unsigned long stSize = sizeof(IP_ADAPTER_INFO);
  //调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量;其中stSize参数既是一个输入量也是一个输出量
  int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
  //记录网卡数量
  int netCardNum = 0;
  //记录每张网卡上的IP地址数量
  int IPnumPerNetCard = 0;
  if (ERROR_BUFFER_OVERFLOW == nRel)
  {
    //如果函数返回的是ERROR_BUFFER_OVERFLOW
    //则说明GetAdaptersInfo参数传递的内存空间不够,同时其传出stSize,表示需要的空间大小
    //这也是说明为什么stSize既是一个输入量也是一个输出量
    //释放原来的内存空间
    delete pIpAdapterInfo;
    //重新申请内存空间用来存储所有网卡信息
    pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
    //再次调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量
    nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
  }
  if (ERROR_SUCCESS == nRel)
  {
    //输出网卡信息
    //可能有多网卡,因此通过循环去判断
    while (pIpAdapterInfo)
    {
      ++netCardNum;				//网卡数量

      NetCardInfo.Name = pIpAdapterInfo->AdapterName;		//网卡名称
      NetCardInfo.Description = pIpAdapterInfo->Description;//网卡描述

      switch (pIpAdapterInfo->Type)//网卡类型
      {
      case MIB_IF_TYPE_OTHER:break;
      case MIB_IF_TYPE_ETHERNET:break;
      case MIB_IF_TYPE_TOKENRING:break;
      case MIB_IF_TYPE_FDDI:break;
      case MIB_IF_TYPE_PPP:break;
      case MIB_IF_TYPE_LOOPBACK:break;
      case MIB_IF_TYPE_SLIP:break;
      }
      //网卡MAC地址
      char tempchar[4];
      for (DWORD i = 0; i < pIpAdapterInfo->AddressLength; i++)
        if (i < pIpAdapterInfo->AddressLength - 1)
        {
          printf("%02X-", pIpAdapterInfo->Address[i]);

          sprintf(tempchar, "%02X-", pIpAdapterInfo->Address[i]);
          NetCardInfo.Local_Mac += tempchar;


        }
        else
        {
          printf("%02X", pIpAdapterInfo->Address[i]);

          sprintf(tempchar, "%02X", pIpAdapterInfo->Address[i]);
          NetCardInfo.Local_Mac += tempchar;

        }

      //网卡IP地址
      //可能网卡有多IP,因此通过循环去判断
      IP_ADDR_STRING* pIpAddrString = &(pIpAdapterInfo->IpAddressList);
      do
      {
        //cout<<"该网卡上的IP数量："<<++IPnumPerNetCard<<endl;
        //cout<<"IP 地址："<<pIpAddrString->IpAddress.String<<endl;
        //cout<<"子网地址："<<pIpAddrString->IpMask.String<<endl;
        //cout<<"网关地址："<<pIpAdapterInfo->GatewayList.IpAddress.String<<endl;

        NetCardInfo.Local_IP = pIpAddrString->IpAddress.String;

        pIpAddrString = pIpAddrString->Next;
      } while (pIpAddrString);

      vectorNetCard.push_back(NetCardInfo);

      pIpAdapterInfo = pIpAdapterInfo->Next;
    }

  }
  if (pIpAdapterInfo)
  {
    delete pIpAdapterInfo;

    pIpAdapterInfo = NULL;
  }
}

//获取操作系统信息 
int BasicSystemInfo::GetOsInfo(std::string& osinfo)
{
  // get os name according to version number
  RegEdit reg;
  string CurrentBuildNumber;
  string ProductName;
  reg.selectRootKey(2);
  reg.getKeyValue((char*)"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
    (char*)"CurrentBuildNumber",
    CurrentBuildNumber);
  reg.getKeyValue((char*)"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
    (char*)"ProductName",
    ProductName);
 
  osinfo = ProductName + " " + CurrentBuildNumber;
  return atoi(CurrentBuildNumber.c_str());
}

//获取CPU硬件信息 
void BasicSystemInfo::GetCpuInfo(std::string& CPUinfo)
{
  int cpuInfo[4] = { -1 };
  char cpu_manufacture[32] = { 0 };
  char cpu_type[32] = { 0 };
  char cpu_freq[32] = { 0 };

  __cpuid(cpuInfo, 0x80000002);
  memcpy(cpu_manufacture, cpuInfo, sizeof(cpuInfo));

  __cpuid(cpuInfo, 0x80000003);
  memcpy(cpu_type, cpuInfo, sizeof(cpuInfo));

  __cpuid(cpuInfo, 0x80000004);
  memcpy(cpu_freq, cpuInfo, sizeof(cpuInfo));

  std::string manufacture = cpu_manufacture;//制造商
  std::string type = cpu_type;				//型号
  std::string freq = cpu_freq;				//频率
  CPUinfo = manufacture + type + freq;
}

string BasicSystemInfo::GetCpuInfo(bool Intel)
{
  array<int, 4> cpui;
  vector<std::array<int, 4>> data_;
  std::string vendor_;
  vector<std::array<int, 4>> extdata_;
  std::string brand_;

  __cpuid(cpui.data(), 0);
  auto nIds_ = cpui[0];

  for (int i = 0; i <= nIds_; ++i)
  {
    __cpuidex(cpui.data(), i, 0);
    data_.push_back(cpui);
  }

  // Capture vendor string
  char vendor[0x20];
  memset(vendor, 0, sizeof(vendor));
  *reinterpret_cast<int*>(vendor) = data_[0][1];
  *reinterpret_cast<int*>(vendor + 4) = data_[0][3];
  *reinterpret_cast<int*>(vendor + 8) = data_[0][2];

  vendor_ = vendor;
  if (vendor_ == "GenuineIntel")
  {
    Intel = true;
  }
  else if (vendor_ == "AuthenticAMD")
  {
    Intel = false;
  }

  // load bitset with flags for function 0x00000001
  if (nIds_ >= 1)
  {
    auto f_1_ECX_ = data_[1][2];
    auto f_1_EDX_ = data_[1][3];
  }

  // load bitset with flags for function 0x00000007
  if (nIds_ >= 7)
  {
    auto f_7_EBX_ = data_[7][1];
    auto f_7_ECX_ = data_[7][2];
  }

  // Calling __cpuid with 0x80000000 as the function_id argument
  // gets the number of the highest valid extended ID.
  __cpuid(cpui.data(), 0x80000000);
  auto nExIds_ = cpui[0];

  char brand[0x40];
  memset(brand, 0, sizeof(brand));

  for (int i = 0x80000000; i <= nExIds_; ++i)
  {
    __cpuidex(cpui.data(), i, 0);
    extdata_.push_back(cpui);
  }

  // load bitset with flags for function 0x80000001
  if (nExIds_ >= 0x80000001)
  {
    auto f_81_ECX_ = extdata_[1][2];
    auto f_81_EDX_ = extdata_[1][3];
  }

  // Interpret CPU brand string if reported
  if (nExIds_ >= 0x80000004)
  {
    memcpy(brand, extdata_[2].data(), sizeof(cpui));
    memcpy(brand + 16, extdata_[3].data(), sizeof(cpui));
    memcpy(brand + 32, extdata_[4].data(), sizeof(cpui));
    brand_ = brand;
  }
  return brand_;
}



BOOL BasicSystemInfo::GetHDSerial(std::string& HDSerial)
{
  BOOL		bRtn = FALSE;
  DWORD		bytesRtn = 0;
  char		szhd[80] = { 0 };
  PIDSECTOR	phdinfo;
  HANDLE		hDrive = NULL;
  GETVERSIONOUTPARAMS vers;
  SENDCMDINPARAMS		in;
  SENDCMDOUTPARAMS	out;

  ZeroMemory(&vers, sizeof(vers));
  ZeroMemory(&in, sizeof(in));
  ZeroMemory(&out, sizeof(out));

  //搜索四个物理硬盘，取第一个有数据的物理硬盘 
  for (int j = 0; j < 4; j++)
  {
    sprintf(szhd, "\\\\.\\PhysicalDrive%d", j);
    hDrive = CreateFileA(szhd,
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      0,
      OPEN_EXISTING,
      0,
      0);
    if (NULL == hDrive)continue;

    if (!DeviceIoControl(hDrive, DFP_GET_VERSION, 0, 0, &vers, sizeof(vers), &bytesRtn, 0))goto FOREND;
    //If IDE identify command not supported, fails 
    if (!(vers.fCapabilities & 1))goto FOREND;

    //Identify the IDE drives 
    if (j & 1)in.irDriveRegs.bDriveHeadReg = 0xb0;
    else in.irDriveRegs.bDriveHeadReg = 0xa0;

    if (vers.fCapabilities & (16 >> j))goto FOREND;	//We don't detect a ATAPI device. 
    else in.irDriveRegs.bCommandReg = 0xec;

    in.bDriveNumber = j;
    in.irDriveRegs.bSectorCountReg = 1;
    in.irDriveRegs.bSectorNumberReg = 1;
    in.cBufferSize = 512;

    if (!DeviceIoControl(hDrive, DFP_RECEIVE_DRIVE_DATA, &in, sizeof(in), &out, sizeof(out), &bytesRtn, 0))
    {
      //"DeviceIoControl failed:DFP_RECEIVE_DRIVE_DATA"<<endl; 
      goto FOREND;
    }
    phdinfo = (PIDSECTOR)out.bBuffer;

    char	s[21] = { 0 };
    memcpy(s, phdinfo->sSerialNumber, 20);
    s[20] = 0;
    ChangeByteOrder(s, 20);

    //删除空格字符
    int ix = 0;
    for (ix = 0; ix < 20; ix++)
    {
      if (s[ix] == ' ')continue;
      break;
    }
    char lpszHD[128] = { 0 };
    memcpy(lpszHD, s + ix, 20);

    HDSerial = lpszHD;

    bRtn = TRUE;
    if (bRtn)break;
  FOREND:
    CloseHandle(hDrive);
    hDrive = NULL;
  }

  CloseHandle(hDrive);
  hDrive = NULL;
  return(bRtn);
}
