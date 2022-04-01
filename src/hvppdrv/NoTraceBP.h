#pragma once
#include <ntifs.h>
#include <EASTL/vector.h>
#include <EASTL/set.h>
#include <EASTL/map.h>
#include "winbase.h"
using namespace eastl;

class BreakPoint
{
public:
  BreakPoint();
  ~BreakPoint();
public:
  ULONG64 address;
  int size;
  /*统一读写属性，没有执行*/
public:
  bool operator== (BreakPoint other);
  bool operator== (ULONG64 other);
  bool operator== (PVOID other);
  bool operator> (BreakPoint other);
  bool operator< (BreakPoint other);

private:
};

class PageMonitor
{
public:
  PageMonitor();
  ~PageMonitor();
public:
  bool operator== (PageMonitor other);
  bool operator< (PageMonitor other);
  bool operator> (PageMonitor other);
public:
  PVOID page_va;
  PVOID page_pa;
  PMDL rwe_mdl;
  bool locked;
  PEPROCESS eprocess;

private:

};

class InfEvent
{
public:
  InfEvent() {};
  ~InfEvent() {};
public:
  map<PEPROCESS, bool> last_inf; //用来通知调试器有调试事件需要获取
  map<PEPROCESS, bool> last_lock;//用来VT内部多核互斥
  map<PEPROCESS, LPDEBUG_EVENT> debugevent;

private:

};

class NoTraceBP
{
public:
  NoTraceBP();
  ~NoTraceBP();
public:
  BreakPoint current_bp;
  PageMonitor pagemonitor;

public:
  bool IsAddressInBp(ULONG64 address);
  bool IsBpInBp(BreakPoint other);
  bool IsBpInCurrentBp(BreakPoint other);
  bool AddBp(BreakPoint& bp);
  bool RemoveBp();

  bool AddPmToMonitor(PageMonitor pm);
  bool RemoveFromMonitor();

private:

};
