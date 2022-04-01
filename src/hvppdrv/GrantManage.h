#pragma once
#include <ntifs.h>


typedef struct _HANDLE_TABLE
{
  ULONG_PTR TableCode;
  struct _EPROCESS* QuotaProcess;
  HANDLE UniqueProcessId;
  void* HandleLock;
  struct _LIST_ENTRY HandleTableList;
  EX_PUSH_LOCK HandleContentionEvent;
  struct _HANDLE_TRACE_DEBUG_INFO* DebugInfo;
  int ExtraInfoPages;
  ULONG Flags;
  ULONG FirstFreeHandle;
  struct _HANDLE_TABLE_ENTRY* LastFreeHandleEntry;
  ULONG HandleCount;
  ULONG NextHandleNeedingPool;
  // More fields here...
} HANDLE_TABLE, * PHANDLE_TABLE;

typedef union _EXHANDLE
{
  struct
  {
    int TagBits : 2;
    int Index : 30;
  } u;
  void* GenericHandleOverlay;
  ULONG_PTR Value;
} EXHANDLE, * PEXHANDLE;

typedef struct _HANDLE_TABLE_ENTRY // Size=16
{
  union
  {
    ULONG_PTR VolatileLowValue; // Size=8 Offset=0
    ULONG_PTR LowValue; // Size=8 Offset=0
    struct _HANDLE_TABLE_ENTRY_INFO* InfoTable; // Size=8 Offset=0
    struct
    {
      ULONG_PTR Unlocked : 1; // Size=8 Offset=0 BitOffset=0 BitCount=1
      ULONG_PTR RefCnt : 16; // Size=8 Offset=0 BitOffset=1 BitCount=16
      ULONG_PTR Attributes : 3; // Size=8 Offset=0 BitOffset=17 BitCount=3
      ULONG_PTR ObjectPointerBits : 44; // Size=8 Offset=0 BitOffset=20 BitCount=44
    };
  };
  union
  {
    ULONG_PTR HighValue; // Size=8 Offset=8
    struct _HANDLE_TABLE_ENTRY* NextFreeHandleEntry; // Size=8 Offset=8
    union _EXHANDLE LeafHandleValue; // Size=8 Offset=8
    struct
    {
      ULONG GrantedAccessBits : 25; // Size=4 Offset=8 BitOffset=0 BitCount=25
      ULONG NoRightsUpgrade : 1; // Size=4 Offset=8 BitOffset=25 BitCount=1
      ULONG Spare : 6; // Size=4 Offset=8 BitOffset=26 BitCount=6
    };
  };
  ULONG TypeInfo; // Size=4 Offset=12
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_GRANT_ACCESS
{
  ULONGLONG  handle;      // Handle to modify
  ULONG      pid;         // Process ID
  ULONG      access;      // Access flags to grant
} HANDLE_GRANT_ACCESS, * PHANDLE_GRANT_ACCESS;


#define EX_ADDITIONAL_INFO_SIGNATURE (ULONG_PTR)(-2)
#define ExpIsValidObjectEntry(Entry) \
    ( (Entry != NULL) && (Entry->LowValue != 0) && (Entry->HighValue != EX_ADDITIONAL_INFO_SIGNATURE) )

extern "C"
NTKERNELAPI
BOOLEAN
ExEnumHandleTable(
  IN PHANDLE_TABLE HandleTable,
  IN PVOID EnumHandleProcedure,
  IN PVOID EnumParameter,
  OUT PHANDLE Handle
);

extern "C"
NTKERNELAPI
VOID
FASTCALL
ExfUnblockPushLock(
  IN OUT PEX_PUSH_LOCK PushLock,
  IN OUT PVOID WaitBlock
);

class GrantManage
{


public:
  GrantManage();
  ~GrantManage();
  /// <summary>
  /// 修改线程的运行模式
  /// </summary>
  /// <param name="Th"></param>
  /// <param name="mode"></param>
  /// <returns></returns>
  NTSTATUS GrantThreadPreMode(HANDLE Th, MODE mode);
  NTSTATUS GrantThreadPreMode(PETHREAD Th, MODE mode);

  /// <summary>
  /// 改回线程的运行模式
  /// </summary>
  /// <param name="Th"></param>
  /// <param name="mode"></param>
  /// <returns></returns>
  NTSTATUS GrantThreadPreModeBack(HANDLE Th);
  NTSTATUS GrantThreadPreModeBack(PETHREAD Th);

  /// <summary>
  /// Change handle granted access
  /// </summary>
  /// <param name="pAccess">Request params</param>
  /// <returns>Status code</returns>
  NTSTATUS BBGrantAccess(IN PHANDLE_GRANT_ACCESS pAccess);

  /// <summary>
  /// 恢复到之前的权限
  /// </summary>
  /// <param name="pAccess"></param>
  /// <returns></returns>
  NTSTATUS BBGrantAccessBack();

private:
  HANDLE_GRANT_ACCESS PreHandleAccess;
  MODE PreMode;

private:
  /// <summary>
/// Handle enumeration callback
/// </summary>
/// <param name="HandleTable">Process handle table</param>
/// <param name="HandleTableEntry">Handle entry</param>
/// <param name="Handle">Handle value</param>
/// <param name="EnumParameter">User context</param>
/// <returns>TRUE when desired handle is found</returns>
  static BOOLEAN BBHandleCallbackWin7(
    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
    IN HANDLE Handle,
    IN PVOID EnumParameter
  );

  /// <summary>
  /// Handle enumeration callback
  /// </summary>
  /// <param name="HandleTable">Process handle table</param>
  /// <param name="HandleTableEntry">Handle entry</param>
  /// <param name="Handle">Handle value</param>
  /// <param name="EnumParameter">User context</param>
  /// <returns>TRUE when desired handle is found</returns>
  static BOOLEAN BBHandleCallback(
    IN PHANDLE_TABLE HandleTable,
    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
    IN HANDLE Handle,
    IN PVOID EnumParameter
  );
};
