#pragma once
#include <ntifs.h>
#ifndef NTWIN10_1903_H
#define NTWIN10_1903_H
namespace ntwin10_1903 {
  typedef union _KEXECUTE_OPTIONS                           // 10 elements, 0x1 bytes (sizeof) 
  {
    struct                                                // 8 elements, 0x1 bytes (sizeof)  
    {
      /*0x000*/         UINT8        ExecuteDisable : 1;                  // 0 BitPosition                   
      /*0x000*/         UINT8        ExecuteEnable : 1;                   // 1 BitPosition                   
      /*0x000*/         UINT8        DisableThunkEmulation : 1;           // 2 BitPosition                   
      /*0x000*/         UINT8        Permanent : 1;                       // 3 BitPosition                   
      /*0x000*/         UINT8        ExecuteDispatchEnable : 1;           // 4 BitPosition                   
      /*0x000*/         UINT8        ImageDispatchEnable : 1;             // 5 BitPosition                   
      /*0x000*/         UINT8        DisableExceptionChainValidation : 1; // 6 BitPosition                   
      /*0x000*/         UINT8        Spare : 1;                           // 7 BitPosition                   
    };
    /*0x000*/     UINT8        ExecuteOptions;
    /*0x000*/     UINT8        ExecuteOptionsNV;
  }KEXECUTE_OPTIONS, * PKEXECUTE_OPTIONS;
  typedef union _KSTACK_COUNT           // 3 elements, 0x4 bytes (sizeof) 
  {
    /*0x000*/     LONG32       Value;
    struct                            // 2 elements, 0x4 bytes (sizeof) 
    {
      /*0x000*/         ULONG32      State : 3;       // 0 BitPosition                  
      /*0x000*/         ULONG32      StackCount : 29; // 3 BitPosition                  
    };
  }KSTACK_COUNT, * PKSTACK_COUNT;
  typedef struct _RTL_AVL_TREE         // 1 elements, 0x8 bytes (sizeof) 
  {
    /*0x000*/     struct _RTL_BALANCED_NODE* Root;
  }RTL_AVL_TREE, * PRTL_AVL_TREE;
  typedef struct _KAFFINITY_EX // 4 elements, 0xA8 bytes (sizeof) 
  {
    /*0x000*/     UINT16       Count;
    /*0x002*/     UINT16       Size;
    /*0x004*/     ULONG32      Reserved;
    /*0x008*/     UINT64       Bitmap[20];
  }KAFFINITY_EX, * PKAFFINITY_EX;
  typedef struct _SE_AUDIT_PROCESS_CREATION_INFO      // 1 elements, 0x8 bytes (sizeof) 
  {
    /*0x000*/     struct _OBJECT_NAME_INFORMATION* ImageFileName;
  }SE_AUDIT_PROCESS_CREATION_INFO, * PSE_AUDIT_PROCESS_CREATION_INFO;
  typedef struct _EX_FAST_REF      // 3 elements, 0x8 bytes (sizeof) 
  {
    union                        // 3 elements, 0x8 bytes (sizeof) 
    {
      /*0x000*/         VOID* Object;
      /*0x000*/         UINT64       RefCnt : 4; // 0 BitPosition                  
      /*0x000*/         UINT64       Value;
    };
  }EX_FAST_REF, * PEX_FAST_REF;
  typedef struct _MMSUPPORT_FLAGS                         // 17 elements, 0x4 bytes (sizeof) 
  {
    union                                               // 2 elements, 0x2 bytes (sizeof)  
    {
      struct                                          // 2 elements, 0x2 bytes (sizeof)  
      {
        struct                                      // 4 elements, 0x1 bytes (sizeof)  
        {
          /*0x000*/                 UINT8        WorkingSetType : 3;        // 0 BitPosition                   
          /*0x000*/                 UINT8        Reserved0 : 3;             // 3 BitPosition                   
          /*0x000*/                 UINT8        MaximumWorkingSetHard : 1; // 6 BitPosition                   
          /*0x000*/                 UINT8        MinimumWorkingSetHard : 1; // 7 BitPosition                   
        };
        struct                                      // 4 elements, 0x1 bytes (sizeof)  
        {
          /*0x001*/                 UINT8        SessionMaster : 1;         // 0 BitPosition                   
          /*0x001*/                 UINT8        TrimmerState : 2;          // 1 BitPosition                   
          /*0x001*/                 UINT8        Reserved : 1;              // 3 BitPosition                   
          /*0x001*/                 UINT8        PageStealers : 4;          // 4 BitPosition                   
        };
      };
      /*0x000*/         UINT16       u1;
    };
    /*0x002*/     UINT8        MemoryPriority;
    union                                               // 2 elements, 0x1 bytes (sizeof)  
    {
      struct                                          // 6 elements, 0x1 bytes (sizeof)  
      {
        /*0x003*/             UINT8        WsleDeleted : 1;               // 0 BitPosition                   
        /*0x003*/             UINT8        SvmEnabled : 1;                // 1 BitPosition                   
        /*0x003*/             UINT8        ForceAge : 1;                  // 2 BitPosition                   
        /*0x003*/             UINT8        ForceTrim : 1;                 // 3 BitPosition                   
        /*0x003*/             UINT8        NewMaximum : 1;                // 4 BitPosition                   
        /*0x003*/             UINT8        CommitReleaseState : 2;        // 5 BitPosition                   
      };
      /*0x003*/         UINT8        u2;
    };
  }MMSUPPORT_FLAGS, * PMMSUPPORT_FLAGS;
  typedef struct _MMSUPPORT_INSTANCE               // 19 elements, 0xC0 bytes (sizeof) 
  {
    /*0x000*/     ULONG32      NextPageColor;
    /*0x004*/     ULONG32      PageFaultCount;
    /*0x008*/     UINT64       TrimmedPageCount;
    /*0x010*/     struct _MMWSL_INSTANCE* VmWorkingSetList;
    /*0x018*/     struct _LIST_ENTRY WorkingSetExpansionLinks; // 2 elements, 0x10 bytes (sizeof)  
    /*0x028*/     UINT64       AgeDistribution[8];
    /*0x068*/     struct _KGATE* ExitOutswapGate;
    /*0x070*/     UINT64       MinimumWorkingSetSize;
    /*0x078*/     UINT64       WorkingSetLeafSize;
    /*0x080*/     UINT64       WorkingSetLeafPrivateSize;
    /*0x088*/     UINT64       WorkingSetSize;
    /*0x090*/     UINT64       WorkingSetPrivateSize;
    /*0x098*/     UINT64       MaximumWorkingSetSize;
    /*0x0A0*/     UINT64       PeakWorkingSetSize;
    /*0x0A8*/     ULONG32      HardFaultCount;
    /*0x0AC*/     UINT16       LastTrimStamp;
    /*0x0AE*/     UINT16       PartitionId;
    /*0x0B0*/     UINT64       SelfmapLock;
    /*0x0B8*/     struct _MMSUPPORT_FLAGS Flags;               // 17 elements, 0x4 bytes (sizeof)  
    /*0x0BC*/     UINT8        _PADDING0_[0x4];
  }MMSUPPORT_INSTANCE, * PMMSUPPORT_INSTANCE;
  typedef struct _MMSUPPORT_SHARED            // 11 elements, 0x80 bytes (sizeof) 
  {
    /*0x000*/     LONG32       WorkingSetLock;
    /*0x004*/     LONG32       GoodCitizenWaiting;
    /*0x008*/     UINT64       ReleasedCommitDebt;
    /*0x010*/     UINT64       ResetPagesRepurposedCount;
    /*0x018*/     VOID* WsSwapSupport;
    /*0x020*/     VOID* CommitReleaseContext;
    /*0x028*/     VOID* AccessLog;
    /*0x030*/     UINT64       ChargedWslePages;
    /*0x038*/     UINT64       ActualWslePages;
    /*0x040*/     UINT64       WorkingSetCoreLock;
    /*0x048*/     VOID* ShadowMapping;
    /*0x050*/     UINT8        _PADDING0_[0x30];
  }MMSUPPORT_SHARED, * PMMSUPPORT_SHARED;
  typedef struct _PS_PROTECTION        // 4 elements, 0x1 bytes (sizeof) 
  {
    union                            // 2 elements, 0x1 bytes (sizeof) 
    {
      /*0x000*/         UINT8        Level;
      struct                       // 3 elements, 0x1 bytes (sizeof) 
      {
        /*0x000*/             UINT8        Type : 3;   // 0 BitPosition                  
        /*0x000*/             UINT8        Audit : 1;  // 3 BitPosition                  
        /*0x000*/             UINT8        Signer : 4; // 4 BitPosition                  
      };
    };
  }PS_PROTECTION, * PPS_PROTECTION;
  typedef struct _MMSUPPORT_FULL           // 2 elements, 0x140 bytes (sizeof) 
  {
    /*0x000*/     struct _MMSUPPORT_INSTANCE Instance; // 19 elements, 0xC0 bytes (sizeof) 
    /*0x0C0*/     struct _MMSUPPORT_SHARED Shared;     // 11 elements, 0x80 bytes (sizeof) 
  }MMSUPPORT_FULL, * PMMSUPPORT_FULL;
  typedef struct _EX_PUSH_LOCK                 // 7 elements, 0x8 bytes (sizeof) 
  {
    union                                    // 3 elements, 0x8 bytes (sizeof) 
    {
      struct                               // 5 elements, 0x8 bytes (sizeof) 
      {
        /*0x000*/             UINT64       Locked : 1;         // 0 BitPosition                  
        /*0x000*/             UINT64       Waiting : 1;        // 1 BitPosition                  
        /*0x000*/             UINT64       Waking : 1;         // 2 BitPosition                  
        /*0x000*/             UINT64       MultipleShared : 1; // 3 BitPosition                  
        /*0x000*/             UINT64       Shared : 60;        // 4 BitPosition                  
      };
      /*0x000*/         UINT64       Value;
      /*0x000*/         VOID* Ptr;
    };
  }EX_PUSH_LOCK, * PEX_PUSH_LOCK;
  typedef struct _ALPC_PROCESS_CONTEXT  // 3 elements, 0x20 bytes (sizeof) 
  {
    /*0x000*/     struct _EX_PUSH_LOCK Lock;        // 7 elements, 0x8 bytes (sizeof)  
    /*0x008*/     struct _LIST_ENTRY ViewListHead;  // 2 elements, 0x10 bytes (sizeof) 
    /*0x018*/     UINT64       PagedPoolQuotaCache;
  }ALPC_PROCESS_CONTEXT, * PALPC_PROCESS_CONTEXT;
  typedef struct _JOBOBJECT_WAKE_FILTER // 2 elements, 0x8 bytes (sizeof) 
  {
    /*0x000*/     ULONG32      HighEdgeFilter;
    /*0x004*/     ULONG32      LowEdgeFilter;
  }JOBOBJECT_WAKE_FILTER, * PJOBOBJECT_WAKE_FILTER;
  typedef struct _PS_PROCESS_WAKE_INFORMATION   // 4 elements, 0x30 bytes (sizeof) 
  {
    /*0x000*/     UINT64       NotificationChannel;
    /*0x008*/     ULONG32      WakeCounters[7];
    /*0x024*/     struct _JOBOBJECT_WAKE_FILTER WakeFilter; // 2 elements, 0x8 bytes (sizeof)  
    /*0x02C*/     ULONG32      NoWakeCounter;
  }PS_PROCESS_WAKE_INFORMATION, * PPS_PROCESS_WAKE_INFORMATION;
  typedef union _PS_INTERLOCKED_TIMER_DELAY_VALUES // 7 elements, 0x8 bytes (sizeof) 
  {
    struct                                       // 6 elements, 0x8 bytes (sizeof) 
    {
      /*0x000*/         UINT64       DelayMs : 30;               // 0 BitPosition                  
      /*0x000*/         UINT64       CoalescingWindowMs : 30;    // 30 BitPosition                 
      /*0x000*/         UINT64       Reserved : 1;               // 60 BitPosition                 
      /*0x000*/         UINT64       NewTimerWheel : 1;          // 61 BitPosition                 
      /*0x000*/         UINT64       Retry : 1;                  // 62 BitPosition                 
      /*0x000*/         UINT64       Locked : 1;                 // 63 BitPosition                 
    };
    /*0x000*/     UINT64       All;
  }PS_INTERLOCKED_TIMER_DELAY_VALUES, * PPS_INTERLOCKED_TIMER_DELAY_VALUES;
  typedef struct _KPROCESS                            // 46 elements, 0x2E0 bytes (sizeof) 
  {
    /*0x000*/     struct _DISPATCHER_HEADER Header;               // 58 elements, 0x18 bytes (sizeof)  
    /*0x018*/     struct _LIST_ENTRY ProfileListHead;             // 2 elements, 0x10 bytes (sizeof)   
    /*0x028*/     UINT64       DirectoryTableBase;
    /*0x030*/     struct _LIST_ENTRY ThreadListHead;              // 2 elements, 0x10 bytes (sizeof)   
    /*0x040*/     ULONG32      ProcessLock;
    /*0x044*/     ULONG32      ProcessTimerDelay;
    /*0x048*/     UINT64       DeepFreezeStartTime;
    /*0x050*/     struct _KAFFINITY_EX Affinity;                  // 4 elements, 0xA8 bytes (sizeof)   
    /*0x0F8*/     struct _LIST_ENTRY ReadyListHead;               // 2 elements, 0x10 bytes (sizeof)   
    /*0x108*/     struct _SINGLE_LIST_ENTRY SwapListEntry;        // 1 elements, 0x8 bytes (sizeof)    
    /*0x110*/     struct _KAFFINITY_EX ActiveProcessors;          // 4 elements, 0xA8 bytes (sizeof)   
    union                                           // 2 elements, 0x4 bytes (sizeof)    
    {
      struct                                      // 10 elements, 0x4 bytes (sizeof)   
      {
        /*0x1B8*/             ULONG32      AutoAlignment : 1;         // 0 BitPosition                     
        /*0x1B8*/             ULONG32      DisableBoost : 1;          // 1 BitPosition                     
        /*0x1B8*/             ULONG32      DisableQuantum : 1;        // 2 BitPosition                     
        /*0x1B8*/             ULONG32      DeepFreeze : 1;            // 3 BitPosition                     
        /*0x1B8*/             ULONG32      TimerVirtualization : 1;   // 4 BitPosition                     
        /*0x1B8*/             ULONG32      CheckStackExtents : 1;     // 5 BitPosition                     
        /*0x1B8*/             ULONG32      CacheIsolationEnabled : 1; // 6 BitPosition                     
        /*0x1B8*/             ULONG32      PpmPolicy : 3;             // 7 BitPosition                     
        /*0x1B8*/             ULONG32      VaSpaceDeleted : 1;        // 10 BitPosition                    
        /*0x1B8*/             ULONG32      ReservedFlags : 21;        // 11 BitPosition                    
      };
      /*0x1B8*/         LONG32       ProcessFlags;
    };
    /*0x1BC*/     ULONG32      ActiveGroupsMask;
    /*0x1C0*/     CHAR         BasePriority;
    /*0x1C1*/     CHAR         QuantumReset;
    /*0x1C2*/     CHAR         Visited;
    /*0x1C3*/     union _KEXECUTE_OPTIONS Flags;                  // 10 elements, 0x1 bytes (sizeof)   
    /*0x1C4*/     UINT16       ThreadSeed[20];
    /*0x1EC*/     UINT16       IdealProcessor[20];
    /*0x214*/     UINT16       IdealNode[20];
    /*0x23C*/     UINT16       IdealGlobalNode;
    /*0x23E*/     UINT16       Spare1;
    /*0x240*/     union _KSTACK_COUNT StackCount;                 // 3 elements, 0x4 bytes (sizeof)    
    /*0x244*/     UINT8        _PADDING0_[0x4];
    /*0x248*/     struct _LIST_ENTRY ProcessListEntry;            // 2 elements, 0x10 bytes (sizeof)   
    /*0x258*/     UINT64       CycleTime;
    /*0x260*/     UINT64       ContextSwitches;
    /*0x268*/     struct _KSCHEDULING_GROUP* SchedulingGroup;
    /*0x270*/     ULONG32      FreezeCount;
    /*0x274*/     ULONG32      KernelTime;
    /*0x278*/     ULONG32      UserTime;
    /*0x27C*/     ULONG32      ReadyTime;
    /*0x280*/     UINT64       UserDirectoryTableBase;
    /*0x288*/     UINT8        AddressPolicy;
    /*0x289*/     UINT8        Spare2[71];
    /*0x2D0*/     VOID* InstrumentationCallback;
    /*0x2D8*/     char SecureState[8];             // 2 elements, 0x8 bytes (sizeof)    
  }KPROCESS, * PKPROCESS;
  typedef struct _EPROCESS                                               // 226 elements, 0x880 bytes (sizeof) 
  {
    /*0x000*/     struct _KPROCESS Pcb;                                              // 46 elements, 0x2E0 bytes (sizeof)  
    /*0x2E0*/     struct _EX_PUSH_LOCK ProcessLock;                                  // 7 elements, 0x8 bytes (sizeof)     
    /*0x2E8*/     VOID* UniqueProcessId;
    /*0x2F0*/     struct _LIST_ENTRY ActiveProcessLinks;                             // 2 elements, 0x10 bytes (sizeof)    
    /*0x300*/     struct _EX_RUNDOWN_REF RundownProtect;                             // 2 elements, 0x8 bytes (sizeof)     
    union                                                              // 2 elements, 0x4 bytes (sizeof)     
    {
      /*0x308*/         ULONG32      Flags2;
      struct                                                         // 28 elements, 0x4 bytes (sizeof)    
      {
        /*0x308*/             ULONG32      JobNotReallyActive : 1;                       // 0 BitPosition                      
        /*0x308*/             ULONG32      AccountingFolded : 1;                         // 1 BitPosition                      
        /*0x308*/             ULONG32      NewProcessReported : 1;                       // 2 BitPosition                      
        /*0x308*/             ULONG32      ExitProcessReported : 1;                      // 3 BitPosition                      
        /*0x308*/             ULONG32      ReportCommitChanges : 1;                      // 4 BitPosition                      
        /*0x308*/             ULONG32      LastReportMemory : 1;                         // 5 BitPosition                      
        /*0x308*/             ULONG32      ForceWakeCharge : 1;                          // 6 BitPosition                      
        /*0x308*/             ULONG32      CrossSessionCreate : 1;                       // 7 BitPosition                      
        /*0x308*/             ULONG32      NeedsHandleRundown : 1;                       // 8 BitPosition                      
        /*0x308*/             ULONG32      RefTraceEnabled : 1;                          // 9 BitPosition                      
        /*0x308*/             ULONG32      PicoCreated : 1;                              // 10 BitPosition                     
        /*0x308*/             ULONG32      EmptyJobEvaluated : 1;                        // 11 BitPosition                     
        /*0x308*/             ULONG32      DefaultPagePriority : 3;                      // 12 BitPosition                     
        /*0x308*/             ULONG32      PrimaryTokenFrozen : 1;                       // 15 BitPosition                     
        /*0x308*/             ULONG32      ProcessVerifierTarget : 1;                    // 16 BitPosition                     
        /*0x308*/             ULONG32      RestrictSetThreadContext : 1;                 // 17 BitPosition                     
        /*0x308*/             ULONG32      AffinityPermanent : 1;                        // 18 BitPosition                     
        /*0x308*/             ULONG32      AffinityUpdateEnable : 1;                     // 19 BitPosition                     
        /*0x308*/             ULONG32      PropagateNode : 1;                            // 20 BitPosition                     
        /*0x308*/             ULONG32      ExplicitAffinity : 1;                         // 21 BitPosition                     
        /*0x308*/             ULONG32      ProcessExecutionState : 2;                    // 22 BitPosition                     
        /*0x308*/             ULONG32      EnableReadVmLogging : 1;                      // 24 BitPosition                     
        /*0x308*/             ULONG32      EnableWriteVmLogging : 1;                     // 25 BitPosition                     
        /*0x308*/             ULONG32      FatalAccessTerminationRequested : 1;          // 26 BitPosition                     
        /*0x308*/             ULONG32      DisableSystemAllowedCpuSet : 1;               // 27 BitPosition                     
        /*0x308*/             ULONG32      ProcessStateChangeRequest : 2;                // 28 BitPosition                     
        /*0x308*/             ULONG32      ProcessStateChangeInProgress : 1;             // 30 BitPosition                     
        /*0x308*/             ULONG32      InPrivate : 1;                                // 31 BitPosition                     
      };
    };
    union                                                              // 2 elements, 0x4 bytes (sizeof)     
    {
      /*0x30C*/         ULONG32      Flags;
      struct                                                         // 29 elements, 0x4 bytes (sizeof)    
      {
        /*0x30C*/             ULONG32      CreateReported : 1;                           // 0 BitPosition                      
        /*0x30C*/             ULONG32      NoDebugInherit : 1;                           // 1 BitPosition                      
        /*0x30C*/             ULONG32      ProcessExiting : 1;                           // 2 BitPosition                      
        /*0x30C*/             ULONG32      ProcessDelete : 1;                            // 3 BitPosition                      
        /*0x30C*/             ULONG32      ManageExecutableMemoryWrites : 1;             // 4 BitPosition                      
        /*0x30C*/             ULONG32      VmDeleted : 1;                                // 5 BitPosition                      
        /*0x30C*/             ULONG32      OutswapEnabled : 1;                           // 6 BitPosition                      
        /*0x30C*/             ULONG32      Outswapped : 1;                               // 7 BitPosition                      
        /*0x30C*/             ULONG32      FailFastOnCommitFail : 1;                     // 8 BitPosition                      
        /*0x30C*/             ULONG32      Wow64VaSpace4Gb : 1;                          // 9 BitPosition                      
        /*0x30C*/             ULONG32      AddressSpaceInitialized : 2;                  // 10 BitPosition                     
        /*0x30C*/             ULONG32      SetTimerResolution : 1;                       // 12 BitPosition                     
        /*0x30C*/             ULONG32      BreakOnTermination : 1;                       // 13 BitPosition                     
        /*0x30C*/             ULONG32      DeprioritizeViews : 1;                        // 14 BitPosition                     
        /*0x30C*/             ULONG32      WriteWatch : 1;                               // 15 BitPosition                     
        /*0x30C*/             ULONG32      ProcessInSession : 1;                         // 16 BitPosition                     
        /*0x30C*/             ULONG32      OverrideAddressSpace : 1;                     // 17 BitPosition                     
        /*0x30C*/             ULONG32      HasAddressSpace : 1;                          // 18 BitPosition                     
        /*0x30C*/             ULONG32      LaunchPrefetched : 1;                         // 19 BitPosition                     
        /*0x30C*/             ULONG32      Background : 1;                               // 20 BitPosition                     
        /*0x30C*/             ULONG32      VmTopDown : 1;                                // 21 BitPosition                     
        /*0x30C*/             ULONG32      ImageNotifyDone : 1;                          // 22 BitPosition                     
        /*0x30C*/             ULONG32      PdeUpdateNeeded : 1;                          // 23 BitPosition                     
        /*0x30C*/             ULONG32      VdmAllowed : 1;                               // 24 BitPosition                     
        /*0x30C*/             ULONG32      ProcessRundown : 1;                           // 25 BitPosition                     
        /*0x30C*/             ULONG32      ProcessInserted : 1;                          // 26 BitPosition                     
        /*0x30C*/             ULONG32      DefaultIoPriority : 3;                        // 27 BitPosition                     
        /*0x30C*/             ULONG32      ProcessSelfDelete : 1;                        // 30 BitPosition                     
        /*0x30C*/             ULONG32      SetTimerResolutionLink : 1;                   // 31 BitPosition                     
      };
    };
    /*0x310*/     union _LARGE_INTEGER CreateTime;                                   // 4 elements, 0x8 bytes (sizeof)     
    /*0x318*/     UINT64       ProcessQuotaUsage[2];
    /*0x328*/     UINT64       ProcessQuotaPeak[2];
    /*0x338*/     UINT64       PeakVirtualSize;
    /*0x340*/     UINT64       VirtualSize;
    /*0x348*/     struct _LIST_ENTRY SessionProcessLinks;                            // 2 elements, 0x10 bytes (sizeof)    
    union                                                              // 3 elements, 0x8 bytes (sizeof)     
    {
      /*0x358*/         VOID* ExceptionPortData;
      /*0x358*/         UINT64       ExceptionPortValue;
      /*0x358*/         UINT64       ExceptionPortState : 3;                           // 0 BitPosition                      
    };
    /*0x360*/     struct _EX_FAST_REF Token;                                         // 3 elements, 0x8 bytes (sizeof)     
    /*0x368*/     UINT64       MmReserved;
    /*0x370*/     struct _EX_PUSH_LOCK AddressCreationLock;                          // 7 elements, 0x8 bytes (sizeof)     
    /*0x378*/     struct _EX_PUSH_LOCK PageTableCommitmentLock;                      // 7 elements, 0x8 bytes (sizeof)     
    /*0x380*/     struct _ETHREAD* RotateInProgress;
    /*0x388*/     struct _ETHREAD* ForkInProgress;
    /*0x390*/     struct _EJOB* CommitChargeJob;
    /*0x398*/     struct _RTL_AVL_TREE CloneRoot;                                    // 1 elements, 0x8 bytes (sizeof)     
    /*0x3A0*/     UINT64       NumberOfPrivatePages;
    /*0x3A8*/     UINT64       NumberOfLockedPages;
    /*0x3B0*/     VOID* Win32Process;
    /*0x3B8*/     struct _EJOB* Job;
    /*0x3C0*/     VOID* SectionObject;
    /*0x3C8*/     VOID* SectionBaseAddress;
    /*0x3D0*/     ULONG32      Cookie;
    /*0x3D4*/     UINT8        _PADDING0_[0x4];
    /*0x3D8*/     struct _PAGEFAULT_HISTORY* WorkingSetWatch;
    /*0x3E0*/     VOID* Win32WindowStation;
    /*0x3E8*/     VOID* InheritedFromUniqueProcessId;
    /*0x3F0*/     UINT64       OwnerProcessId;
    /*0x3F8*/     struct _PEB* Peb;
    /*0x400*/     struct _MM_SESSION_SPACE* Session;
    /*0x408*/     VOID* Spare1;
    /*0x410*/     struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;
    /*0x418*/     struct _HANDLE_TABLE* ObjectTable;
    /*0x420*/     VOID* DebugPort;
    /*0x428*/     struct _EWOW64PROCESS* WoW64Process;
    /*0x430*/     VOID* DeviceMap;
    /*0x438*/     VOID* EtwDataSource;
    /*0x440*/     UINT64       PageDirectoryPte;
    /*0x448*/     struct _FILE_OBJECT* ImageFilePointer;
    /*0x450*/     UINT8        ImageFileName[15];
    /*0x45F*/     UINT8        PriorityClass;
    /*0x460*/     VOID* SecurityPort;
    /*0x468*/     struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo; // 1 elements, 0x8 bytes (sizeof)     
    /*0x470*/     struct _LIST_ENTRY JobLinks;                                       // 2 elements, 0x10 bytes (sizeof)    
    /*0x480*/     VOID* HighestUserAddress;
    /*0x488*/     struct _LIST_ENTRY ThreadListHead;                                 // 2 elements, 0x10 bytes (sizeof)    
    /*0x498*/     ULONG32      ActiveThreads;
    /*0x49C*/     ULONG32      ImagePathHash;
    /*0x4A0*/     ULONG32      DefaultHardErrorProcessing;
    /*0x4A4*/     LONG32       LastThreadExitStatus;
    /*0x4A8*/     struct _EX_FAST_REF PrefetchTrace;                                 // 3 elements, 0x8 bytes (sizeof)     
    /*0x4B0*/     VOID* LockedPagesList;
    /*0x4B8*/     union _LARGE_INTEGER ReadOperationCount;                           // 4 elements, 0x8 bytes (sizeof)     
    /*0x4C0*/     union _LARGE_INTEGER WriteOperationCount;                          // 4 elements, 0x8 bytes (sizeof)     
    /*0x4C8*/     union _LARGE_INTEGER OtherOperationCount;                          // 4 elements, 0x8 bytes (sizeof)     
    /*0x4D0*/     union _LARGE_INTEGER ReadTransferCount;                            // 4 elements, 0x8 bytes (sizeof)     
    /*0x4D8*/     union _LARGE_INTEGER WriteTransferCount;                           // 4 elements, 0x8 bytes (sizeof)     
    /*0x4E0*/     union _LARGE_INTEGER OtherTransferCount;                           // 4 elements, 0x8 bytes (sizeof)     
    /*0x4E8*/     UINT64       CommitChargeLimit;
    /*0x4F0*/     UINT64       CommitCharge;
    /*0x4F8*/     UINT64       CommitChargePeak;
    /*0x500*/     struct _MMSUPPORT_FULL Vm;                                         // 2 elements, 0x140 bytes (sizeof)   
    /*0x640*/     struct _LIST_ENTRY MmProcessLinks;                                 // 2 elements, 0x10 bytes (sizeof)    
    /*0x650*/     ULONG32      ModifiedPageCount;
    /*0x654*/     LONG32       ExitStatus;
    /*0x658*/     struct _RTL_AVL_TREE VadRoot;                                      // 1 elements, 0x8 bytes (sizeof)     
    /*0x660*/     VOID* VadHint;
    /*0x668*/     UINT64       VadCount;
    /*0x670*/     UINT64       VadPhysicalPages;
    /*0x678*/     UINT64       VadPhysicalPagesLimit;
    /*0x680*/     struct _ALPC_PROCESS_CONTEXT AlpcContext;                          // 3 elements, 0x20 bytes (sizeof)    
    /*0x6A0*/     struct _LIST_ENTRY TimerResolutionLink;                            // 2 elements, 0x10 bytes (sizeof)    
    /*0x6B0*/     struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;
    /*0x6B8*/     ULONG32      RequestedTimerResolution;
    /*0x6BC*/     ULONG32      SmallestTimerResolution;
    /*0x6C0*/     union _LARGE_INTEGER ExitTime;                                     // 4 elements, 0x8 bytes (sizeof)     
    /*0x6C8*/     struct _INVERTED_FUNCTION_TABLE* InvertedFunctionTable;
    /*0x6D0*/     struct _EX_PUSH_LOCK InvertedFunctionTableLock;                    // 7 elements, 0x8 bytes (sizeof)     
    /*0x6D8*/     ULONG32      ActiveThreadsHighWatermark;
    /*0x6DC*/     ULONG32      LargePrivateVadCount;
    /*0x6E0*/     struct _EX_PUSH_LOCK ThreadListLock;                               // 7 elements, 0x8 bytes (sizeof)     
    /*0x6E8*/     VOID* WnfContext;
    /*0x6F0*/     struct _EJOB* ServerSilo;
    /*0x6F8*/     UINT8        SignatureLevel;
    /*0x6F9*/     UINT8        SectionSignatureLevel;
    /*0x6FA*/     struct _PS_PROTECTION Protection;                                  // 4 elements, 0x1 bytes (sizeof)     
    struct                                                             // 3 elements, 0x1 bytes (sizeof)     
    {
      /*0x6FB*/         UINT8        HangCount : 3;                                    // 0 BitPosition                      
      /*0x6FB*/         UINT8        GhostCount : 3;                                   // 3 BitPosition                      
      /*0x6FB*/         UINT8        PrefilterException : 1;                           // 6 BitPosition                      
    };
    union                                                              // 2 elements, 0x4 bytes (sizeof)     
    {
      /*0x6FC*/         ULONG32      Flags3;
      struct                                                         // 24 elements, 0x4 bytes (sizeof)    
      {
        /*0x6FC*/             ULONG32      Minimal : 1;                                  // 0 BitPosition                      
        /*0x6FC*/             ULONG32      ReplacingPageRoot : 1;                        // 1 BitPosition                      
        /*0x6FC*/             ULONG32      Crashed : 1;                                  // 2 BitPosition                      
        /*0x6FC*/             ULONG32      JobVadsAreTracked : 1;                        // 3 BitPosition                      
        /*0x6FC*/             ULONG32      VadTrackingDisabled : 1;                      // 4 BitPosition                      
        /*0x6FC*/             ULONG32      AuxiliaryProcess : 1;                         // 5 BitPosition                      
        /*0x6FC*/             ULONG32      SubsystemProcess : 1;                         // 6 BitPosition                      
        /*0x6FC*/             ULONG32      IndirectCpuSets : 1;                          // 7 BitPosition                      
        /*0x6FC*/             ULONG32      RelinquishedCommit : 1;                       // 8 BitPosition                      
        /*0x6FC*/             ULONG32      HighGraphicsPriority : 1;                     // 9 BitPosition                      
        /*0x6FC*/             ULONG32      CommitFailLogged : 1;                         // 10 BitPosition                     
        /*0x6FC*/             ULONG32      ReserveFailLogged : 1;                        // 11 BitPosition                     
        /*0x6FC*/             ULONG32      SystemProcess : 1;                            // 12 BitPosition                     
        /*0x6FC*/             ULONG32      HideImageBaseAddresses : 1;                   // 13 BitPosition                     
        /*0x6FC*/             ULONG32      AddressPolicyFrozen : 1;                      // 14 BitPosition                     
        /*0x6FC*/             ULONG32      ProcessFirstResume : 1;                       // 15 BitPosition                     
        /*0x6FC*/             ULONG32      ForegroundExternal : 1;                       // 16 BitPosition                     
        /*0x6FC*/             ULONG32      ForegroundSystem : 1;                         // 17 BitPosition                     
        /*0x6FC*/             ULONG32      HighMemoryPriority : 1;                       // 18 BitPosition                     
        /*0x6FC*/             ULONG32      EnableProcessSuspendResumeLogging : 1;        // 19 BitPosition                     
        /*0x6FC*/             ULONG32      EnableThreadSuspendResumeLogging : 1;         // 20 BitPosition                     
        /*0x6FC*/             ULONG32      SecurityDomainChanged : 1;                    // 21 BitPosition                     
        /*0x6FC*/             ULONG32      SecurityFreezeComplete : 1;                   // 22 BitPosition                     
        /*0x6FC*/             ULONG32      VmProcessorHost : 1;                          // 23 BitPosition                     
      };
    };
    /*0x700*/     LONG32       DeviceAsid;
    /*0x704*/     UINT8        _PADDING1_[0x4];
    /*0x708*/     VOID* SvmData;
    /*0x710*/     struct _EX_PUSH_LOCK SvmProcessLock;                               // 7 elements, 0x8 bytes (sizeof)     
    /*0x718*/     UINT64       SvmLock;
    /*0x720*/     struct _LIST_ENTRY SvmProcessDeviceListHead;                       // 2 elements, 0x10 bytes (sizeof)    
    /*0x730*/     UINT64       LastFreezeInterruptTime;
    /*0x738*/     struct _PROCESS_DISK_COUNTERS* DiskCounters;
    /*0x740*/     VOID* PicoContext;
    /*0x748*/     VOID* EnclaveTable;
    /*0x750*/     UINT64       EnclaveNumber;
    /*0x758*/     struct _EX_PUSH_LOCK EnclaveLock;                                  // 7 elements, 0x8 bytes (sizeof)     
    /*0x760*/     ULONG32      HighPriorityFaultsAllowed;
    /*0x764*/     UINT8        _PADDING2_[0x4];
    /*0x768*/     struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;
    /*0x770*/     VOID* VmContext;
    /*0x778*/     UINT64       SequenceNumber;
    /*0x780*/     UINT64       CreateInterruptTime;
    /*0x788*/     UINT64       CreateUnbiasedInterruptTime;
    /*0x790*/     UINT64       TotalUnbiasedFrozenTime;
    /*0x798*/     UINT64       LastAppStateUpdateTime;
    struct                                                             // 2 elements, 0x8 bytes (sizeof)     
    {
      /*0x7A0*/         UINT64       LastAppStateUptime : 61;                          // 0 BitPosition                      
      /*0x7A0*/         UINT64       LastAppState : 3;                                 // 61 BitPosition                     
    };
    /*0x7A8*/     UINT64       SharedCommitCharge;
    /*0x7B0*/     struct _EX_PUSH_LOCK SharedCommitLock;                             // 7 elements, 0x8 bytes (sizeof)     
    /*0x7B8*/     struct _LIST_ENTRY SharedCommitLinks;                              // 2 elements, 0x10 bytes (sizeof)    
    union                                                              // 2 elements, 0x10 bytes (sizeof)    
    {
      struct                                                         // 2 elements, 0x10 bytes (sizeof)    
      {
        /*0x7C8*/             UINT64       AllowedCpuSets;
        /*0x7D0*/             UINT64       DefaultCpuSets;
      };
      struct                                                         // 2 elements, 0x10 bytes (sizeof)    
      {
        /*0x7C8*/             UINT64* AllowedCpuSetsIndirect;
        /*0x7D0*/             UINT64* DefaultCpuSetsIndirect;
      };
    };
    /*0x7D8*/     VOID* DiskIoAttribution;
    /*0x7E0*/     VOID* DxgProcess;
    /*0x7E8*/     ULONG32      Win32KFilterSet;
    /*0x7EC*/     UINT8        _PADDING3_[0x4];
    /*0x7F0*/     union _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;        // 7 elements, 0x8 bytes (sizeof)     
    /*0x7F8*/     ULONG32      KTimerSets;
    /*0x7FC*/     ULONG32      KTimer2Sets;
    /*0x800*/     ULONG32      ThreadTimerSets;
    /*0x804*/     UINT8        _PADDING4_[0x4];
    /*0x808*/     UINT64       VirtualTimerListLock;
    /*0x810*/     struct _LIST_ENTRY VirtualTimerListHead;                           // 2 elements, 0x10 bytes (sizeof)    
    union                                                              // 2 elements, 0x30 bytes (sizeof)    
    {
      /*0x820*/         struct _WNF_STATE_NAME WakeChannel;                            // 1 elements, 0x8 bytes (sizeof)     
      /*0x820*/         struct _PS_PROCESS_WAKE_INFORMATION WakeInfo;                  // 4 elements, 0x30 bytes (sizeof)    
    };
    union                                                              // 2 elements, 0x4 bytes (sizeof)     
    {
      /*0x850*/         ULONG32      MitigationFlags;
      /*0x850*/         char MitigationFlagsValues[4];                 // 32 elements, 0x4 bytes (sizeof)    
    };
    union                                                              // 2 elements, 0x4 bytes (sizeof)     
    {
      /*0x854*/         ULONG32      MitigationFlags2;
      /*0x854*/         char MitigationFlags2Values[4];                // 15 elements, 0x4 bytes (sizeof)    
    };
    /*0x858*/     VOID* PartitionObject;
    /*0x860*/     UINT64       SecurityDomain;
    /*0x868*/     UINT64       ParentSecurityDomain;
    /*0x870*/     VOID* CoverageSamplerContext;
    /*0x878*/     VOID* MmHotPatchContext;
  }EPROCESS, * PEPROCESS;
  typedef union _KWAIT_STATUS_REGISTER // 7 elements, 0x1 bytes (sizeof) 
  {
    /*0x000*/     UINT8        Flags;
    struct                           // 6 elements, 0x1 bytes (sizeof) 
    {
      /*0x000*/         UINT8        State : 3;      // 0 BitPosition                  
      /*0x000*/         UINT8        Affinity : 1;   // 3 BitPosition                  
      /*0x000*/         UINT8        Priority : 1;   // 4 BitPosition                  
      /*0x000*/         UINT8        Apc : 1;        // 5 BitPosition                  
      /*0x000*/         UINT8        UserApc : 1;    // 6 BitPosition                  
      /*0x000*/         UINT8        Alert : 1;      // 7 BitPosition                  
    };
  }KWAIT_STATUS_REGISTER, * PKWAIT_STATUS_REGISTER;
  typedef struct _KLOCK_ENTRY_LOCK_STATE              // 8 elements, 0x10 bytes (sizeof) 
  {
    union                                           // 2 elements, 0x8 bytes (sizeof)  
    {
      struct                                      // 4 elements, 0x8 bytes (sizeof)  
      {
        /*0x000*/             UINT64       CrossThreadReleasable : 1; // 0 BitPosition                   
        /*0x000*/             UINT64       Busy : 1;                  // 1 BitPosition                   
        /*0x000*/             UINT64       Reserved : 61;             // 2 BitPosition                   
        /*0x000*/             UINT64       InTree : 1;                // 63 BitPosition                  
      };
      /*0x000*/         VOID* LockState;
    };
    union                                           // 2 elements, 0x8 bytes (sizeof)  
    {
      /*0x008*/         VOID* SessionState;
      struct                                      // 2 elements, 0x8 bytes (sizeof)  
      {
        /*0x008*/             ULONG32      SessionId;
        /*0x00C*/             ULONG32      SessionPad;
      };
    };
  }KLOCK_ENTRY_LOCK_STATE, * PKLOCK_ENTRY_LOCK_STATE;
  typedef struct _RTL_RB_TREE             // 3 elements, 0x10 bytes (sizeof) 
  {
    /*0x000*/     struct _RTL_BALANCED_NODE* Root;
    union                               // 2 elements, 0x8 bytes (sizeof)  
    {
      /*0x008*/         UINT8        Encoded : 1;       // 0 BitPosition                   
      /*0x008*/         struct _RTL_BALANCED_NODE* Min;
    };
  }RTL_RB_TREE, * PRTL_RB_TREE;
  typedef union _KLOCK_ENTRY_BOOST_BITMAP               // 8 elements, 0x4 bytes (sizeof) 
  {
    /*0x000*/     ULONG32      AllFields;
    struct                                            // 4 elements, 0x4 bytes (sizeof) 
    {
      /*0x000*/         ULONG32      AllBoosts : 17;                  // 0 BitPosition                  
      /*0x000*/         ULONG32      Reserved : 15;                   // 17 BitPosition                 
      /*0x000*/         UINT16       CpuBoostsBitmap : 15;            // 0 BitPosition                  
      /*0x000*/         UINT16       IoBoost : 1;                     // 15 BitPosition                 
    };
    struct                                            // 3 elements, 0x2 bytes (sizeof) 
    {
      /*0x002*/         UINT16       IoQoSBoost : 1;                  // 0 BitPosition                  
      /*0x002*/         UINT16       IoNormalPriorityWaiterCount : 8; // 1 BitPosition                  
      /*0x002*/         UINT16       IoQoSWaiterCount : 7;            // 9 BitPosition                  
    };
  }KLOCK_ENTRY_BOOST_BITMAP, * PKLOCK_ENTRY_BOOST_BITMAP;
  typedef struct _KLOCK_ENTRY                                // 31 elements, 0x60 bytes (sizeof) 
  {
    union                                                  // 2 elements, 0x18 bytes (sizeof)  
    {
      /*0x000*/         struct _RTL_BALANCED_NODE TreeNode;                // 6 elements, 0x18 bytes (sizeof)  
      /*0x000*/         struct _SINGLE_LIST_ENTRY FreeListEntry;           // 1 elements, 0x8 bytes (sizeof)   
    };
    union                                                  // 3 elements, 0x4 bytes (sizeof)   
    {
      /*0x018*/         ULONG32      EntryFlags;
      struct                                             // 4 elements, 0x4 bytes (sizeof)   
      {
        /*0x018*/             UINT8        EntryOffset;
        union                                          // 2 elements, 0x1 bytes (sizeof)   
        {
          /*0x019*/                 UINT8        ThreadLocalFlags;
          struct                                     // 2 elements, 0x1 bytes (sizeof)   
          {
            /*0x019*/                     UINT8        WaitingBit : 1;           // 0 BitPosition                    
            /*0x019*/                     UINT8        Spare0 : 7;               // 1 BitPosition                    
          };
        };
        union                                          // 2 elements, 0x1 bytes (sizeof)   
        {
          /*0x01A*/                 UINT8        AcquiredByte;
          /*0x01A*/                 UINT8        AcquiredBit : 1;              // 0 BitPosition                    
        };
        union                                          // 2 elements, 0x1 bytes (sizeof)   
        {
          /*0x01B*/                 UINT8        CrossThreadFlags;
          struct                                     // 4 elements, 0x1 bytes (sizeof)   
          {
            /*0x01B*/                     UINT8        HeadNodeBit : 1;          // 0 BitPosition                    
            /*0x01B*/                     UINT8        IoPriorityBit : 1;        // 1 BitPosition                    
            /*0x01B*/                     UINT8        IoQoSWaiter : 1;          // 2 BitPosition                    
            /*0x01B*/                     UINT8        Spare1 : 5;               // 3 BitPosition                    
          };
        };
      };
      struct                                             // 2 elements, 0x4 bytes (sizeof)   
      {
        /*0x018*/             ULONG32      StaticState : 8;                  // 0 BitPosition                    
        /*0x018*/             ULONG32      AllFlags : 24;                    // 8 BitPosition                    
      };
    };
    /*0x01C*/     ULONG32      SpareFlags;
    union                                                  // 3 elements, 0x10 bytes (sizeof)  
    {
      /*0x020*/         struct _KLOCK_ENTRY_LOCK_STATE LockState;          // 8 elements, 0x10 bytes (sizeof)  
      /*0x020*/         VOID* LockUnsafe;
      struct                                             // 4 elements, 0x10 bytes (sizeof)  
      {
        /*0x020*/             UINT8        CrossThreadReleasableAndBusyByte;
        /*0x021*/             UINT8        Reserved[6];
        /*0x027*/             UINT8        InTreeByte;
        union                                          // 2 elements, 0x8 bytes (sizeof)   
        {
          /*0x028*/                 VOID* SessionState;
          struct                                     // 2 elements, 0x8 bytes (sizeof)   
          {
            /*0x028*/                     ULONG32      SessionId;
            /*0x02C*/                     ULONG32      SessionPad;
          };
        };
      };
    };
    union                                                  // 2 elements, 0x20 bytes (sizeof)  
    {
      struct                                             // 2 elements, 0x20 bytes (sizeof)  
      {
        /*0x030*/             struct _RTL_RB_TREE OwnerTree;                 // 3 elements, 0x10 bytes (sizeof)  
        /*0x040*/             struct _RTL_RB_TREE WaiterTree;                // 3 elements, 0x10 bytes (sizeof)  
      };
      /*0x030*/         CHAR         CpuPriorityKey;
    };
    /*0x050*/     UINT64       EntryLock;
    /*0x058*/     union _KLOCK_ENTRY_BOOST_BITMAP BoostBitmap;           // 8 elements, 0x4 bytes (sizeof)   
    /*0x05C*/     ULONG32      SparePad;
  }KLOCK_ENTRY, * PKLOCK_ENTRY;
  typedef struct _PS_PROPERTY_SET  // 2 elements, 0x18 bytes (sizeof) 
  {
    /*0x000*/     struct _LIST_ENTRY ListHead; // 2 elements, 0x10 bytes (sizeof) 
    /*0x010*/     UINT64       Lock;
  }PS_PROPERTY_SET, * PPS_PROPERTY_SET;
  typedef union _PS_CLIENT_SECURITY_CONTEXT    // 4 elements, 0x8 bytes (sizeof) 
  {
    /*0x000*/     UINT64       ImpersonationData;
    /*0x000*/     VOID* ImpersonationToken;
    struct                                   // 2 elements, 0x8 bytes (sizeof) 
    {
      /*0x000*/         UINT64       ImpersonationLevel : 2; // 0 BitPosition                  
      /*0x000*/         UINT64       EffectiveOnly : 1;      // 2 BitPosition                  
    };
  }PS_CLIENT_SECURITY_CONTEXT, * PPS_CLIENT_SECURITY_CONTEXT;
  typedef struct _KTHREAD                                            // 190 elements, 0x600 bytes (sizeof) 
  {
    /*0x000*/     struct _DISPATCHER_HEADER Header;                              // 58 elements, 0x18 bytes (sizeof)   
    /*0x018*/     VOID* SListFaultAddress;
    /*0x020*/     UINT64       QuantumTarget;
    /*0x028*/     VOID* InitialStack;
    /*0x030*/     VOID* StackLimit;
    /*0x038*/     VOID* StackBase;
    /*0x040*/     UINT64       ThreadLock;
    /*0x048*/     UINT64       CycleTime;
    /*0x050*/     ULONG32      CurrentRunTime;
    /*0x054*/     ULONG32      ExpectedRunTime;
    /*0x058*/     VOID* KernelStack;
    /*0x060*/     struct _XSAVE_FORMAT* StateSaveArea;
    /*0x068*/     struct _KSCHEDULING_GROUP* SchedulingGroup;
    /*0x070*/     union _KWAIT_STATUS_REGISTER WaitRegister;                     // 7 elements, 0x1 bytes (sizeof)     
    /*0x071*/     UINT8        Running;
    /*0x072*/     UINT8        Alerted[2];
    union                                                          // 2 elements, 0x4 bytes (sizeof)     
    {
      struct                                                     // 23 elements, 0x4 bytes (sizeof)    
      {
        /*0x074*/             ULONG32      AutoBoostActive : 1;                      // 0 BitPosition                      
        /*0x074*/             ULONG32      ReadyTransition : 1;                      // 1 BitPosition                      
        /*0x074*/             ULONG32      WaitNext : 1;                             // 2 BitPosition                      
        /*0x074*/             ULONG32      SystemAffinityActive : 1;                 // 3 BitPosition                      
        /*0x074*/             ULONG32      Alertable : 1;                            // 4 BitPosition                      
        /*0x074*/             ULONG32      UserStackWalkActive : 1;                  // 5 BitPosition                      
        /*0x074*/             ULONG32      ApcInterruptRequest : 1;                  // 6 BitPosition                      
        /*0x074*/             ULONG32      QuantumEndMigrate : 1;                    // 7 BitPosition                      
        /*0x074*/             ULONG32      UmsDirectedSwitchEnable : 1;              // 8 BitPosition                      
        /*0x074*/             ULONG32      TimerActive : 1;                          // 9 BitPosition                      
        /*0x074*/             ULONG32      SystemThread : 1;                         // 10 BitPosition                     
        /*0x074*/             ULONG32      ProcessDetachActive : 1;                  // 11 BitPosition                     
        /*0x074*/             ULONG32      CalloutActive : 1;                        // 12 BitPosition                     
        /*0x074*/             ULONG32      ScbReadyQueue : 1;                        // 13 BitPosition                     
        /*0x074*/             ULONG32      ApcQueueable : 1;                         // 14 BitPosition                     
        /*0x074*/             ULONG32      ReservedStackInUse : 1;                   // 15 BitPosition                     
        /*0x074*/             ULONG32      UmsPerformingSyscall : 1;                 // 16 BitPosition                     
        /*0x074*/             ULONG32      TimerSuspended : 1;                       // 17 BitPosition                     
        /*0x074*/             ULONG32      SuspendedWaitMode : 1;                    // 18 BitPosition                     
        /*0x074*/             ULONG32      SuspendSchedulerApcWait : 1;              // 19 BitPosition                     
        /*0x074*/             ULONG32      CetUserShadowStack : 1;                   // 20 BitPosition                     
        /*0x074*/             ULONG32      BypassProcessFreeze : 1;                  // 21 BitPosition                     
        /*0x074*/             ULONG32      Reserved : 10;                            // 22 BitPosition                     
      };
      /*0x074*/         LONG32       MiscFlags;
    };
    union                                                          // 2 elements, 0x4 bytes (sizeof)     
    {
      struct                                                     // 23 elements, 0x4 bytes (sizeof)    
      {
        /*0x078*/             ULONG32      BamQosLevel : 2;                          // 0 BitPosition                      
        /*0x078*/             ULONG32      AutoAlignment : 1;                        // 2 BitPosition                      
        /*0x078*/             ULONG32      DisableBoost : 1;                         // 3 BitPosition                      
        /*0x078*/             ULONG32      AlertedByThreadId : 1;                    // 4 BitPosition                      
        /*0x078*/             ULONG32      QuantumDonation : 1;                      // 5 BitPosition                      
        /*0x078*/             ULONG32      EnableStackSwap : 1;                      // 6 BitPosition                      
        /*0x078*/             ULONG32      GuiThread : 1;                            // 7 BitPosition                      
        /*0x078*/             ULONG32      DisableQuantum : 1;                       // 8 BitPosition                      
        /*0x078*/             ULONG32      ChargeOnlySchedulingGroup : 1;            // 9 BitPosition                      
        /*0x078*/             ULONG32      DeferPreemption : 1;                      // 10 BitPosition                     
        /*0x078*/             ULONG32      QueueDeferPreemption : 1;                 // 11 BitPosition                     
        /*0x078*/             ULONG32      ForceDeferSchedule : 1;                   // 12 BitPosition                     
        /*0x078*/             ULONG32      SharedReadyQueueAffinity : 1;             // 13 BitPosition                     
        /*0x078*/             ULONG32      FreezeCount : 1;                          // 14 BitPosition                     
        /*0x078*/             ULONG32      TerminationApcRequest : 1;                // 15 BitPosition                     
        /*0x078*/             ULONG32      AutoBoostEntriesExhausted : 1;            // 16 BitPosition                     
        /*0x078*/             ULONG32      KernelStackResident : 1;                  // 17 BitPosition                     
        /*0x078*/             ULONG32      TerminateRequestReason : 2;               // 18 BitPosition                     
        /*0x078*/             ULONG32      ProcessStackCountDecremented : 1;         // 20 BitPosition                     
        /*0x078*/             ULONG32      RestrictedGuiThread : 1;                  // 21 BitPosition                     
        /*0x078*/             ULONG32      VpBackingThread : 1;                      // 22 BitPosition                     
        /*0x078*/             ULONG32      ThreadFlagsSpare : 1;                     // 23 BitPosition                     
        /*0x078*/             ULONG32      EtwStackTraceApcInserted : 8;             // 24 BitPosition                     
      };
      /*0x078*/         LONG32       ThreadFlags;
    };
    /*0x07C*/     UINT8        Tag;
    /*0x07D*/     UINT8        SystemHeteroCpuPolicy;
    struct                                                         // 2 elements, 0x1 bytes (sizeof)     
    {
      /*0x07E*/         UINT8        UserHeteroCpuPolicy : 7;                      // 0 BitPosition                      
      /*0x07E*/         UINT8        ExplicitSystemHeteroCpuPolicy : 1;            // 7 BitPosition                      
    };
    union                                                          // 2 elements, 0x1 bytes (sizeof)     
    {
      struct                                                     // 2 elements, 0x1 bytes (sizeof)     
      {
        /*0x07F*/             UINT8        RunningNonRetpolineCode : 1;              // 0 BitPosition                      
        /*0x07F*/             UINT8        SpecCtrlSpare : 7;                        // 1 BitPosition                      
      };
      /*0x07F*/         UINT8        SpecCtrl;
    };
    /*0x080*/     ULONG32      SystemCallNumber;
    /*0x084*/     ULONG32      ReadyTime;
    /*0x088*/     VOID* FirstArgument;
    /*0x090*/     struct _KTRAP_FRAME* TrapFrame;
    union                                                          // 2 elements, 0x30 bytes (sizeof)    
    {
      /*0x098*/         struct _KAPC_STATE ApcState;                               // 9 elements, 0x30 bytes (sizeof)    
      struct                                                     // 3 elements, 0x30 bytes (sizeof)    
      {
        /*0x098*/             UINT8        ApcStateFill[43];
        /*0x0C3*/             CHAR         Priority;
        /*0x0C4*/             ULONG32      UserIdealProcessor;
      };
    };
    /*0x0C8*/     INT64        WaitStatus;
    /*0x0D0*/     struct _KWAIT_BLOCK* WaitBlockList;
    union                                                          // 2 elements, 0x10 bytes (sizeof)    
    {
      /*0x0D8*/         struct _LIST_ENTRY WaitListEntry;                          // 2 elements, 0x10 bytes (sizeof)    
      /*0x0D8*/         struct _SINGLE_LIST_ENTRY SwapListEntry;                   // 1 elements, 0x8 bytes (sizeof)     
    };
    /*0x0E8*/     struct _DISPATCHER_HEADER* Queue;
    /*0x0F0*/     VOID* Teb;
    /*0x0F8*/     UINT64       RelativeTimerBias;
    /*0x100*/     struct _KTIMER Timer;                                          // 6 elements, 0x40 bytes (sizeof)    
    union                                                          // 9 elements, 0xC0 bytes (sizeof)    
    {
      /*0x140*/         struct _KWAIT_BLOCK WaitBlock[4];
      struct                                                     // 2 elements, 0xC0 bytes (sizeof)    
      {
        /*0x140*/             UINT8        WaitBlockFill4[20];
        /*0x154*/             ULONG32      ContextSwitches;
        /*0x158*/             UINT8        _PADDING0_[0xA8];
      };
      struct                                                     // 5 elements, 0xC0 bytes (sizeof)    
      {
        /*0x140*/             UINT8        WaitBlockFill5[68];
        /*0x184*/             UINT8        State;
        /*0x185*/             CHAR         Spare13;
        /*0x186*/             UINT8        WaitIrql;
        /*0x187*/             CHAR         WaitMode;
        /*0x188*/             UINT8        _PADDING1_[0x78];
      };
      struct                                                     // 2 elements, 0xC0 bytes (sizeof)    
      {
        /*0x140*/             UINT8        WaitBlockFill6[116];
        /*0x1B4*/             ULONG32      WaitTime;
        /*0x1B8*/             UINT8        _PADDING2_[0x48];
      };
      struct                                                     // 2 elements, 0xC0 bytes (sizeof)    
      {
        /*0x140*/             UINT8        WaitBlockFill7[164];
        union                                                  // 2 elements, 0x4 bytes (sizeof)     
        {
          struct                                             // 2 elements, 0x4 bytes (sizeof)     
          {
            /*0x1E4*/                     INT16        KernelApcDisable;
            /*0x1E6*/                     INT16        SpecialApcDisable;
          };
          /*0x1E4*/                 ULONG32      CombinedApcDisable;
        };
      };
      struct                                                     // 2 elements, 0xC0 bytes (sizeof)    
      {
        /*0x140*/             UINT8        WaitBlockFill8[40];
        /*0x168*/             struct _KTHREAD_COUNTERS* ThreadCounters;
        /*0x170*/             UINT8        _PADDING3_[0x90];
      };
      struct                                                     // 2 elements, 0xC0 bytes (sizeof)    
      {
        /*0x140*/             UINT8        WaitBlockFill9[88];
        /*0x198*/             struct _XSTATE_SAVE* XStateSave;
        /*0x1A0*/             UINT8        _PADDING4_[0x60];
      };
      struct                                                     // 2 elements, 0xC0 bytes (sizeof)    
      {
        /*0x140*/             UINT8        WaitBlockFill10[136];
        /*0x1C8*/             VOID* Win32Thread;
        /*0x1D0*/             UINT8        _PADDING5_[0x30];
      };
      struct                                                     // 3 elements, 0xC0 bytes (sizeof)    
      {
        /*0x140*/             UINT8        WaitBlockFill11[176];
        /*0x1F0*/             struct _UMS_CONTROL_BLOCK* Ucb;
        /*0x1F8*/             struct _KUMS_CONTEXT_HEADER* Uch;
      };
    };
    /*0x200*/     VOID* Spare21;
    /*0x208*/     struct _LIST_ENTRY QueueListEntry;                             // 2 elements, 0x10 bytes (sizeof)    
    union                                                          // 2 elements, 0x4 bytes (sizeof)     
    {
      /*0x218*/         ULONG32      NextProcessor;
      struct                                                     // 2 elements, 0x4 bytes (sizeof)     
      {
        /*0x218*/             ULONG32      NextProcessorNumber : 31;                 // 0 BitPosition                      
        /*0x218*/             ULONG32      SharedReadyQueue : 1;                     // 31 BitPosition                     
      };
    };
    /*0x21C*/     LONG32       QueuePriority;
    /*0x220*/     struct _KPROCESS* Process;
    union                                                          // 2 elements, 0x10 bytes (sizeof)    
    {
      /*0x228*/         struct _GROUP_AFFINITY UserAffinity;                       // 3 elements, 0x10 bytes (sizeof)    
      struct                                                     // 7 elements, 0x10 bytes (sizeof)    
      {
        /*0x228*/             UINT8        UserAffinityFill[10];
        /*0x232*/             CHAR         PreviousMode;
        /*0x233*/             CHAR         BasePriority;
        union                                                  // 2 elements, 0x1 bytes (sizeof)     
        {
          /*0x234*/                 CHAR         PriorityDecrement;
          struct                                             // 2 elements, 0x1 bytes (sizeof)     
          {
            /*0x234*/                     UINT8        ForegroundBoost : 4;              // 0 BitPosition                      
            /*0x234*/                     UINT8        UnusualBoost : 4;                 // 4 BitPosition                      
          };
        };
        /*0x235*/             UINT8        Preempted;
        /*0x236*/             UINT8        AdjustReason;
        /*0x237*/             CHAR         AdjustIncrement;
      };
    };
    /*0x238*/     UINT64       AffinityVersion;
    union                                                          // 2 elements, 0x10 bytes (sizeof)    
    {
      /*0x240*/         struct _GROUP_AFFINITY Affinity;                           // 3 elements, 0x10 bytes (sizeof)    
      struct                                                     // 4 elements, 0x10 bytes (sizeof)    
      {
        /*0x240*/             UINT8        AffinityFill[10];
        /*0x24A*/             UINT8        ApcStateIndex;
        /*0x24B*/             UINT8        WaitBlockCount;
        /*0x24C*/             ULONG32      IdealProcessor;
      };
    };
    /*0x250*/     UINT64       NpxState;
    union                                                          // 2 elements, 0x30 bytes (sizeof)    
    {
      /*0x258*/         struct _KAPC_STATE SavedApcState;                          // 9 elements, 0x30 bytes (sizeof)    
      struct                                                     // 5 elements, 0x30 bytes (sizeof)    
      {
        /*0x258*/             UINT8        SavedApcStateFill[43];
        /*0x283*/             UINT8        WaitReason;
        /*0x284*/             CHAR         SuspendCount;
        /*0x285*/             CHAR         Saturation;
        /*0x286*/             UINT16       SListFaultCount;
      };
    };
    union                                                          // 7 elements, 0x58 bytes (sizeof)    
    {
      /*0x288*/         struct _KAPC SchedulerApc;                                 // 17 elements, 0x58 bytes (sizeof)   
      struct                                                     // 2 elements, 0x58 bytes (sizeof)    
      {
        /*0x288*/             UINT8        SchedulerApcFill0[1];
        /*0x289*/             UINT8        ResourceIndex;
        /*0x28A*/             UINT8        _PADDING6_[0x56];
      };
      struct                                                     // 2 elements, 0x58 bytes (sizeof)    
      {
        /*0x288*/             UINT8        SchedulerApcFill1[3];
        /*0x28B*/             UINT8        QuantumReset;
        /*0x28C*/             UINT8        _PADDING7_[0x54];
      };
      struct                                                     // 2 elements, 0x58 bytes (sizeof)    
      {
        /*0x288*/             UINT8        SchedulerApcFill2[4];
        /*0x28C*/             ULONG32      KernelTime;
        /*0x290*/             UINT8        _PADDING8_[0x50];
      };
      struct                                                     // 2 elements, 0x58 bytes (sizeof)    
      {
        /*0x288*/             UINT8        SchedulerApcFill3[64];
        /*0x2C8*/             struct _KPRCB* WaitPrcb;
        /*0x2D0*/             UINT8        _PADDING9_[0x10];
      };
      struct                                                     // 2 elements, 0x58 bytes (sizeof)    
      {
        /*0x288*/             UINT8        SchedulerApcFill4[72];
        /*0x2D0*/             VOID* LegoData;
        /*0x2D8*/             UINT8        _PADDING10_[0x8];
      };
      struct                                                     // 3 elements, 0x58 bytes (sizeof)    
      {
        /*0x288*/             UINT8        SchedulerApcFill5[83];
        /*0x2DB*/             UINT8        CallbackNestingLevel;
        /*0x2DC*/             ULONG32      UserTime;
      };
    };
    /*0x2E0*/     struct _KEVENT SuspendEvent;                                   // 1 elements, 0x18 bytes (sizeof)    
    /*0x2F8*/     struct _LIST_ENTRY ThreadListEntry;                            // 2 elements, 0x10 bytes (sizeof)    
    /*0x308*/     struct _LIST_ENTRY MutantListHead;                             // 2 elements, 0x10 bytes (sizeof)    
    /*0x318*/     UINT8        AbEntrySummary;
    /*0x319*/     UINT8        AbWaitEntryCount;
    /*0x31A*/     UINT8        AbAllocationRegionCount;
    /*0x31B*/     CHAR         SystemPriority;
    /*0x31C*/     ULONG32      SecureThreadCookie;
    /*0x320*/     struct _KLOCK_ENTRY LockEntries[6];
    /*0x560*/     struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;                // 1 elements, 0x8 bytes (sizeof)     
    /*0x568*/     struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;                   // 1 elements, 0x8 bytes (sizeof)     
    /*0x570*/     UINT8        PriorityFloorCounts[16];
    /*0x580*/     ULONG32      PriorityFloorSummary;
    /*0x584*/     LONG32       AbCompletedIoBoostCount;
    /*0x588*/     LONG32       AbCompletedIoQoSBoostCount;
    /*0x58C*/     INT16        KeReferenceCount;
    /*0x58E*/     UINT8        AbOrphanedEntrySummary;
    /*0x58F*/     UINT8        AbOwnedEntryCount;
    /*0x590*/     ULONG32      ForegroundLossTime;
    /*0x594*/     UINT8        _PADDING11_[0x4];
    union                                                          // 2 elements, 0x10 bytes (sizeof)    
    {
      /*0x598*/         struct _LIST_ENTRY GlobalForegroundListEntry;              // 2 elements, 0x10 bytes (sizeof)    
      struct                                                     // 2 elements, 0x10 bytes (sizeof)    
      {
        /*0x598*/             struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry; // 1 elements, 0x8 bytes (sizeof)     
        /*0x5A0*/             UINT64       InGlobalForegroundList;
      };
    };
    /*0x5A8*/     INT64        ReadOperationCount;
    /*0x5B0*/     INT64        WriteOperationCount;
    /*0x5B8*/     INT64        OtherOperationCount;
    /*0x5C0*/     INT64        ReadTransferCount;
    /*0x5C8*/     INT64        WriteTransferCount;
    /*0x5D0*/     INT64        OtherTransferCount;
    /*0x5D8*/     struct _KSCB* QueuedScb;
    /*0x5E0*/     ULONG32      ThreadTimerDelay;
    union                                                          // 2 elements, 0x4 bytes (sizeof)     
    {
      /*0x5E4*/         LONG32       ThreadFlags2;
      struct                                                     // 2 elements, 0x4 bytes (sizeof)     
      {
        /*0x5E4*/             ULONG32      PpmPolicy : 2;                            // 0 BitPosition                      
        /*0x5E4*/             ULONG32      ThreadFlags2Reserved : 30;                // 2 BitPosition                      
      };
    };
    /*0x5E8*/     UINT64       TracingPrivate[1];
    /*0x5F0*/     VOID* SchedulerAssist;
    /*0x5F8*/     VOID* AbWaitObject;
  }KTHREAD, * PKTHREAD;
  typedef struct _ETHREAD                                               // 117 elements, 0x820 bytes (sizeof) 
  {
    /*0x000*/     struct _KTHREAD Tcb;                                              // 190 elements, 0x600 bytes (sizeof) 
    /*0x600*/     union _LARGE_INTEGER CreateTime;                                  // 4 elements, 0x8 bytes (sizeof)     
    union                                                             // 2 elements, 0x10 bytes (sizeof)    
    {
      /*0x608*/         union _LARGE_INTEGER ExitTime;                                // 4 elements, 0x8 bytes (sizeof)     
      /*0x608*/         struct _LIST_ENTRY KeyedWaitChain;                            // 2 elements, 0x10 bytes (sizeof)    
    };
    union                                                             // 2 elements, 0x10 bytes (sizeof)    
    {
      /*0x618*/         struct _LIST_ENTRY PostBlockList;                             // 2 elements, 0x10 bytes (sizeof)    
      struct                                                        // 2 elements, 0x10 bytes (sizeof)    
      {
        /*0x618*/             VOID* ForwardLinkShadow;
        /*0x620*/             VOID* StartAddress;
      };
    };
    union                                                             // 3 elements, 0x8 bytes (sizeof)     
    {
      /*0x628*/         struct _TERMINATION_PORT* TerminationPort;
      /*0x628*/         struct _ETHREAD* ReaperLink;
      /*0x628*/         VOID* KeyedWaitValue;
    };
    /*0x630*/     UINT64       ActiveTimerListLock;
    /*0x638*/     struct _LIST_ENTRY ActiveTimerListHead;                           // 2 elements, 0x10 bytes (sizeof)    
    /*0x648*/     struct _CLIENT_ID Cid;                                            // 2 elements, 0x10 bytes (sizeof)    
    union                                                             // 2 elements, 0x20 bytes (sizeof)    
    {
      /*0x658*/         struct _KSEMAPHORE KeyedWaitSemaphore;                        // 2 elements, 0x20 bytes (sizeof)    
      /*0x658*/         struct _KSEMAPHORE AlpcWaitSemaphore;                         // 2 elements, 0x20 bytes (sizeof)    
    };
    /*0x678*/     union _PS_CLIENT_SECURITY_CONTEXT ClientSecurity;                 // 4 elements, 0x8 bytes (sizeof)     
    /*0x680*/     struct _LIST_ENTRY IrpList;                                       // 2 elements, 0x10 bytes (sizeof)    
    /*0x690*/     UINT64       TopLevelIrp;
    /*0x698*/     struct _DEVICE_OBJECT* DeviceToVerify;
    /*0x6A0*/     VOID* Win32StartAddress;
    /*0x6A8*/     VOID* ChargeOnlySession;
    /*0x6B0*/     VOID* LegacyPowerObject;
    /*0x6B8*/     struct _LIST_ENTRY ThreadListEntry;                               // 2 elements, 0x10 bytes (sizeof)    
    /*0x6C8*/     struct _EX_RUNDOWN_REF RundownProtect;                            // 2 elements, 0x8 bytes (sizeof)     
    /*0x6D0*/     struct _EX_PUSH_LOCK ThreadLock;                                  // 7 elements, 0x8 bytes (sizeof)     
    /*0x6D8*/     ULONG32      ReadClusterSize;
    /*0x6DC*/     LONG32       MmLockOrdering;
    union                                                             // 2 elements, 0x4 bytes (sizeof)     
    {
      /*0x6E0*/         ULONG32      CrossThreadFlags;
      struct                                                        // 21 elements, 0x4 bytes (sizeof)    
      {
        /*0x6E0*/             ULONG32      Terminated : 1;                              // 0 BitPosition                      
        /*0x6E0*/             ULONG32      ThreadInserted : 1;                          // 1 BitPosition                      
        /*0x6E0*/             ULONG32      HideFromDebugger : 1;                        // 2 BitPosition                      
        /*0x6E0*/             ULONG32      ActiveImpersonationInfo : 1;                 // 3 BitPosition                      
        /*0x6E0*/             ULONG32      HardErrorsAreDisabled : 1;                   // 4 BitPosition                      
        /*0x6E0*/             ULONG32      BreakOnTermination : 1;                      // 5 BitPosition                      
        /*0x6E0*/             ULONG32      SkipCreationMsg : 1;                         // 6 BitPosition                      
        /*0x6E0*/             ULONG32      SkipTerminationMsg : 1;                      // 7 BitPosition                      
        /*0x6E0*/             ULONG32      CopyTokenOnOpen : 1;                         // 8 BitPosition                      
        /*0x6E0*/             ULONG32      ThreadIoPriority : 3;                        // 9 BitPosition                      
        /*0x6E0*/             ULONG32      ThreadPagePriority : 3;                      // 12 BitPosition                     
        /*0x6E0*/             ULONG32      RundownFail : 1;                             // 15 BitPosition                     
        /*0x6E0*/             ULONG32      UmsForceQueueTermination : 1;                // 16 BitPosition                     
        /*0x6E0*/             ULONG32      IndirectCpuSets : 1;                         // 17 BitPosition                     
        /*0x6E0*/             ULONG32      DisableDynamicCodeOptOut : 1;                // 18 BitPosition                     
        /*0x6E0*/             ULONG32      ExplicitCaseSensitivity : 1;                 // 19 BitPosition                     
        /*0x6E0*/             ULONG32      PicoNotifyExit : 1;                          // 20 BitPosition                     
        /*0x6E0*/             ULONG32      DbgWerUserReportActive : 1;                  // 21 BitPosition                     
        /*0x6E0*/             ULONG32      ForcedSelfTrimActive : 1;                    // 22 BitPosition                     
        /*0x6E0*/             ULONG32      SamplingCoverage : 1;                        // 23 BitPosition                     
        /*0x6E0*/             ULONG32      ReservedCrossThreadFlags : 8;                // 24 BitPosition                     
      };
    };
    union                                                             // 2 elements, 0x4 bytes (sizeof)     
    {
      /*0x6E4*/         ULONG32      SameThreadPassiveFlags;
      struct                                                        // 12 elements, 0x4 bytes (sizeof)    
      {
        /*0x6E4*/             ULONG32      ActiveExWorker : 1;                          // 0 BitPosition                      
        /*0x6E4*/             ULONG32      MemoryMaker : 1;                             // 1 BitPosition                      
        /*0x6E4*/             ULONG32      StoreLockThread : 2;                         // 2 BitPosition                      
        /*0x6E4*/             ULONG32      ClonedThread : 1;                            // 4 BitPosition                      
        /*0x6E4*/             ULONG32      KeyedEventInUse : 1;                         // 5 BitPosition                      
        /*0x6E4*/             ULONG32      SelfTerminate : 1;                           // 6 BitPosition                      
        /*0x6E4*/             ULONG32      RespectIoPriority : 1;                       // 7 BitPosition                      
        /*0x6E4*/             ULONG32      ActivePageLists : 1;                         // 8 BitPosition                      
        /*0x6E4*/             ULONG32      SecureContext : 1;                           // 9 BitPosition                      
        /*0x6E4*/             ULONG32      ZeroPageThread : 1;                          // 10 BitPosition                     
        /*0x6E4*/             ULONG32      WorkloadClass : 1;                           // 11 BitPosition                     
        /*0x6E4*/             ULONG32      ReservedSameThreadPassiveFlags : 20;         // 12 BitPosition                     
      };
    };
    union                                                             // 2 elements, 0x4 bytes (sizeof)     
    {
      /*0x6E8*/         ULONG32      SameThreadApcFlags;
      struct                                                        // 2 elements, 0x4 bytes (sizeof)     
      {
        struct                                                    // 8 elements, 0x1 bytes (sizeof)     
        {
          /*0x6E8*/                 UINT8        OwnsProcessAddressSpaceExclusive : 1;    // 0 BitPosition                      
          /*0x6E8*/                 UINT8        OwnsProcessAddressSpaceShared : 1;       // 1 BitPosition                      
          /*0x6E8*/                 UINT8        HardFaultBehavior : 1;                   // 2 BitPosition                      
          /*0x6E8*/                 UINT8        StartAddressInvalid : 1;                 // 3 BitPosition                      
          /*0x6E8*/                 UINT8        EtwCalloutActive : 1;                    // 4 BitPosition                      
          /*0x6E8*/                 UINT8        SuppressSymbolLoad : 1;                  // 5 BitPosition                      
          /*0x6E8*/                 UINT8        Prefetching : 1;                         // 6 BitPosition                      
          /*0x6E8*/                 UINT8        OwnsVadExclusive : 1;                    // 7 BitPosition                      
        };
        struct                                                    // 5 elements, 0x1 bytes (sizeof)     
        {
          /*0x6E9*/                 UINT8        SystemPagePriorityActive : 1;            // 0 BitPosition                      
          /*0x6E9*/                 UINT8        SystemPagePriority : 3;                  // 1 BitPosition                      
          /*0x6E9*/                 UINT8        AllowUserWritesToExecutableMemory : 1;   // 4 BitPosition                      
          /*0x6E9*/                 UINT8        AllowKernelWritesToExecutableMemory : 1; // 5 BitPosition                      
          /*0x6E9*/                 UINT8        OwnsVadShared : 1;                       // 6 BitPosition                      
        };
      };
    };
    /*0x6EC*/     UINT8        CacheManagerActive;
    /*0x6ED*/     UINT8        DisablePageFaultClustering;
    /*0x6EE*/     UINT8        ActiveFaultCount;
    /*0x6EF*/     UINT8        LockOrderState;
    /*0x6F0*/     UINT64       AlpcMessageId;
    union                                                             // 2 elements, 0x8 bytes (sizeof)     
    {
      /*0x6F8*/         VOID* AlpcMessage;
      /*0x6F8*/         ULONG32      AlpcReceiveAttributeSet;
    };
    /*0x700*/     struct _LIST_ENTRY AlpcWaitListEntry;                             // 2 elements, 0x10 bytes (sizeof)    
    /*0x710*/     LONG32       ExitStatus;
    /*0x714*/     ULONG32      CacheManagerCount;
    /*0x718*/     ULONG32      IoBoostCount;
    /*0x71C*/     ULONG32      IoQoSBoostCount;
    /*0x720*/     ULONG32      IoQoSThrottleCount;
    /*0x724*/     ULONG32      KernelStackReference;
    /*0x728*/     struct _LIST_ENTRY BoostList;                                     // 2 elements, 0x10 bytes (sizeof)    
    /*0x738*/     struct _LIST_ENTRY DeboostList;                                   // 2 elements, 0x10 bytes (sizeof)    
    /*0x748*/     UINT64       BoostListLock;
    /*0x750*/     UINT64       IrpListLock;
    /*0x758*/     VOID* ReservedForSynchTracking;
    /*0x760*/     struct _SINGLE_LIST_ENTRY CmCallbackListHead;                     // 1 elements, 0x8 bytes (sizeof)     
    /*0x768*/     struct _GUID* ActivityId;
    /*0x770*/     struct _SINGLE_LIST_ENTRY SeLearningModeListHead;                 // 1 elements, 0x8 bytes (sizeof)     
    /*0x778*/     VOID* VerifierContext;
    /*0x780*/     VOID* AdjustedClientToken;
    /*0x788*/     VOID* WorkOnBehalfThread;
    /*0x790*/     struct _PS_PROPERTY_SET PropertySet;                              // 2 elements, 0x18 bytes (sizeof)    
    /*0x7A8*/     VOID* PicoContext;
    /*0x7B0*/     UINT64       UserFsBase;
    /*0x7B8*/     UINT64       UserGsBase;
    /*0x7C0*/     struct _THREAD_ENERGY_VALUES* EnergyValues;
    /*0x7C8*/     VOID* CmDbgInfo;
    union                                                             // 2 elements, 0x8 bytes (sizeof)     
    {
      /*0x7D0*/         UINT64       SelectedCpuSets;
      /*0x7D0*/         UINT64* SelectedCpuSetsIndirect;
    };
    /*0x7D8*/     struct _EJOB* Silo;
    /*0x7E0*/     struct _UNICODE_STRING* ThreadName;
    /*0x7E8*/     struct _CONTEXT* SetContextState;
    /*0x7F0*/     ULONG32      LastExpectedRunTime;
    /*0x7F4*/     ULONG32      HeapData;
    /*0x7F8*/     struct _LIST_ENTRY OwnerEntryListHead;                            // 2 elements, 0x10 bytes (sizeof)    
    /*0x808*/     UINT64       DisownedOwnerEntryListLock;
    /*0x810*/     struct _LIST_ENTRY DisownedOwnerEntryListHead;                    // 2 elements, 0x10 bytes (sizeof)    
  }ETHREAD, * PETHREAD;

}
#endif
