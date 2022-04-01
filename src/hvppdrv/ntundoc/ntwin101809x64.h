#pragma once
#include <ntifs.h>
#ifndef NTWIN101809X64_H
#define NTWIN101809X64_H
namespace ntwin101809x64
{
  //0xa8 bytes (sizeof)
  struct _KAFFINITY_EX
  {
    USHORT Count;                                                           //0x0
    USHORT Size;                                                            //0x2
    ULONG Reserved;                                                         //0x4
    ULONGLONG Bitmap[20];                                                   //0x8
  };

  //0x1 bytes (sizeof)
  union _KEXECUTE_OPTIONS
  {
    UCHAR ExecuteDisable : 1;                                                 //0x0
    UCHAR ExecuteEnable : 1;                                                  //0x0
    UCHAR DisableThunkEmulation : 1;                                          //0x0
    UCHAR Permanent : 1;                                                      //0x0
    UCHAR ExecuteDispatchEnable : 1;                                          //0x0
    UCHAR ImageDispatchEnable : 1;                                            //0x0
    UCHAR DisableExceptionChainValidation : 1;                                //0x0
    UCHAR Spare : 1;                                                          //0x0
    volatile UCHAR ExecuteOptions;                                          //0x0
    UCHAR ExecuteOptionsNV;                                                 //0x0
  };

  //0x4 bytes (sizeof)
  union _KSTACK_COUNT
  {
    LONG Value;                                                             //0x0
    ULONG State : 3;                                                          //0x0
    ULONG StackCount : 29;                                                    //0x0
  };

  //0x2d8 bytes (sizeof)
  struct _KPROCESS
  {
    struct _DISPATCHER_HEADER Header;                                       //0x0
    struct _LIST_ENTRY ProfileListHead;                                     //0x18
    ULONGLONG DirectoryTableBase;                                           //0x28
    struct _LIST_ENTRY ThreadListHead;                                      //0x30
    ULONG ProcessLock;                                                      //0x40
    ULONG ProcessTimerDelay;                                                //0x44
    ULONGLONG DeepFreezeStartTime;                                          //0x48
    struct _KAFFINITY_EX Affinity;                                          //0x50
    struct _LIST_ENTRY ReadyListHead;                                       //0xf8
    struct _SINGLE_LIST_ENTRY SwapListEntry;                                //0x108
    volatile struct _KAFFINITY_EX ActiveProcessors;                         //0x110
    union
    {
      struct
      {
        LONG AutoAlignment : 1;                                           //0x1b8
        LONG DisableBoost : 1;                                            //0x1b8
        LONG DisableQuantum : 1;                                          //0x1b8
        ULONG DeepFreeze : 1;                                             //0x1b8
        ULONG TimerVirtualization : 1;                                    //0x1b8
        ULONG CheckStackExtents : 1;                                      //0x1b8
        ULONG PpmPolicy : 2;                                              //0x1b8
        ULONG ActiveGroupsMask : 20;                                      //0x1b8
        LONG ReservedFlags : 4;                                           //0x1b8
      };
      volatile LONG ProcessFlags;                                         //0x1b8
    };
    CHAR BasePriority;                                                      //0x1bc
    CHAR QuantumReset;                                                      //0x1bd
    UCHAR Visited;                                                          //0x1be
    union _KEXECUTE_OPTIONS Flags;                                          //0x1bf
    ULONG ThreadSeed[20];                                                   //0x1c0
    USHORT IdealNode[20];                                                   //0x210
    USHORT IdealGlobalNode;                                                 //0x238
    USHORT Spare1;                                                          //0x23a
    _KSTACK_COUNT StackCount;                                               //0x23c
    struct _LIST_ENTRY ProcessListEntry;                                    //0x240
    ULONGLONG CycleTime;                                                    //0x250
    ULONGLONG ContextSwitches;                                              //0x258
    struct _KSCHEDULING_GROUP* SchedulingGroup;                             //0x260
    ULONG FreezeCount;                                                      //0x268
    ULONG KernelTime;                                                       //0x26c
    ULONG UserTime;                                                         //0x270
    ULONG ReadyTime;                                                        //0x274
    UCHAR Spare2[80];                                                       //0x278
    VOID* InstrumentationCallback;                                          //0x2c8
    ULONGLONG SecurePid;                                                    //0x2d0
  };

  static_assert(sizeof(_KPROCESS) == 0x2d8, "no =");

  //0x8 bytes (sizeof)
  struct _EX_PUSH_LOCK
  {
    union
    {
      struct
      {
        ULONGLONG Locked : 1;                                             //0x0
        ULONGLONG Waiting : 1;                                            //0x0
        ULONGLONG Waking : 1;                                             //0x0
        ULONGLONG MultipleShared : 1;                                     //0x0
        ULONGLONG Shared : 60;                                            //0x0
      };
      ULONGLONG Value;                                                    //0x0
      VOID* Ptr;                                                          //0x0
    };
  };

  //0x8 bytes (sizeof)
  struct _EX_FAST_REF
  {
    union
    {
      VOID* Object;                                                       //0x0
      ULONGLONG RefCnt : 4;                                                 //0x0
      ULONGLONG Value;                                                    //0x0
    };
  };

  //0x8 bytes (sizeof)
  struct _RTL_AVL_TREE
  {
    struct _RTL_BALANCED_NODE* Root;                                        //0x0
  };

  //0x8 bytes (sizeof)
  struct _SE_AUDIT_PROCESS_CREATION_INFO
  {
    struct _OBJECT_NAME_INFORMATION* ImageFileName;                         //0x0
  };

  //0x4 bytes (sizeof)
  struct _MMSUPPORT_FLAGS
  {
    union
    {
      struct
      {
        UCHAR WorkingSetType : 3;                                         //0x0
        UCHAR Reserved0 : 3;                                              //0x0
        UCHAR MaximumWorkingSetHard : 1;                                  //0x0
        UCHAR MinimumWorkingSetHard : 1;                                  //0x0
        UCHAR SessionMaster : 1;                                          //0x1
        UCHAR TrimmerState : 2;                                           //0x1
        UCHAR Reserved : 1;                                               //0x1
        UCHAR PageStealers : 4;                                           //0x1
      };
      USHORT u1;                                                          //0x0
    };
    UCHAR MemoryPriority;                                                   //0x2
    union
    {
      struct
      {
        UCHAR WsleDeleted : 1;                                            //0x3
        UCHAR SvmEnabled : 1;                                             //0x3
        UCHAR ForceAge : 1;                                               //0x3
        UCHAR ForceTrim : 1;                                              //0x3
        UCHAR UnlockInProgress : 1;                                       //0x3
        UCHAR NewMaximum : 1;                                             //0x3
        UCHAR CommitReleaseState : 2;                                     //0x3
      };
      UCHAR u2;                                                           //0x3
    };
  };

  //0xc8 bytes (sizeof)
  struct _MMSUPPORT_INSTANCE
  {
    USHORT NextPageColor;                                                   //0x0
    USHORT LastTrimStamp;                                                   //0x2
    ULONG PageFaultCount;                                                   //0x4
    ULONGLONG TrimmedPageCount;                                             //0x8
    struct _MMWSL_INSTANCE* VmWorkingSetList;                               //0x10
    struct _LIST_ENTRY WorkingSetExpansionLinks;                            //0x18
    ULONGLONG AgeDistribution[8];                                           //0x28
    struct _KGATE* ExitOutswapGate;                                         //0x68
    ULONGLONG MinimumWorkingSetSize;                                        //0x70
    ULONGLONG WorkingSetLeafSize;                                           //0x78
    ULONGLONG WorkingSetLeafPrivateSize;                                    //0x80
    ULONGLONG WorkingSetSize;                                               //0x88
    ULONGLONG WorkingSetPrivateSize;                                        //0x90
    ULONGLONG MaximumWorkingSetSize;                                        //0x98
    ULONGLONG PeakWorkingSetSize;                                           //0xa0
    ULONG HardFaultCount;                                                   //0xa8
    USHORT PartitionId;                                                     //0xac
    USHORT Pad0;                                                            //0xae
    union
    {
      VOID* InstancedWorkingSet;                                          //0xb0
    } u1;                                                                   //0xb0
    ULONGLONG Reserved0;                                                    //0xb8
    struct _MMSUPPORT_FLAGS Flags;                                          //0xc0
  };

  //0x48 bytes (sizeof)
  struct _MMSUPPORT_SHARED
  {
    volatile LONG WorkingSetLock;                                           //0x0
    LONG GoodCitizenWaiting;                                                //0x4
    ULONGLONG ReleasedCommitDebt;                                           //0x8
    ULONGLONG ResetPagesRepurposedCount;                                    //0x10
    VOID* WsSwapSupport;                                                    //0x18
    VOID* CommitReleaseContext;                                             //0x20
    VOID* AccessLog;                                                        //0x28
    volatile ULONGLONG ChargedWslePages;                                    //0x30
    ULONGLONG ActualWslePages;                                              //0x38
    ULONGLONG Reserved0;                                                    //0x40
  };

  //0x110 bytes (sizeof)
  struct _MMSUPPORT_FULL
  {
    struct _MMSUPPORT_INSTANCE Instance;                                    //0x0
    struct _MMSUPPORT_SHARED Shared;                                        //0xc8
  };

  //0x20 bytes (sizeof)
  struct _ALPC_PROCESS_CONTEXT
  {
    struct _EX_PUSH_LOCK Lock;                                              //0x0
    struct _LIST_ENTRY ViewListHead;                                        //0x8
    volatile ULONGLONG PagedPoolQuotaCache;                                 //0x18
  };

  //0x1 bytes (sizeof)
  struct _PS_PROTECTION
  {
    union
    {
      UCHAR Level;                                                        //0x0
      struct
      {
        UCHAR Type : 3;                                                   //0x0
        UCHAR Audit : 1;                                                  //0x0
        UCHAR Signer : 4;                                                 //0x0
      };
    };
  };

  //0x8 bytes (sizeof)
  union _PS_INTERLOCKED_TIMER_DELAY_VALUES
  {
    ULONGLONG DelayMs : 30;                                                   //0x0
    ULONGLONG CoalescingWindowMs : 30;                                        //0x0
    ULONGLONG Reserved : 1;                                                   //0x0
    ULONGLONG NewTimerWheel : 1;                                              //0x0
    ULONGLONG Retry : 1;                                                      //0x0
    ULONGLONG Locked : 1;                                                     //0x0
    ULONGLONG All;                                                          //0x0
  };

  //0x8 bytes (sizeof)
  struct _JOBOBJECT_WAKE_FILTER
  {
    ULONG HighEdgeFilter;                                                   //0x0
    ULONG LowEdgeFilter;                                                    //0x4
  };

  //0x30 bytes (sizeof)
  struct _PS_PROCESS_WAKE_INFORMATION
  {
    ULONGLONG NotificationChannel;                                          //0x0
    ULONG WakeCounters[7];                                                  //0x8
    struct _JOBOBJECT_WAKE_FILTER WakeFilter;                               //0x24
    ULONG NoWakeCounter;                                                    //0x2c
  };

  //0x850 bytes (sizeof)
  struct _EPROCESS
  {
    struct _KPROCESS Pcb;                                                   //0x0
    struct _EX_PUSH_LOCK ProcessLock;                                       //0x2d8
    VOID* UniqueProcessId;                                                  //0x2e0
    struct _LIST_ENTRY ActiveProcessLinks;                                  //0x2e8
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x2f8
    union
    {
      ULONG Flags2;                                                       //0x300
      struct
      {
        ULONG JobNotReallyActive : 1;                                     //0x300
        ULONG AccountingFolded : 1;                                       //0x300
        ULONG NewProcessReported : 1;                                     //0x300
        ULONG ExitProcessReported : 1;                                    //0x300
        ULONG ReportCommitChanges : 1;                                    //0x300
        ULONG LastReportMemory : 1;                                       //0x300
        ULONG ForceWakeCharge : 1;                                        //0x300
        ULONG CrossSessionCreate : 1;                                     //0x300
        ULONG NeedsHandleRundown : 1;                                     //0x300
        ULONG RefTraceEnabled : 1;                                        //0x300
        ULONG PicoCreated : 1;                                            //0x300
        ULONG EmptyJobEvaluated : 1;                                      //0x300
        ULONG DefaultPagePriority : 3;                                    //0x300
        ULONG PrimaryTokenFrozen : 1;                                     //0x300
        ULONG ProcessVerifierTarget : 1;                                  //0x300
        ULONG RestrictSetThreadContext : 1;                               //0x300
        ULONG AffinityPermanent : 1;                                      //0x300
        ULONG AffinityUpdateEnable : 1;                                   //0x300
        ULONG PropagateNode : 1;                                          //0x300
        ULONG ExplicitAffinity : 1;                                       //0x300
        ULONG ProcessExecutionState : 2;                                  //0x300
        ULONG EnableReadVmLogging : 1;                                    //0x300
        ULONG EnableWriteVmLogging : 1;                                   //0x300
        ULONG FatalAccessTerminationRequested : 1;                        //0x300
        ULONG DisableSystemAllowedCpuSet : 1;                             //0x300
        ULONG ProcessStateChangeRequest : 2;                              //0x300
        ULONG ProcessStateChangeInProgress : 1;                           //0x300
        ULONG InPrivate : 1;                                              //0x300
      };
    };
    union
    {
      ULONG Flags;                                                        //0x304
      struct
      {
        ULONG CreateReported : 1;                                         //0x304
        ULONG NoDebugInherit : 1;                                         //0x304
        ULONG ProcessExiting : 1;                                         //0x304
        ULONG ProcessDelete : 1;                                          //0x304
        ULONG ManageExecutableMemoryWrites : 1;                           //0x304
        ULONG VmDeleted : 1;                                              //0x304
        ULONG OutswapEnabled : 1;                                         //0x304
        ULONG Outswapped : 1;                                             //0x304
        ULONG FailFastOnCommitFail : 1;                                   //0x304
        ULONG Wow64VaSpace4Gb : 1;                                        //0x304
        ULONG AddressSpaceInitialized : 2;                                //0x304
        ULONG SetTimerResolution : 1;                                     //0x304
        ULONG BreakOnTermination : 1;                                     //0x304
        ULONG DeprioritizeViews : 1;                                      //0x304
        ULONG WriteWatch : 1;                                             //0x304
        ULONG ProcessInSession : 1;                                       //0x304
        ULONG OverrideAddressSpace : 1;                                   //0x304
        ULONG HasAddressSpace : 1;                                        //0x304
        ULONG LaunchPrefetched : 1;                                       //0x304
        ULONG Background : 1;                                             //0x304
        ULONG VmTopDown : 1;                                              //0x304
        ULONG ImageNotifyDone : 1;                                        //0x304
        ULONG PdeUpdateNeeded : 1;                                        //0x304
        ULONG VdmAllowed : 1;                                             //0x304
        ULONG ProcessRundown : 1;                                         //0x304
        ULONG ProcessInserted : 1;                                        //0x304
        ULONG DefaultIoPriority : 3;                                      //0x304
        ULONG ProcessSelfDelete : 1;                                      //0x304
        ULONG SetTimerResolutionLink : 1;                                 //0x304
      };
    };
    union _LARGE_INTEGER CreateTime;                                        //0x308
    ULONGLONG ProcessQuotaUsage[2];                                         //0x310
    ULONGLONG ProcessQuotaPeak[2];                                          //0x320
    ULONGLONG PeakVirtualSize;                                              //0x330
    ULONGLONG VirtualSize;                                                  //0x338
    struct _LIST_ENTRY SessionProcessLinks;                                 //0x340
    union
    {
      VOID* ExceptionPortData;                                            //0x350
      ULONGLONG ExceptionPortValue;                                       //0x350
      ULONGLONG ExceptionPortState : 3;                                     //0x350
    };
    struct _EX_FAST_REF Token;                                              //0x358
    ULONGLONG MmReserved;                                                   //0x360
    struct _EX_PUSH_LOCK AddressCreationLock;                               //0x368
    struct _EX_PUSH_LOCK PageTableCommitmentLock;                           //0x370
    struct _ETHREAD* RotateInProgress;                                      //0x378
    struct _ETHREAD* ForkInProgress;                                        //0x380
    struct _EJOB* volatile CommitChargeJob;                                 //0x388
    struct _RTL_AVL_TREE CloneRoot;                                         //0x390
    volatile ULONGLONG NumberOfPrivatePages;                                //0x398
    volatile ULONGLONG NumberOfLockedPages;                                 //0x3a0
    VOID* Win32Process;                                                     //0x3a8
    struct _EJOB* volatile Job;                                             //0x3b0
    VOID* SectionObject;                                                    //0x3b8
    VOID* SectionBaseAddress;                                               //0x3c0
    ULONG Cookie;                                                           //0x3c8
    struct _PAGEFAULT_HISTORY* WorkingSetWatch;                             //0x3d0
    VOID* Win32WindowStation;                                               //0x3d8
    VOID* InheritedFromUniqueProcessId;                                     //0x3e0
    VOID* Spare0;                                                           //0x3e8
    volatile ULONGLONG OwnerProcessId;                                      //0x3f0
    struct _PEB* Peb;                                                       //0x3f8
    struct _MM_SESSION_SPACE* Session;                                      //0x400
    VOID* Spare1;                                                           //0x408
    struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;                               //0x410
    struct _HANDLE_TABLE* ObjectTable;                                      //0x418
    VOID* DebugPort;                                                        //0x420
    struct _EWOW64PROCESS* WoW64Process;                                    //0x428
    VOID* DeviceMap;                                                        //0x430
    VOID* EtwDataSource;                                                    //0x438
    ULONGLONG PageDirectoryPte;                                             //0x440
    struct _FILE_OBJECT* ImageFilePointer;                                  //0x448
    UCHAR ImageFileName[15];                                                //0x450
    UCHAR PriorityClass;                                                    //0x45f
    VOID* SecurityPort;                                                     //0x460
    struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;      //0x468
    struct _LIST_ENTRY JobLinks;                                            //0x470
    VOID* HighestUserAddress;                                               //0x480
    struct _LIST_ENTRY ThreadListHead;                                      //0x488
    volatile ULONG ActiveThreads;                                           //0x498
    ULONG ImagePathHash;                                                    //0x49c
    ULONG DefaultHardErrorProcessing;                                       //0x4a0
    LONG LastThreadExitStatus;                                              //0x4a4
    struct _EX_FAST_REF PrefetchTrace;                                      //0x4a8
    VOID* LockedPagesList;                                                  //0x4b0
    union _LARGE_INTEGER ReadOperationCount;                                //0x4b8
    union _LARGE_INTEGER WriteOperationCount;                               //0x4c0
    union _LARGE_INTEGER OtherOperationCount;                               //0x4c8
    union _LARGE_INTEGER ReadTransferCount;                                 //0x4d0
    union _LARGE_INTEGER WriteTransferCount;                                //0x4d8
    union _LARGE_INTEGER OtherTransferCount;                                //0x4e0
    ULONGLONG CommitChargeLimit;                                            //0x4e8
    volatile ULONGLONG CommitCharge;                                        //0x4f0
    volatile ULONGLONG CommitChargePeak;                                    //0x4f8
    struct _MMSUPPORT_FULL Vm;                                              //0x500
    struct _LIST_ENTRY MmProcessLinks;                                      //0x610
    ULONG ModifiedPageCount;                                                //0x620
    LONG ExitStatus;                                                        //0x624
    struct _RTL_AVL_TREE VadRoot;                                           //0x628
    VOID* VadHint;                                                          //0x630
    ULONGLONG VadCount;                                                     //0x638
    volatile ULONGLONG VadPhysicalPages;                                    //0x640
    ULONGLONG VadPhysicalPagesLimit;                                        //0x648
    struct _ALPC_PROCESS_CONTEXT AlpcContext;                               //0x650
    struct _LIST_ENTRY TimerResolutionLink;                                 //0x670
    struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;               //0x680
    ULONG RequestedTimerResolution;                                         //0x688
    ULONG SmallestTimerResolution;                                          //0x68c
    union _LARGE_INTEGER ExitTime;                                          //0x690
    struct _INVERTED_FUNCTION_TABLE* InvertedFunctionTable;                 //0x698
    struct _EX_PUSH_LOCK InvertedFunctionTableLock;                         //0x6a0
    ULONG ActiveThreadsHighWatermark;                                       //0x6a8
    ULONG LargePrivateVadCount;                                             //0x6ac
    struct _EX_PUSH_LOCK ThreadListLock;                                    //0x6b0
    VOID* WnfContext;                                                       //0x6b8
    struct _EJOB* ServerSilo;                                               //0x6c0
    UCHAR SignatureLevel;                                                   //0x6c8
    UCHAR SectionSignatureLevel;                                            //0x6c9
    struct _PS_PROTECTION Protection;                                       //0x6ca
    UCHAR HangCount : 3;                                                      //0x6cb
    UCHAR GhostCount : 3;                                                     //0x6cb
    UCHAR PrefilterException : 1;                                             //0x6cb
    union
    {
      ULONG Flags3;                                                       //0x6cc
      struct
      {
        ULONG Minimal : 1;                                                //0x6cc
        ULONG ReplacingPageRoot : 1;                                      //0x6cc
        ULONG Crashed : 1;                                                //0x6cc
        ULONG JobVadsAreTracked : 1;                                      //0x6cc
        ULONG VadTrackingDisabled : 1;                                    //0x6cc
        ULONG AuxiliaryProcess : 1;                                       //0x6cc
        ULONG SubsystemProcess : 1;                                       //0x6cc
        ULONG IndirectCpuSets : 1;                                        //0x6cc
        ULONG RelinquishedCommit : 1;                                     //0x6cc
        ULONG HighGraphicsPriority : 1;                                   //0x6cc
        ULONG CommitFailLogged : 1;                                       //0x6cc
        ULONG ReserveFailLogged : 1;                                      //0x6cc
        ULONG SystemProcess : 1;                                          //0x6cc
        ULONG HideImageBaseAddresses : 1;                                 //0x6cc
        ULONG AddressPolicyFrozen : 1;                                    //0x6cc
        ULONG ProcessFirstResume : 1;                                     //0x6cc
        ULONG ForegroundExternal : 1;                                     //0x6cc
        ULONG ForegroundSystem : 1;                                       //0x6cc
        ULONG HighMemoryPriority : 1;                                     //0x6cc
        ULONG EnableProcessSuspendResumeLogging : 1;                      //0x6cc
        ULONG EnableThreadSuspendResumeLogging : 1;                       //0x6cc
        ULONG SecurityDomainChanged : 1;                                  //0x6cc
        ULONG SecurityFreezeComplete : 1;                                 //0x6cc
        ULONG VmProcessorHost : 1;                                        //0x6cc
      };
    };
    LONG DeviceAsid;                                                        //0x6d0
    VOID* SvmData;                                                          //0x6d8
    struct _EX_PUSH_LOCK SvmProcessLock;                                    //0x6e0
    ULONGLONG SvmLock;                                                      //0x6e8
    struct _LIST_ENTRY SvmProcessDeviceListHead;                            //0x6f0
    ULONGLONG LastFreezeInterruptTime;                                      //0x700
    struct _PROCESS_DISK_COUNTERS* DiskCounters;                            //0x708
    VOID* PicoContext;                                                      //0x710
    VOID* EnclaveTable;                                                     //0x718
    ULONGLONG EnclaveNumber;                                                //0x720
    struct _EX_PUSH_LOCK EnclaveLock;                                       //0x728
    ULONG HighPriorityFaultsAllowed;                                        //0x730
    struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;                       //0x738
    VOID* VmContext;                                                        //0x740
    ULONGLONG SequenceNumber;                                               //0x748
    ULONGLONG CreateInterruptTime;                                          //0x750
    ULONGLONG CreateUnbiasedInterruptTime;                                  //0x758
    ULONGLONG TotalUnbiasedFrozenTime;                                      //0x760
    ULONGLONG LastAppStateUpdateTime;                                       //0x768
    ULONGLONG LastAppStateUptime : 61;                                        //0x770
    ULONGLONG LastAppState : 3;                                               //0x770
    volatile ULONGLONG SharedCommitCharge;                                  //0x778
    struct _EX_PUSH_LOCK SharedCommitLock;                                  //0x780
    struct _LIST_ENTRY SharedCommitLinks;                                   //0x788
    union
    {
      struct
      {
        ULONGLONG AllowedCpuSets;                                       //0x798
        ULONGLONG DefaultCpuSets;                                       //0x7a0
      };
      struct
      {
        ULONGLONG* AllowedCpuSetsIndirect;                              //0x798
        ULONGLONG* DefaultCpuSetsIndirect;                              //0x7a0
      };
    };
    VOID* DiskIoAttribution;                                                //0x7a8
    VOID* DxgProcess;                                                       //0x7b0
    ULONG Win32KFilterSet;                                                  //0x7b8
    _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;     //0x7c0
    volatile ULONG KTimerSets;                                              //0x7c8
    volatile ULONG KTimer2Sets;                                             //0x7cc
    volatile ULONG ThreadTimerSets;                                         //0x7d0
    ULONGLONG VirtualTimerListLock;                                         //0x7d8
    struct _LIST_ENTRY VirtualTimerListHead;                                //0x7e0
    union
    {
      struct _WNF_STATE_NAME WakeChannel;                                 //0x7f0
      struct _PS_PROCESS_WAKE_INFORMATION WakeInfo;                       //0x7f0
    };
    union
    {
      ULONG MitigationFlags;                                              //0x820
      struct
      {
        ULONG ControlFlowGuardEnabled : 1;                                //0x820
        ULONG ControlFlowGuardExportSuppressionEnabled : 1;               //0x820
        ULONG ControlFlowGuardStrict : 1;                                 //0x820
        ULONG DisallowStrippedImages : 1;                                 //0x820
        ULONG ForceRelocateImages : 1;                                    //0x820
        ULONG HighEntropyASLREnabled : 1;                                 //0x820
        ULONG StackRandomizationDisabled : 1;                             //0x820
        ULONG ExtensionPointDisable : 1;                                  //0x820
        ULONG DisableDynamicCode : 1;                                     //0x820
        ULONG DisableDynamicCodeAllowOptOut : 1;                          //0x820
        ULONG DisableDynamicCodeAllowRemoteDowngrade : 1;                 //0x820
        ULONG AuditDisableDynamicCode : 1;                                //0x820
        ULONG DisallowWin32kSystemCalls : 1;                              //0x820
        ULONG AuditDisallowWin32kSystemCalls : 1;                         //0x820
        ULONG EnableFilteredWin32kAPIs : 1;                               //0x820
        ULONG AuditFilteredWin32kAPIs : 1;                                //0x820
        ULONG DisableNonSystemFonts : 1;                                  //0x820
        ULONG AuditNonSystemFontLoading : 1;                              //0x820
        ULONG PreferSystem32Images : 1;                                   //0x820
        ULONG ProhibitRemoteImageMap : 1;                                 //0x820
        ULONG AuditProhibitRemoteImageMap : 1;                            //0x820
        ULONG ProhibitLowILImageMap : 1;                                  //0x820
        ULONG AuditProhibitLowILImageMap : 1;                             //0x820
        ULONG SignatureMitigationOptIn : 1;                               //0x820
        ULONG AuditBlockNonMicrosoftBinaries : 1;                         //0x820
        ULONG AuditBlockNonMicrosoftBinariesAllowStore : 1;               //0x820
        ULONG LoaderIntegrityContinuityEnabled : 1;                       //0x820
        ULONG AuditLoaderIntegrityContinuity : 1;                         //0x820
        ULONG EnableModuleTamperingProtection : 1;                        //0x820
        ULONG EnableModuleTamperingProtectionNoInherit : 1;               //0x820
        ULONG RestrictIndirectBranchPrediction : 1;                       //0x820
        ULONG IsolateSecurityDomain : 1;                                  //0x820
      } MitigationFlagsValues;                                            //0x820
    };
    union
    {
      ULONG MitigationFlags2;                                             //0x824
      struct
      {
        ULONG EnableExportAddressFilter : 1;                              //0x824
        ULONG AuditExportAddressFilter : 1;                               //0x824
        ULONG EnableExportAddressFilterPlus : 1;                          //0x824
        ULONG AuditExportAddressFilterPlus : 1;                           //0x824
        ULONG EnableRopStackPivot : 1;                                    //0x824
        ULONG AuditRopStackPivot : 1;                                     //0x824
        ULONG EnableRopCallerCheck : 1;                                   //0x824
        ULONG AuditRopCallerCheck : 1;                                    //0x824
        ULONG EnableRopSimExec : 1;                                       //0x824
        ULONG AuditRopSimExec : 1;                                        //0x824
        ULONG EnableImportAddressFilter : 1;                              //0x824
        ULONG AuditImportAddressFilter : 1;                               //0x824
        ULONG DisablePageCombine : 1;                                     //0x824
        ULONG SpeculativeStoreBypassDisable : 1;                          //0x824
        ULONG CetShadowStacks : 1;                                        //0x824
      } MitigationFlags2Values;                                           //0x824
    };
    VOID* PartitionObject;                                                  //0x828
    ULONGLONG SecurityDomain;                                               //0x830
    ULONGLONG ParentSecurityDomain;                                         //0x838
    VOID* CoverageSamplerContext;                                           //0x840
    VOID* MmHotPatchContext;                                                //0x848
  };
  static_assert(sizeof(_EPROCESS) == 0x850, "!=");

  //0x190 bytes (sizeof)
  struct _KTRAP_FRAME
  {
    ULONGLONG P1Home;                                                       //0x0
    ULONGLONG P2Home;                                                       //0x8
    ULONGLONG P3Home;                                                       //0x10
    ULONGLONG P4Home;                                                       //0x18
    ULONGLONG P5;                                                           //0x20
    CHAR PreviousMode;                                                      //0x28
    UCHAR PreviousIrql;                                                     //0x29
    UCHAR FaultIndicator;                                                   //0x2a
    UCHAR ExceptionActive;                                                  //0x2b
    ULONG MxCsr;                                                            //0x2c
    ULONGLONG Rax;                                                          //0x30
    ULONGLONG Rcx;                                                          //0x38
    ULONGLONG Rdx;                                                          //0x40
    ULONGLONG R8;                                                           //0x48
    ULONGLONG R9;                                                           //0x50
    ULONGLONG R10;                                                          //0x58
    ULONGLONG R11;                                                          //0x60
    union
    {
      ULONGLONG GsBase;                                                   //0x68
      ULONGLONG GsSwap;                                                   //0x68
    };
    struct _M128A Xmm0;                                                     //0x70
    struct _M128A Xmm1;                                                     //0x80
    struct _M128A Xmm2;                                                     //0x90
    struct _M128A Xmm3;                                                     //0xa0
    struct _M128A Xmm4;                                                     //0xb0
    struct _M128A Xmm5;                                                     //0xc0
    union
    {
      ULONGLONG FaultAddress;                                             //0xd0
      ULONGLONG ContextRecord;                                            //0xd0
    };
    ULONGLONG Dr0;                                                          //0xd8
    ULONGLONG Dr1;                                                          //0xe0
    ULONGLONG Dr2;                                                          //0xe8
    ULONGLONG Dr3;                                                          //0xf0
    ULONGLONG Dr6;                                                          //0xf8
    ULONGLONG Dr7;                                                          //0x100
    ULONGLONG DebugControl;                                                 //0x108
    ULONGLONG LastBranchToRip;                                              //0x110
    ULONGLONG LastBranchFromRip;                                            //0x118
    ULONGLONG LastExceptionToRip;                                           //0x120
    ULONGLONG LastExceptionFromRip;                                         //0x128
    USHORT SegDs;                                                           //0x130
    USHORT SegEs;                                                           //0x132
    USHORT SegFs;                                                           //0x134
    USHORT SegGs;                                                           //0x136
    ULONGLONG TrapFrame;                                                    //0x138
    ULONGLONG Rbx;                                                          //0x140
    ULONGLONG Rdi;                                                          //0x148
    ULONGLONG Rsi;                                                          //0x150
    ULONGLONG Rbp;                                                          //0x158
    union
    {
      ULONGLONG ErrorCode;                                                //0x160
      ULONGLONG ExceptionFrame;                                           //0x160
    };
    ULONGLONG Rip;                                                          //0x168
    USHORT SegCs;                                                           //0x170
    UCHAR Fill0;                                                            //0x172
    UCHAR Logging;                                                          //0x173
    USHORT Fill1[2];                                                        //0x174
    ULONG EFlags;                                                           //0x178
    ULONG Fill2;                                                            //0x17c
    ULONGLONG Rsp;                                                          //0x180
    USHORT SegSs;                                                           //0x188
    USHORT Fill3;                                                           //0x18a
    ULONG Fill4;                                                            //0x18c
  };

  //0x140 bytes (sizeof)
  struct _KEXCEPTION_FRAME
  {
    ULONGLONG P1Home;                                                       //0x0
    ULONGLONG P2Home;                                                       //0x8
    ULONGLONG P3Home;                                                       //0x10
    ULONGLONG P4Home;                                                       //0x18
    ULONGLONG P5;                                                           //0x20
    ULONGLONG Spare1;                                                       //0x28
    struct _M128A Xmm6;                                                     //0x30
    struct _M128A Xmm7;                                                     //0x40
    struct _M128A Xmm8;                                                     //0x50
    struct _M128A Xmm9;                                                     //0x60
    struct _M128A Xmm10;                                                    //0x70
    struct _M128A Xmm11;                                                    //0x80
    struct _M128A Xmm12;                                                    //0x90
    struct _M128A Xmm13;                                                    //0xa0
    struct _M128A Xmm14;                                                    //0xb0
    struct _M128A Xmm15;                                                    //0xc0
    ULONGLONG TrapFrame;                                                    //0xd0
    ULONGLONG OutputBuffer;                                                 //0xd8
    ULONGLONG OutputLength;                                                 //0xe0
    ULONGLONG Spare2;                                                       //0xe8
    ULONGLONG MxCsr;                                                        //0xf0
    ULONGLONG Rbp;                                                          //0xf8
    ULONGLONG Rbx;                                                          //0x100
    ULONGLONG Rdi;                                                          //0x108
    ULONGLONG Rsi;                                                          //0x110
    ULONGLONG R12;                                                          //0x118
    ULONGLONG R13;                                                          //0x120
    ULONGLONG R14;                                                          //0x128
    ULONGLONG R15;                                                          //0x130
    ULONGLONG Return;                                                       //0x138
  };

  //0x4d0 bytes (sizeof)
  struct _CONTEXT
  {
    ULONGLONG P1Home;                                                       //0x0
    ULONGLONG P2Home;                                                       //0x8
    ULONGLONG P3Home;                                                       //0x10
    ULONGLONG P4Home;                                                       //0x18
    ULONGLONG P5Home;                                                       //0x20
    ULONGLONG P6Home;                                                       //0x28
    ULONG ContextFlags;                                                     //0x30
    ULONG MxCsr;                                                            //0x34
    USHORT SegCs;                                                           //0x38
    USHORT SegDs;                                                           //0x3a
    USHORT SegEs;                                                           //0x3c
    USHORT SegFs;                                                           //0x3e
    USHORT SegGs;                                                           //0x40
    USHORT SegSs;                                                           //0x42
    ULONG EFlags;                                                           //0x44
    ULONGLONG Dr0;                                                          //0x48
    ULONGLONG Dr1;                                                          //0x50
    ULONGLONG Dr2;                                                          //0x58
    ULONGLONG Dr3;                                                          //0x60
    ULONGLONG Dr6;                                                          //0x68
    ULONGLONG Dr7;                                                          //0x70
    ULONGLONG Rax;                                                          //0x78
    ULONGLONG Rcx;                                                          //0x80
    ULONGLONG Rdx;                                                          //0x88
    ULONGLONG Rbx;                                                          //0x90
    ULONGLONG Rsp;                                                          //0x98
    ULONGLONG Rbp;                                                          //0xa0
    ULONGLONG Rsi;                                                          //0xa8
    ULONGLONG Rdi;                                                          //0xb0
    ULONGLONG R8;                                                           //0xb8
    ULONGLONG R9;                                                           //0xc0
    ULONGLONG R10;                                                          //0xc8
    ULONGLONG R11;                                                          //0xd0
    ULONGLONG R12;                                                          //0xd8
    ULONGLONG R13;                                                          //0xe0
    ULONGLONG R14;                                                          //0xe8
    ULONGLONG R15;                                                          //0xf0
    ULONGLONG Rip;                                                          //0xf8
    union
    {
      struct _XSAVE_FORMAT FltSave;                                       //0x100
      struct
      {
        struct _M128A Header[2];                                        //0x100
        struct _M128A Legacy[8];                                        //0x120
        struct _M128A Xmm0;                                             //0x1a0
        struct _M128A Xmm1;                                             //0x1b0
        struct _M128A Xmm2;                                             //0x1c0
        struct _M128A Xmm3;                                             //0x1d0
        struct _M128A Xmm4;                                             //0x1e0
        struct _M128A Xmm5;                                             //0x1f0
        struct _M128A Xmm6;                                             //0x200
        struct _M128A Xmm7;                                             //0x210
        struct _M128A Xmm8;                                             //0x220
        struct _M128A Xmm9;                                             //0x230
        struct _M128A Xmm10;                                            //0x240
        struct _M128A Xmm11;                                            //0x250
        struct _M128A Xmm12;                                            //0x260
        struct _M128A Xmm13;                                            //0x270
        struct _M128A Xmm14;                                            //0x280
        struct _M128A Xmm15;                                            //0x290
      };
    };
    struct _M128A VectorRegister[26];                                       //0x300
    ULONGLONG VectorControl;                                                //0x4a0
    ULONGLONG DebugControl;                                                 //0x4a8
    ULONGLONG LastBranchToRip;                                              //0x4b0
    ULONGLONG LastBranchFromRip;                                            //0x4b8
    ULONGLONG LastExceptionToRip;                                           //0x4c0
    ULONGLONG LastExceptionFromRip;                                         //0x4c8
  };

  //0x1 bytes (sizeof)
  union _KWAIT_STATUS_REGISTER
  {
    UCHAR Flags;                                                            //0x0
    UCHAR State : 3;                                                          //0x0
    UCHAR Affinity : 1;                                                       //0x0
    UCHAR Priority : 1;                                                       //0x0
    UCHAR Apc : 1;                                                            //0x0
    UCHAR UserApc : 1;                                                        //0x0
    UCHAR Alert : 1;                                                          //0x0
  };

  //0x10 bytes (sizeof)
  struct _KLOCK_ENTRY_LOCK_STATE
  {
    union
    {
      struct
      {
        ULONGLONG CrossThreadReleasable : 1;                              //0x0
        ULONGLONG Busy : 1;                                               //0x0
        ULONGLONG Reserved : 61;                                          //0x0
        ULONGLONG InTree : 1;                                             //0x0
      };
      VOID* LockState;                                                    //0x0
    };
    union
    {
      VOID* SessionState;                                                 //0x8
      struct
      {
        ULONG SessionId;                                                //0x8
        ULONG SessionPad;                                               //0xc
      };
    };
  };

  //0x10 bytes (sizeof)
  struct _RTL_RB_TREE
  {
    struct _RTL_BALANCED_NODE* Root;                                        //0x0
    union
    {
      UCHAR Encoded : 1;                                                    //0x8
      struct _RTL_BALANCED_NODE* Min;                                     //0x8
    };
  };

  //0x4 bytes (sizeof)
  union _KLOCK_ENTRY_BOOST_BITMAP
  {
    ULONG AllFields;                                                        //0x0
    ULONG AllBoosts : 17;                                                     //0x0
    ULONG Reserved : 15;                                                      //0x0
    USHORT CpuBoostsBitmap : 15;                                              //0x0
    struct
    {
      USHORT IoBoost : 1;                                                   //0x0
      USHORT IoQoSBoost : 1;                                                    //0x2
      USHORT IoNormalPriorityWaiterCount : 8;                                   //0x2
    };
    USHORT IoQoSWaiterCount : 7;                                              //0x2
  };

  //0x60 bytes (sizeof)
  struct _KLOCK_ENTRY
  {
    union
    {
      struct _RTL_BALANCED_NODE TreeNode;                                 //0x0
      struct _SINGLE_LIST_ENTRY FreeListEntry;                            //0x0
    };
    union
    {
      ULONG EntryFlags;                                                   //0x18
      struct
      {
        UCHAR EntryOffset;                                              //0x18
        union
        {
          UCHAR ThreadLocalFlags;                                     //0x19
          struct
          {
            UCHAR WaitingBit : 1;                                     //0x19
            UCHAR Spare0 : 7;                                         //0x19
          };
        };
        union
        {
          UCHAR AcquiredByte;                                         //0x1a
          UCHAR AcquiredBit : 1;                                        //0x1a
        };
        union
        {
          UCHAR CrossThreadFlags;                                     //0x1b
          struct
          {
            UCHAR HeadNodeBit : 1;                                    //0x1b
            UCHAR IoPriorityBit : 1;                                  //0x1b
            UCHAR IoQoSWaiter : 1;                                    //0x1b
            UCHAR Spare1 : 5;                                         //0x1b
          };
        };
      };
      struct
      {
        ULONG StaticState : 8;                                            //0x18
        ULONG AllFlags : 24;                                              //0x18
      };
    };
    ULONG SpareFlags;                                                       //0x1c
    union
    {
      struct _KLOCK_ENTRY_LOCK_STATE LockState;                           //0x20
      VOID* volatile LockUnsafe;                                          //0x20
      struct
      {
        volatile UCHAR CrossThreadReleasableAndBusyByte;                //0x20
        UCHAR Reserved[6];                                              //0x21
        volatile UCHAR InTreeByte;                                      //0x27
        union
        {
          VOID* SessionState;                                         //0x28
          struct
          {
            ULONG SessionId;                                        //0x28
            ULONG SessionPad;                                       //0x2c
          };
        };
      };
    };
    union
    {
      struct
      {
        struct _RTL_RB_TREE OwnerTree;                                  //0x30
        struct _RTL_RB_TREE WaiterTree;                                 //0x40
      };
      CHAR CpuPriorityKey;                                                //0x30
    };
    ULONGLONG EntryLock;                                                    //0x50
    union _KLOCK_ENTRY_BOOST_BITMAP BoostBitmap;                            //0x58
    ULONG SparePad;                                                         //0x5c
  };

  //0x5f0 bytes (sizeof)
  struct _KTHREAD
  {
    struct _DISPATCHER_HEADER Header;                                       //0x0
    VOID* SListFaultAddress;                                                //0x18
    ULONGLONG QuantumTarget;                                                //0x20
    VOID* InitialStack;                                                     //0x28
    VOID* volatile StackLimit;                                              //0x30
    VOID* StackBase;                                                        //0x38
    ULONGLONG ThreadLock;                                                   //0x40
    volatile ULONGLONG CycleTime;                                           //0x48
    ULONG CurrentRunTime;                                                   //0x50
    ULONG ExpectedRunTime;                                                  //0x54
    VOID* KernelStack;                                                      //0x58
    struct _XSAVE_FORMAT* StateSaveArea;                                    //0x60
    struct _KSCHEDULING_GROUP* volatile SchedulingGroup;                    //0x68
    union _KWAIT_STATUS_REGISTER WaitRegister;                              //0x70
    volatile UCHAR Running;                                                 //0x71
    UCHAR Alerted[2];                                                       //0x72
    union
    {
      struct
      {
        ULONG AutoBoostActive : 1;                                        //0x74
        ULONG ReadyTransition : 1;                                        //0x74
        ULONG WaitNext : 1;                                               //0x74
        ULONG SystemAffinityActive : 1;                                   //0x74
        ULONG Alertable : 1;                                              //0x74
        ULONG UserStackWalkActive : 1;                                    //0x74
        ULONG ApcInterruptRequest : 1;                                    //0x74
        ULONG QuantumEndMigrate : 1;                                      //0x74
        ULONG UmsDirectedSwitchEnable : 1;                                //0x74
        ULONG TimerActive : 1;                                            //0x74
        ULONG SystemThread : 1;                                           //0x74
        ULONG ProcessDetachActive : 1;                                    //0x74
        ULONG CalloutActive : 1;                                          //0x74
        ULONG ScbReadyQueue : 1;                                          //0x74
        ULONG ApcQueueable : 1;                                           //0x74
        ULONG ReservedStackInUse : 1;                                     //0x74
        ULONG UmsPerformingSyscall : 1;                                   //0x74
        ULONG TimerSuspended : 1;                                         //0x74
        ULONG SuspendedWaitMode : 1;                                      //0x74
        ULONG SuspendSchedulerApcWait : 1;                                //0x74
        ULONG Reserved : 12;                                              //0x74
      };
      LONG MiscFlags;                                                     //0x74
    };
    union
    {
      struct
      {
        ULONG BamQosLevel : 2;                                            //0x78
        ULONG AutoAlignment : 1;                                          //0x78
        ULONG DisableBoost : 1;                                           //0x78
        ULONG AlertedByThreadId : 1;                                      //0x78
        ULONG QuantumDonation : 1;                                        //0x78
        ULONG EnableStackSwap : 1;                                        //0x78
        ULONG GuiThread : 1;                                              //0x78
        ULONG DisableQuantum : 1;                                         //0x78
        ULONG ChargeOnlySchedulingGroup : 1;                              //0x78
        ULONG DeferPreemption : 1;                                        //0x78
        ULONG QueueDeferPreemption : 1;                                   //0x78
        ULONG ForceDeferSchedule : 1;                                     //0x78
        ULONG SharedReadyQueueAffinity : 1;                               //0x78
        ULONG FreezeCount : 1;                                            //0x78
        ULONG TerminationApcRequest : 1;                                  //0x78
        ULONG AutoBoostEntriesExhausted : 1;                              //0x78
        ULONG KernelStackResident : 1;                                    //0x78
        ULONG TerminateRequestReason : 2;                                 //0x78
        ULONG ProcessStackCountDecremented : 1;                           //0x78
        ULONG RestrictedGuiThread : 1;                                    //0x78
        ULONG VpBackingThread : 1;                                        //0x78
        ULONG ThreadFlagsSpare : 1;                                       //0x78
        ULONG EtwStackTraceApcInserted : 8;                               //0x78
      };
      volatile LONG ThreadFlags;                                          //0x78
    };
    volatile UCHAR Tag;                                                     //0x7c
    UCHAR SystemHeteroCpuPolicy;                                            //0x7d
    UCHAR UserHeteroCpuPolicy : 7;                                            //0x7e
    UCHAR ExplicitSystemHeteroCpuPolicy : 1;                                  //0x7e
    UCHAR Spare0;                                                           //0x7f
    ULONG SystemCallNumber;                                                 //0x80
    ULONG ReadyTime;                                                        //0x84
    VOID* FirstArgument;                                                    //0x88
    struct _KTRAP_FRAME* TrapFrame;                                         //0x90
    union
    {
      struct _KAPC_STATE ApcState;                                        //0x98
      struct
      {
        UCHAR ApcStateFill[43];                                         //0x98
        CHAR Priority;                                                  //0xc3
        ULONG UserIdealProcessor;                                       //0xc4
      };
    };
    volatile LONGLONG WaitStatus;                                           //0xc8
    struct _KWAIT_BLOCK* WaitBlockList;                                     //0xd0
    union
    {
      struct _LIST_ENTRY WaitListEntry;                                   //0xd8
      struct _SINGLE_LIST_ENTRY SwapListEntry;                            //0xd8
    };
    struct _DISPATCHER_HEADER* volatile Queue;                              //0xe8
    VOID* Teb;                                                              //0xf0
    ULONGLONG RelativeTimerBias;                                            //0xf8
    struct _KTIMER Timer;                                                   //0x100
    union
    {
      struct _KWAIT_BLOCK WaitBlock[4];                                   //0x140
      struct
      {
        UCHAR WaitBlockFill4[20];                                       //0x140
        ULONG ContextSwitches;                                          //0x154
      };
      struct
      {
        UCHAR WaitBlockFill5[68];                                       //0x140
        volatile UCHAR State;                                           //0x184
        CHAR Spare13;                                                   //0x185
        UCHAR WaitIrql;                                                 //0x186
        CHAR WaitMode;                                                  //0x187
      };
      struct
      {
        UCHAR WaitBlockFill6[116];                                      //0x140
        ULONG WaitTime;                                                 //0x1b4
      };
      struct
      {
        UCHAR WaitBlockFill7[164];                                      //0x140
        union
        {
          struct
          {
            SHORT KernelApcDisable;                                 //0x1e4
            SHORT SpecialApcDisable;                                //0x1e6
          };
          ULONG CombinedApcDisable;                                   //0x1e4
        };
      };
      struct
      {
        UCHAR WaitBlockFill8[40];                                       //0x140
        struct _KTHREAD_COUNTERS* ThreadCounters;                       //0x168
      };
      struct
      {
        UCHAR WaitBlockFill9[88];                                       //0x140
        struct _XSTATE_SAVE* XStateSave;                                //0x198
      };
      struct
      {
        UCHAR WaitBlockFill10[136];                                     //0x140
        VOID* volatile Win32Thread;                                     //0x1c8
      };
      struct
      {
        UCHAR WaitBlockFill11[176];                                     //0x140
        struct _UMS_CONTROL_BLOCK* Ucb;                                 //0x1f0
        struct _KUMS_CONTEXT_HEADER* volatile Uch;                      //0x1f8
      };
    };
    VOID* Spare21;                                                          //0x200
    struct _LIST_ENTRY QueueListEntry;                                      //0x208
    union
    {
      volatile ULONG NextProcessor;                                       //0x218
      struct
      {
        ULONG NextProcessorNumber : 31;                                   //0x218
        ULONG SharedReadyQueue : 1;                                       //0x218
      };
    };
    LONG QueuePriority;                                                     //0x21c
    struct _KPROCESS* Process;                                              //0x220
    union
    {
      struct _GROUP_AFFINITY UserAffinity;                                //0x228
      struct
      {
        UCHAR UserAffinityFill[10];                                     //0x228
        CHAR PreviousMode;                                              //0x232
        CHAR BasePriority;                                              //0x233
        union
        {
          CHAR PriorityDecrement;                                     //0x234
          struct
          {
            UCHAR ForegroundBoost : 4;                                //0x234
            UCHAR UnusualBoost : 4;                                   //0x234
          };
        };
        UCHAR Preempted;                                                //0x235
        UCHAR AdjustReason;                                             //0x236
        CHAR AdjustIncrement;                                           //0x237
      };
    };
    ULONGLONG AffinityVersion;                                              //0x238
    union
    {
      struct _GROUP_AFFINITY Affinity;                                    //0x240
      struct
      {
        UCHAR AffinityFill[10];                                         //0x240
        UCHAR ApcStateIndex;                                            //0x24a
        UCHAR WaitBlockCount;                                           //0x24b
        ULONG IdealProcessor;                                           //0x24c
      };
    };
    ULONGLONG NpxState;                                                     //0x250
    union
    {
      struct _KAPC_STATE SavedApcState;                                   //0x258
      struct
      {
        UCHAR SavedApcStateFill[43];                                    //0x258
        UCHAR WaitReason;                                               //0x283
        CHAR SuspendCount;                                              //0x284
        CHAR Saturation;                                                //0x285
        USHORT SListFaultCount;                                         //0x286
      };
    };
    union
    {
      struct _KAPC SchedulerApc;                                          //0x288
      struct
      {
        UCHAR SchedulerApcFill0[1];                                     //0x288
        UCHAR ResourceIndex;                                            //0x289
      };
      struct
      {
        UCHAR SchedulerApcFill1[3];                                     //0x288
        UCHAR QuantumReset;                                             //0x28b
      };
      struct
      {
        UCHAR SchedulerApcFill2[4];                                     //0x288
        ULONG KernelTime;                                               //0x28c
      };
      struct
      {
        UCHAR SchedulerApcFill3[64];                                    //0x288
        struct _KPRCB* volatile WaitPrcb;                               //0x2c8
      };
      struct
      {
        UCHAR SchedulerApcFill4[72];                                    //0x288
        VOID* LegoData;                                                 //0x2d0
      };
      struct
      {
        UCHAR SchedulerApcFill5[83];                                    //0x288
        UCHAR CallbackNestingLevel;                                     //0x2db
        ULONG UserTime;                                                 //0x2dc
      };
    };
    struct _KEVENT SuspendEvent;                                            //0x2e0
    struct _LIST_ENTRY ThreadListEntry;                                     //0x2f8
    struct _LIST_ENTRY MutantListHead;                                      //0x308
    UCHAR AbEntrySummary;                                                   //0x318
    UCHAR AbWaitEntryCount;                                                 //0x319
    UCHAR AbAllocationRegionCount;                                          //0x31a
    UCHAR Spare20;                                                          //0x31b
    ULONG SecureThreadCookie;                                               //0x31c
    struct _KLOCK_ENTRY LockEntries[6];                                     //0x320
    struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;                         //0x560
    struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;                            //0x568
    UCHAR PriorityFloorCounts[16];                                          //0x570
    ULONG PriorityFloorSummary;                                             //0x580
    volatile LONG AbCompletedIoBoostCount;                                  //0x584
    volatile LONG AbCompletedIoQoSBoostCount;                               //0x588
    volatile SHORT KeReferenceCount;                                        //0x58c
    UCHAR AbOrphanedEntrySummary;                                           //0x58e
    UCHAR AbOwnedEntryCount;                                                //0x58f
    ULONG ForegroundLossTime;                                               //0x590
    union
    {
      struct _LIST_ENTRY GlobalForegroundListEntry;                       //0x598
      struct
      {
        struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;          //0x598
        ULONGLONG InGlobalForegroundList;                               //0x5a0
      };
    };
    LONGLONG ReadOperationCount;                                            //0x5a8
    LONGLONG WriteOperationCount;                                           //0x5b0
    LONGLONG OtherOperationCount;                                           //0x5b8
    LONGLONG ReadTransferCount;                                             //0x5c0
    LONGLONG WriteTransferCount;                                            //0x5c8
    LONGLONG OtherTransferCount;                                            //0x5d0
    struct _KSCB* QueuedScb;                                                //0x5d8
    volatile ULONG ThreadTimerDelay;                                        //0x5e0
    union
    {
      volatile LONG ThreadFlags2;                                         //0x5e4
      struct
      {
        ULONG PpmPolicy : 2;                                              //0x5e4
        ULONG ThreadFlags2Reserved : 30;                                  //0x5e4
      };
    };
    VOID* SchedulerAssist;                                                  //0x5e8
  };

  //0x8 bytes (sizeof)
  union _PS_CLIENT_SECURITY_CONTEXT
  {
    ULONGLONG ImpersonationData;                                            //0x0
    VOID* ImpersonationToken;                                               //0x0
    ULONGLONG ImpersonationLevel : 2;                                         //0x0
    ULONGLONG EffectiveOnly : 1;                                              //0x0
  };


  //0x18 bytes (sizeof)
  struct _PS_PROPERTY_SET
  {
    struct _LIST_ENTRY ListHead;                                            //0x0
    ULONGLONG Lock;                                                         //0x10
  };

  //0x810 bytes (sizeof)
  struct _ETHREAD
  {
    struct _KTHREAD Tcb;                                                    //0x0
    union _LARGE_INTEGER CreateTime;                                        //0x5f0
    union
    {
      union _LARGE_INTEGER ExitTime;                                      //0x5f8
      struct _LIST_ENTRY KeyedWaitChain;                                  //0x5f8
    };
    union
    {
      struct _LIST_ENTRY PostBlockList;                                   //0x608
      struct
      {
        VOID* ForwardLinkShadow;                                        //0x608
        VOID* StartAddress;                                             //0x610
      };
    };
    union
    {
      struct _TERMINATION_PORT* TerminationPort;                          //0x618
      struct _ETHREAD* ReaperLink;                                        //0x618
      VOID* KeyedWaitValue;                                               //0x618
    };
    ULONGLONG ActiveTimerListLock;                                          //0x620
    struct _LIST_ENTRY ActiveTimerListHead;                                 //0x628
    struct _CLIENT_ID Cid;                                                  //0x638
    union
    {
      struct _KSEMAPHORE KeyedWaitSemaphore;                              //0x648
      struct _KSEMAPHORE AlpcWaitSemaphore;                               //0x648
    };
    union _PS_CLIENT_SECURITY_CONTEXT ClientSecurity;                       //0x668
    struct _LIST_ENTRY IrpList;                                             //0x670
    ULONGLONG TopLevelIrp;                                                  //0x680
    struct _DEVICE_OBJECT* DeviceToVerify;                                  //0x688
    VOID* Win32StartAddress;                                                //0x690
    VOID* ChargeOnlySession;                                                //0x698
    VOID* LegacyPowerObject;                                                //0x6a0
    struct _LIST_ENTRY ThreadListEntry;                                     //0x6a8
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x6b8
    struct _EX_PUSH_LOCK ThreadLock;                                        //0x6c0
    ULONG ReadClusterSize;                                                  //0x6c8
    volatile LONG MmLockOrdering;                                           //0x6cc
    union
    {
      ULONG CrossThreadFlags;                                             //0x6d0
      struct
      {
        ULONG Terminated : 1;                                             //0x6d0
        ULONG ThreadInserted : 1;                                         //0x6d0
        ULONG HideFromDebugger : 1;                                       //0x6d0
        ULONG ActiveImpersonationInfo : 1;                                //0x6d0
        ULONG HardErrorsAreDisabled : 1;                                  //0x6d0
        ULONG BreakOnTermination : 1;                                     //0x6d0
        ULONG SkipCreationMsg : 1;                                        //0x6d0
        ULONG SkipTerminationMsg : 1;                                     //0x6d0
        ULONG CopyTokenOnOpen : 1;                                        //0x6d0
        ULONG ThreadIoPriority : 3;                                       //0x6d0
        ULONG ThreadPagePriority : 3;                                     //0x6d0
        ULONG RundownFail : 1;                                            //0x6d0
        ULONG UmsForceQueueTermination : 1;                               //0x6d0
        ULONG IndirectCpuSets : 1;                                        //0x6d0
        ULONG DisableDynamicCodeOptOut : 1;                               //0x6d0
        ULONG ExplicitCaseSensitivity : 1;                                //0x6d0
        ULONG PicoNotifyExit : 1;                                         //0x6d0
        ULONG DbgWerUserReportActive : 1;                                 //0x6d0
        ULONG ForcedSelfTrimActive : 1;                                   //0x6d0
        ULONG SamplingCoverage : 1;                                       //0x6d0
        ULONG ReservedCrossThreadFlags : 8;                               //0x6d0
      };
    };
    union
    {
      ULONG SameThreadPassiveFlags;                                       //0x6d4
      struct
      {
        ULONG ActiveExWorker : 1;                                         //0x6d4
        ULONG MemoryMaker : 1;                                            //0x6d4
        ULONG StoreLockThread : 2;                                        //0x6d4
        ULONG ClonedThread : 1;                                           //0x6d4
        ULONG KeyedEventInUse : 1;                                        //0x6d4
        ULONG SelfTerminate : 1;                                          //0x6d4
        ULONG RespectIoPriority : 1;                                      //0x6d4
        ULONG ActivePageLists : 1;                                        //0x6d4
        ULONG SecureContext : 1;                                          //0x6d4
        ULONG ZeroPageThread : 1;                                         //0x6d4
        ULONG WorkloadClass : 1;                                          //0x6d4
        ULONG ReservedSameThreadPassiveFlags : 20;                        //0x6d4
      };
    };
    union
    {
      ULONG SameThreadApcFlags;                                           //0x6d8
      struct
      {
        UCHAR OwnsProcessAddressSpaceExclusive : 1;                       //0x6d8
        UCHAR OwnsProcessAddressSpaceShared : 1;                          //0x6d8
        UCHAR HardFaultBehavior : 1;                                      //0x6d8
        volatile UCHAR StartAddressInvalid : 1;                           //0x6d8
        UCHAR EtwCalloutActive : 1;                                       //0x6d8
        UCHAR SuppressSymbolLoad : 1;                                     //0x6d8
        UCHAR Prefetching : 1;                                            //0x6d8
        UCHAR OwnsVadExclusive : 1;                                       //0x6d8
        UCHAR SystemPagePriorityActive : 1;                               //0x6d9
        UCHAR SystemPagePriority : 3;                                     //0x6d9
        UCHAR AllowWritesToExecutableMemory : 1;                          //0x6d9
        UCHAR OwnsVadShared : 1;                                          //0x6d9
      };
    };
    UCHAR CacheManagerActive;                                               //0x6dc
    UCHAR DisablePageFaultClustering;                                       //0x6dd
    UCHAR ActiveFaultCount;                                                 //0x6de
    UCHAR LockOrderState;                                                   //0x6df
    ULONGLONG AlpcMessageId;                                                //0x6e0
    union
    {
      VOID* AlpcMessage;                                                  //0x6e8
      ULONG AlpcReceiveAttributeSet;                                      //0x6e8
    };
    struct _LIST_ENTRY AlpcWaitListEntry;                                   //0x6f0
    LONG ExitStatus;                                                        //0x700
    ULONG CacheManagerCount;                                                //0x704
    ULONG IoBoostCount;                                                     //0x708
    ULONG IoQoSBoostCount;                                                  //0x70c
    ULONG IoQoSThrottleCount;                                               //0x710
    ULONG KernelStackReference;                                             //0x714
    struct _LIST_ENTRY BoostList;                                           //0x718
    struct _LIST_ENTRY DeboostList;                                         //0x728
    ULONGLONG BoostListLock;                                                //0x738
    ULONGLONG IrpListLock;                                                  //0x740
    VOID* ReservedForSynchTracking;                                         //0x748
    struct _SINGLE_LIST_ENTRY CmCallbackListHead;                           //0x750
    struct _GUID* ActivityId;                                               //0x758
    struct _SINGLE_LIST_ENTRY SeLearningModeListHead;                       //0x760
    VOID* VerifierContext;                                                  //0x768
    VOID* AdjustedClientToken;                                              //0x770
    VOID* WorkOnBehalfThread;                                               //0x778
    struct _PS_PROPERTY_SET PropertySet;                                    //0x780
    VOID* PicoContext;                                                      //0x798
    ULONGLONG UserFsBase;                                                   //0x7a0
    ULONGLONG UserGsBase;                                                   //0x7a8
    struct _THREAD_ENERGY_VALUES* EnergyValues;                             //0x7b0
    VOID* CmDbgInfo;                                                        //0x7b8
    union
    {
      ULONGLONG SelectedCpuSets;                                          //0x7c0
      ULONGLONG* SelectedCpuSetsIndirect;                                 //0x7c0
    };
    struct _EJOB* Silo;                                                     //0x7c8
    struct _UNICODE_STRING* ThreadName;                                     //0x7d0
    struct _CONTEXT* SetContextState;                                       //0x7d8
    ULONG LastExpectedRunTime;                                              //0x7e0
    ULONG HeapData;                                                         //0x7e4
    struct _LIST_ENTRY OwnerEntryListHead;                                  //0x7e8
    ULONGLONG DisownedOwnerEntryListLock;                                   //0x7f8
    struct _LIST_ENTRY DisownedOwnerEntryListHead;                          //0x800
  };

  static_assert(sizeof(_ETHREAD) == 0x810, "!=");
}
#endif // !NTWIN101809X64_H
