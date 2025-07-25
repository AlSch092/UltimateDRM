#pragma once
#include <Windows.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
    ThreadTimes, // q: KERNEL_USER_TIMES
    ThreadPriority, // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
    ThreadBasePriority, // s: KPRIORITY
    ThreadAffinityMask, // s: KAFFINITY
    ThreadImpersonationToken, // s: HANDLE
    ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
    ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
    ThreadEventPair, // Obsolete
    ThreadQuerySetWin32StartAddress, // qs: PVOID (requires THREAD_Set_LIMITED_INFORMATION)
    ThreadZeroTlsCell, // s: ULONG // TlsIndex // 10
    ThreadPerformanceCount, // q: LARGE_INTEGER
    ThreadAmILastThread, // q: ULONG
    ThreadIdealProcessor, // s: ULONG
    ThreadPriorityBoost, // qs: ULONG
    ThreadSetTlsArrayAddress, // s: ULONG_PTR
    ThreadIsIoPending, // q: ULONG
    ThreadHideFromDebugger, // q: BOOLEAN; s: void
    ThreadBreakOnTermination, // qs: ULONG
    ThreadSwitchLegacyState, // s: void // NtCurrentThread // NPX/FPU
    ThreadIsTerminated, // q: ULONG // 20
    ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
    ThreadIoPriority, // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
    ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION (requires THREAD_QUERY_LIMITED_INFORMATION)
    ThreadPagePriority, // qs: PAGE_PRIORITY_INFORMATION
    ThreadActualBasePriority, // s: LONG (requires SeIncreaseBasePriorityPrivilege)
    ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
    ThreadCSwitchMon, // Obsolete
    ThreadCSwitchPmu, // Obsolete
    ThreadWow64Context, // qs: WOW64_CONTEXT, ARM_NT_CONTEXT since 20H1
    ThreadGroupInformation, // qs: GROUP_AFFINITY // 30
    ThreadUmsInformation, // q: THREAD_UMS_INFORMATION // Obsolete
    ThreadCounterProfiling, // q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
    ThreadIdealProcessorEx, // qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
    ThreadCpuAccountingInformation, // q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
    ThreadSuspendCount, // q: ULONG // since WINBLUE
    ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
    ThreadContainerId, // q: GUID
    ThreadNameInformation, // qs: THREAD_NAME_INFORMATION (requires THREAD_SET_LIMITED_INFORMATION)
    ThreadSelectedCpuSets, // q: ULONG[]
    ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
    ThreadActualGroupAffinity, // q: GROUP_AFFINITY // since THRESHOLD2
    ThreadDynamicCodePolicyInfo, // q: ULONG; s: ULONG (NtCurrentThread)
    ThreadExplicitCaseSensitivity, // qs: ULONG; s: 0 disables, otherwise enables // (requires SeDebugPrivilege and PsProtectedSignerAntimalware)
    ThreadWorkOnBehalfTicket, // ALPC_WORK_ON_BEHALF_TICKET // RTL_WORK_ON_BEHALF_TICKET_EX // NtCurrentThread
    ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ThreadDbgkWerReportActive, // s: ULONG; s: 0 disables, otherwise enables
    ThreadAttachContainer, // s: HANDLE (job object) // NtCurrentThread
    ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ThreadPowerThrottlingState, // qs: POWER_THROTTLING_THREAD_STATE // since REDSTONE3 (set), WIN11 22H2 (query)
    ThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
    ThreadCreateStateChange, // since WIN11
    ThreadApplyStateChange,
    ThreadStrongerBadHandleChecks, // s: ULONG // NtCurrentThread // since 22H1
    ThreadEffectiveIoPriority, // q: IO_PRIORITY_HINT
    ThreadEffectivePagePriority, // q: ULONG
    ThreadUpdateLockOwnership, // THREAD_LOCK_OWNERSHIP // since 24H2
    ThreadSchedulerSharedDataSlot, // SCHEDULER_SHARED_DATA_SLOT_INFORMATION
    ThreadTebInformationAtomic, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_QUERY_INFORMATION)
    ThreadIndexInformation, // THREAD_INDEX_INFORMATION
    MaxThreadInfoClass
} THREADINFOCLASS;

typedef struct _KSYSTEM_TIME
{
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, * PKSYSTEM_TIME;

typedef enum _NT_PRODUCT_TYPE
{
    NtProductWinNt = 1,
    NtProductLanManNt = 2,
    NtProductServer = 3
} NT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
    StandardDesign = 0,
    NEC98x86 = 1,
    EndAlternatives = 2
} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA  //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data
{
    ULONG                         TickCountLowDeprecated;
    ULONG                         TickCountMultiplier;
    KSYSTEM_TIME                  InterruptTime;
    KSYSTEM_TIME                  SystemTime;
    KSYSTEM_TIME                  TimeZoneBias;
    USHORT                        ImageNumberLow;
    USHORT                        ImageNumberHigh;
    WCHAR                         NtSystemRoot[260];
    ULONG                         MaxStackTraceDepth;
    ULONG                         CryptoExponent;
    ULONG                         TimeZoneId;
    ULONG                         LargePageMinimum;
    ULONG                         AitSamplingValue;
    ULONG                         AppCompatFlag;
    ULONGLONG                     RNGSeedVersion;
    ULONG                         GlobalValidationRunlevel;
    LONG                          TimeZoneBiasStamp;
    ULONG                         NtBuildNumber;
    NT_PRODUCT_TYPE               NtProductType;
    BOOLEAN                       ProductTypeIsValid;
    BOOLEAN                       Reserved0[1];
    USHORT                        NativeProcessorArchitecture;
    ULONG                         NtMajorVersion;
    ULONG                         NtMinorVersion;
    BOOLEAN                       ProcessorFeatures[64];
    ULONG                         Reserved1;
    ULONG                         Reserved3;
    ULONG                         TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    ULONG                         BootId;
    LARGE_INTEGER                 SystemExpirationDate;
    ULONG                         SuiteMask;
    BOOLEAN                       KdDebuggerEnabled;
    union {
        UCHAR MitigationPolicies;
        struct {
            UCHAR NXSupportPolicy : 2;
            UCHAR SEHValidationPolicy : 2;
            UCHAR CurDirDevicesSkippedForDlls : 2;
            UCHAR Reserved : 2;
        };
    };
    USHORT                        CyclesPerYield;
    ULONG                         ActiveConsoleId;
    ULONG                         DismountCount;
    ULONG                         ComPlusPackage;
    ULONG                         LastSystemRITEventTickCount;
    ULONG                         NumberOfPhysicalPages;
    BOOLEAN                       SafeBootMode;
    union {
        UCHAR VirtualizationFlags;
        struct {
            UCHAR ArchStartedInEl2 : 1;
            UCHAR QcSlIsSupported : 1;
        };
    };
    UCHAR                         Reserved12[2];
    union
    {
        ULONG SharedDataFlags;
        struct
        {
            ULONG DbgErrorPortPresent : 1;
            ULONG DbgElevationEnabled : 1;
            ULONG DbgVirtEnabled : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgLkgEnabled : 1;
            ULONG DbgDynProcessorEnabled : 1;
            ULONG DbgConsoleBrokerEnabled : 1;
            ULONG DbgSecureBootEnabled : 1;
            ULONG DbgMultiSessionSku : 1;
            ULONG DbgMultiUsersInSessionSku : 1;
            ULONG DbgStateSeparationEnabled : 1;
            ULONG SpareBits : 21;
        } Dbg;
    } DbgUnion;
    ULONG                         DataFlagsPad[1];
    ULONGLONG                     TestRetInstruction;
    LONGLONG                      QpcFrequency;
    ULONG                         SystemCall;
    ULONG                         Reserved2;
    ULONGLONG                     FullNumberOfPhysicalPages;
    ULONGLONG                     SystemCallPad[1];
    union
    {
        KSYSTEM_TIME TickCount;
        ULONG64      TickCountQuad;
        struct
        {
            ULONG ReservedTickCountOverlay[3];
            ULONG TickCountPad[1];
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME3;
    ULONG                         Cookie;
    ULONG                         CookiePad[1];
    LONGLONG                      ConsoleSessionForegroundProcessId;
    ULONGLONG                     TimeUpdateLock;
    ULONGLONG                     BaselineSystemTimeQpc;
    ULONGLONG                     BaselineInterruptTimeQpc;
    ULONGLONG                     QpcSystemTimeIncrement;
    ULONGLONG                     QpcInterruptTimeIncrement;
    UCHAR                         QpcSystemTimeIncrementShift;
    UCHAR                         QpcInterruptTimeIncrementShift;
    USHORT                        UnparkedProcessorCount;
    ULONG                         EnclaveFeatureMask[4];
    ULONG                         TelemetryCoverageRound;
    USHORT                        UserModeGlobalLogger[16];
    ULONG                         ImageFileExecutionOptions;
    ULONG                         LangGenerationCount;
    ULONGLONG                     Reserved4;
    ULONGLONG                     InterruptTimeBias;
    ULONGLONG                     QpcBias;
    ULONG                         ActiveProcessorCount;
    UCHAR                         ActiveGroupCount;
    UCHAR                         Reserved9;
    union
    {
        USHORT QpcData;
        struct
        {
            UCHAR QpcBypassEnabled;
            UCHAR QpcReserved;
        };
    };
    LARGE_INTEGER                 TimeZoneBiasEffectiveStart;
    LARGE_INTEGER                 TimeZoneBiasEffectiveEnd;
    XSTATE_CONFIGURATION          XState;
    KSYSTEM_TIME                  FeatureConfigurationChangeStamp;
    ULONG                         Spare;
    ULONG64                       UserPointerAuthMask;
    XSTATE_CONFIGURATION          XStateArm64;
    ULONG                         Reserved10[210];
} KUSER_SHARED_DATA, * PKUSER_SHARED_DATA;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct MY_PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    PVOID ShutdownThreadId;
} MY_PEB_LDR_DATA, * MY_PPEB_LDR_DATA;

typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticLoad,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonEnclavePrimary,
    LoadReasonEnclaveDependency,
    LoadReasonPatchImage,
    LoadReasonUnknownReason = -1
} LDR_DLL_LOAD_REASON;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    // Windows 10 specific fields
    PVOID LoadedImports;
    PVOID EntryPointActivationContext; // Since Windows 10 1607 (Anniversary Update)
    PVOID PatchInformation;
    LDR_DLL_LOAD_REASON LoadReason;
} MY_LDR_DATA_TABLE_ENTRY, * MY_PLDR_DATA_TABLE_ENTRY;

typedef struct _MYPEB
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR Spare;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    MY_PEB_LDR_DATA* Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID FastPebLockRoutine;
    PVOID FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID* KernelCallbackTable;
    PVOID EventLogSection;
    PVOID EventLog;
    PVOID FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[0x2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    UCHAR Spare2[0x4];
    ULARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID** ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper; //PPS_POST_PREOCESS_INIT_ROUTINE?
    PVOID GdiDCAttributeList;
    PVOID LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    ULONG OSBuildNumber;
    ULONG OSPlatformId;
    ULONG ImageSubSystem;
    ULONG ImageSubSystemMajorVersion;
    ULONG ImageSubSystemMinorVersion;
    ULONG GdiHandleBuffer[0x22];
    PVOID ProcessWindowStation;
} MYPEB, * PMYPEB;


#ifndef _NTDEF_
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
#endif

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_INVALID_PAGE_PROTECTION   ((NTSTATUS)0xC0000045L)
#define STATUS_PROCEDURE_NOT_FOUND       ((NTSTATUS)0xC000007AL)

#define SEC_NO_CHANGE 0x00400000

#define PAGE_SIZE 0x1000
#define POINTER_IS_ALIGNED(Pointer, Alignment) \
    (((((ULONG_PTR)(Pointer)) & (((Alignment)-1))) == 0) ? TRUE : FALSE)

#define NtCurrentProcess()  ((HANDLE)(LONG_PTR)-1)

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;


EXTERN_C NTSTATUS NTAPI NtCreateSection(
    _Out_    PHANDLE            SectionHandle,
    _In_     ACCESS_MASK        DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER     MaximumSize,
    _In_     ULONG              SectionPageProtection,
    _In_     ULONG              AllocationAttributes,
    _In_opt_ HANDLE             FileHandle
);

EXTERN_C NTSTATUS NTAPI NtMapViewOfSection(
    _In_        HANDLE          SectionHandle,
    _In_        HANDLE          ProcessHandle,
    _Inout_     PVOID * BaseAddress,
    _In_        ULONG_PTR       ZeroBits,
    _In_        SIZE_T          CommitSize,
    _Inout_opt_ PLARGE_INTEGER  SectionOffset,
    _Inout_     PSIZE_T         ViewSize,
    _In_        SECTION_INHERIT InheritDisposition,
    _In_        ULONG           AllocationType,
    _In_        ULONG           Win32Protect
);

EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(_In_        HANDLE  ProcessHandle, _In_opt_    PVOID   BaseAddress);
EXTERN_C NTSTATUS NTAPI NtClose(_In_ HANDLE Handle);
EXTERN_C PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(_In_ PVOID BaseAddress);