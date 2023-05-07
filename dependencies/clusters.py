track_process = ["PsLookupProcessByProcessId","PsGetCurrentProcess","ZwQuerySystemInformation","GetLocationOfProcessName","ZwQueryObject","ZwQueryInformationThread","ZwAreMappedFilesTheSame", "ZwGetContextThread","ZwTestAlert","IoGetCurrentProcess","PsLookupThreadByThreadId","ObQueryNameString","PsLookupProcessThreadByCid"]

track_file = ["ZwQueryFullAttributesFile","ZwQueryAttributesFile","ZwQueryInformationFile","ZwQueryDirectoryFile","CcSetLogHandleForFileEx"]

write = ["VirtualProtect"]


notify = ["IoRegisterFsRegistrationChange","ExNotifyCallback","ExCreateCallback","KiUserCallbackDispatcher","ExRegisterCallback","ExCreateCallback", "IoRegisterShutdownNotification","PsSetCreateProcessNotifyRoutine"," PsSetCreateThreadNotifyRoutine","CmRegisterCallbackEx","CmRegisterCallback","ZwRegisterThreadTerminatePort","ZwNotifyChangeDirectoryFile","ZwNotifyChangeKey" , "ZwNotifyChangeMultipleKeys","ZwPrivilegeObjectAuditAlarm","ZwPrivilegedServiceAuditAlarm","ZwAccessCheckAndAuditAlarm","ZwAccessCheckByTypeAndAuditAlarm", "KeRegisterNmiCallback","CcGetDirtyPages","CcSetDirtyPinnedData"]

#registery = [""]



multi_processor_cluster = ["KeNumberProcessors","KeSetAffinityThread","KeQueryActiveProcessors","KeGetProcessorNumberFromIndex","KeGetProcessorIndexFromNumber","KeQueryActiveProcessorCountEx","KeQueryMaximumProcessorCountEx", "KeQueryMaximumProcessorCount"]

system_reconaissance = ["PsGetVersion","RtlGetVersion","ZwQuerySystemEnvironmentValue", "ZwQuerySecurityObject","ZwPrivilegeCheck","ZwAccessCheck","ZwAccessCheckByType","ZwAccessCheckByTypeResultList", "ZwAccessCheckByTypeResultListAndAuditAlarm","ZwAccessCheckByTypeResultListAndAuditAlarmByHandle","ZwOpenObjectAuditAlarm","ZwQueryInstallUILanguage","RtlInitializeGenericTableAvl", "MmSystemRangeStart","MmHighestUserAddress","IoIsWdmVersionAvailable","NtBuildNumber"]



attache_device = ["IoEnumerateDeviceObjectList","IoGetDeviceObjectPointer","IoAttachDevice","IoAttachDeviceToDeviceStackSafe","IoAttachDeviceToDeviceStack","IoAttachDeviceByPointer"]


inject1 = ["KeAttachProcess","KeStackAttachProcess","ZwAllocateVirtualMemory","ZwWriteVirtualMemory","ZwQueryVirtualMemory","ZwFlushVirtualMemory","ZwSuspendThread", "ZwSetContextThread","ZwImpersonateThread","ZwAssignProcessToJobObject","KeDetachProcess"]

inject_section = ["ZwMapViewOfSection"]

inject_fs = ["ZwSetEaFile","ZwQueryEaFile"]


SSDT = ["KeServiceDescriptorTable","KeAddSystemServiceTable","KeServiceDescriptorTable"]

hook = ["RtlLookupElementGenericTable","RtlLookupElementGenericTableAvl","RtlIsGenericTableEmptyAvl","RtlNumberGenericTableElementsAvl","RtlDeleteElementGenericTableAvl"]

DKOM_cluster = [ "PsActiveProcessHead","PsLoadedModuleList"," PsLoadedModuleResource","ExCreateHandleTable","ExDupHandleTable","ExSweepHandleTable","ExDestroyHandleTable","ExChangeHandle","ExSnapShotHandleTables","ExfInterlockedInsertTailList" , "ExfInterlockedRemoveHeadList","IoGetDeviceObjectPointer"]

boot = ["IoRegisterBootDriverReinitialization","IoRegisterBootDriverCallback","IoUnRegisterBootDriverCallback","Ke386CallBios"]


filter_cluster = ["FltLoadFilter","IoRegisterDriverReinitialization","IoSkipCurrentIrpStackLocation","IoEnumerateDeviceObjectList","IoSetCompletionRoutine"]

protection = ["ZwLockVirtualMemory","ZwProtectVirtualMemory","ZwLockFile"]

system_manipul = ["ZwSetSecurityObject"]

kernel_communication = ["ZwLoadDriver","FltLoadFilter","KeInitializeApc","MmLoadSystemImage","MmLoadAndLockSystemImage","ZwSetSystemInformation","ZwSetInformationObject","ZwSetInformationProcess","ZwSetInformationJobObject"]

user_communication = ["IoCreateSymbolicLink","IoRegisterDeviceInterface","IoGetDeviceInterfaces","ZwCreateSymbolicLinkObject","ZwOpenSymbolicLinkObject","ZwQuerySymbolicLinkObject","ZwLockVirtualMemory","ZwReadVirtualMemory", "ZwW32Call","IoGetDeviceInterfaces"]

APC = ["KeInitializeApc","KeInsertQueueApc"]

pipe = ["ZwCreateNamedPipeFile","ZwCreateMailslotFile"]


awaken = ["ZwAlertThread","ZwAlertResumeThread","ZwSetEvent","ZwCreateEvent","ZwPulseEvent","ZwResetEvent","ZwCreateEventPair"]

synchronize = ["KeSynchronizeExecution","WaitForSingleObject","WaitForMultipleObjects","ZwCreateTimer","ZwSetTimer","ZwWaitLowEventPair","ZwWaitHighEventPair","ZwSetLowWaitHighThread","KeInitializeTimer" ,"KeWaitForMutexObject"]
 
exclusion = ["ZwCreateSemaphore","ZwQuerySemaphore","ZwOpenSemaphore","ZwCreateMutant","ZwQueryMutant","KeEnterGuardedRegion","KeAcquireGuardedMutexUnsafe","KeAcquireGuardedMutex", "KeAcquireInStackQueuedSpinLockAtDpcLevel","KeAcquireInStackQueuedSpinLockForDpc","KeAcquireSpinLock","KeAcquireInStackQueuedSpinLock","KeTryToAcquireSpinLockAtDpcLevel", "KeInitializeMutex","ExInitializeFastMutex","KeInitializeSpinLock","KeInsertByKeyDeviceQueue","KeEnterCriticalRegion","KeAcquireSpinLockRaiseToSynch","KfAcquireSpinLock", "IoAcquireCancelSpinLock","KeReadStateSemaphore","ExAcquireSharedStarveExclusive","ExAcquireResourceExclusiveLite","ExTryToAcquireFastMutex"]




MDL = ["MmBuildMdlForNonPagedPool","MmMapLockedPagesSpecifyCache"," MmMapLockedPages","CcPrepareMdlWrite","CcMdlWriteComplete"]

suspect = ["ZwSystemDebugControl","RtlQueryProcessDebugInformation","ZwCancelIoFile","ZwFlushInstructionCache","IofCompleteRequest","MmSystemRangeStart","IoGetTopLevelIrp"]


security = ["RtlAbsoluteToSelfRelativeSD","SeExports","RtlGetOwnerSecurityDescriptor","RtlGetGroupSecurityDescriptor","RtlAbsoluteToSelfRelativeSD","RtlAddAccessAllowedAceEx","RtlAddAce","RtlGetSaclSecurityDescriptor","ZwSetSecurityObject" , "ExAcquireRundownProtectionEx","ZwSetSecurityObject","SeCreateTokenPrivilege","SeAssignPrimaryTokenPrivilege","SeLockMemoryPrivilege","SeIncreaseQuotaPrivilege",
"SeUnsolicitedInputPrivilege","SeMachineAccountPrivilege","SeTcbPrivilege","SeSecurityPrivilege","SeTakeOwnershipPrivilege","SeLoadDriverPrivilege",
"SeSystemProfilePrivilege","SeSystemtimePrivilege","SeProfileSingleProcessPrivilege","SeIncreaseBasePriorityPrivilege","SeCreatePagefilePrivilege","SeCreatePermanentPrivilege",
"SeBackupPrivilege","SeRestorePrivilege","SeShutdownPrivilege","SeDebugPrivilege","SeAuditPrivilege","SeSystemEnvironmentPrivilege","SeChangeNotifyPrivilege","SeRemoteShutdownPrivilege"
,"SeCaptureSecurityDescriptor","RtlSetDaclSecurityDescriptor","SeTokenIsAdmin"]


overwrite = ["MmMapIoSpace","memset","RtlCopyMemory","RtlCopyBytes","MmUnMapIoSpace"]

dynamic_load = ["MmGetSystemRoutineAddress","MmLoadSystemImage","MmLoadAndLockSystemImage","IofCallDriver"]

random = ["keTickCount","RtlRandom"]

self_check = ["RtlHashUnicodeString","ZwQueryDirectoryObject","ZwNotifyChangeDirectoryFile","ZwQueryVolumeInformationFile"]

anti_analysis = ["KdDebuggerEnabled,InitSafeBootMode","ZwQueryPerformanceCounter","ZwQuerySystemTime","ZwGetTickCount","KdDebuggerEnabled","KdDisableDebugger"]


allocat = ["ExAllocatePoolWithQuotaTag","ExAllocatePoolWithTagPriority","NdisAllocateMemory","NdisAllocateMemoryWithTag",
"MmAllocateNonCachedMemory","ExAllocatePoolWithTag","ExAllocatePool","NdisMAllocateSharedMemory","NdisMAllocateSharedMemoryAsyncEx","ZwAllocateVirtualMemory","ZwAllocateVirtualMemory" , "RtlAllocateHeap","MmAllocateContiguousMemory"]

dis_allocat = ["MmFreeNonCachedMemory","ExFreePool","ExFreePoolWithTag","ZwFreeVirtualMemory","MmFreeContiguousMemory"]


str = ["RtlInitString","RtlInitAnsiString","RtlInitUnicodeString","RtlAnsiStringToUnicodeSize","RtlAnsiStringToUnicodeString","RtlUnicodeStringToAnsiString","RtlFreeAnsiString", "RtlAppendUnicodeStringToString","RtlAppendUnicodeToString","RtlCopyString","RtlCopyUnicodeString", 
"RtlUnicodeStringToInteger","RtlIntegerToUnicodeString","RtlUpcaseUnicodeString","RtlCompareUnicodeString", "RtlCompareString"," RtlEqualUnicodeString","RtlEqualString"]

network_activity = ["GetPhysicalAddress","GetAllNetworkInterfaces","GetIsNetworkAvailable","GetIP"]


DMA_cluster = ["IoGetDmaAdapter","GetDmaAlignment","PutScatterGatherList"]




section = ["ZwCreateSection","ZwOpenSection","ZwQuerySection","SectionBasicInformation","SectionImageInformation","ZwCreateDirectoryObject","ZwOpenDirectoryObject","ZwReadFile","ZwWriteFile","ZwReadFileScatter","ZwWriteFileGather"]

file_activity = ["CcSetLogHandleForFile","ZwOpenFile","ZwCreateFile","ZwFlushBuffersFile","ZwSetInformationFile","ZwCreatePagingFile","CcGetFileObjectFromSectionPtrsRef","CcGetFileObjectFromSectionPtrs","CcGetFileObjectFromBcb"]

device_activity = ["ZwDeviceIoControlFile","ZwFsControlFile","KeInsertDeviceQueue","PcAddAdapterDevice"]

fs_activity = ["ZwSetQuotaInformationFile","IoWritePartitionTable","IoSetPartitionInformation","IoReadPartitionTable"]

registery_activity = ["ZwCreateKey","ZwOpenKey","ZwDeleteKey","ZwFlushKey","ZwSaveKey","ZwSaveMergedKeys","ZwRestoreKey","ZwLoadKey","ZwLoadKey2","ZwQueryOpenSubKeys","ZwReplaceKey" , "ZwSetInformationKey","ZwQueryKey","ZwEnumerateKey","ZwDeleteValueKey","ZwSetValueKey","ZwQueryValueKey","ZwEnumerateValueKey","ZwQueryMultipleValueKey","ZwInitializeRegistry"]

thread_activity = ["PsCreateSystemThread","PsTerminateSystemThread","KeSetPriorityThread"]

DPC_routine = ["KeRaiseIrqlToDpcLevel","KeInitializeDpc","KeInsertQueueDpc","KeRemoveQueueDpc","KeSetTimer","KeSetTargetProcessorDpc","KefAcquireSpinLockAtDpcLevel"]

IRQL_raise = ["KeRaiseIrqlToDpcLevel","KeRaiseIrql","KfRaiseIrql"]

