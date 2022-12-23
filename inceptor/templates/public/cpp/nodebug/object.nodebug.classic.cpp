#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <thread>
#include <vector>
#include <iostream>

#define NT_FAIL(status) (status < 0)
#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#define FLG_HEAP_ENABLE_FREE_CHECK 0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))

typedef struct {
    LPVOID lpVirtualAddress;
    DWORD dwSizeOfRawData;
} SECTIONINFO, * PSECTIONINFO;

typedef struct {
    DWORD64 dwRealHash;
    SECTIONINFO SectionInfo;
} HASHSET, * PHASHSET;

typedef NTSTATUS(WINAPI* fnNtQueryInformationProcess) (
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationCLass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef struct __PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} __PEB_LDR_DATA, * __PPEB_LDR_DATA;

// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK
typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct __PEB // 65 elements, 0x210 bytes
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    __PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    LPVOID lpApiSetMap;				// used to be PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STRING usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} __PEB, * __PPEB;

__PPEB GetProcessEnvironmentBlock()
{
    ULONG_PTR pPeb;
#ifdef _WIN64
    pPeb = __readgsqword(0x60);
#else
    // _WIN32
    pPeb = __readfsdword(0x30);
#endif
    return (__PPEB)pPeb;
}

//####SHELLCODE####

fnNtQueryInformationProcess GetNtQueryInformationProcess() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == NULL) {
        return NULL;
    }
    FARPROC func = GetProcAddress(hNtdll, "NtQueryInformationProcess");
    fnNtQueryInformationProcess query_func = (fnNtQueryInformationProcess)func;
    return query_func;
}

// https://anti-debug.checkpoint.com/techniques/object-handles.html#openprocess
bool veh_check(DWORD pid) {
    fnNtQueryInformationProcess NtQueryInformationProcess = GetNtQueryInformationProcess();

    ULONG ReturnLength;
    PROCESS_BASIC_INFORMATION pbi;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ReturnLength);
    PPEB pPEB = (PPEB)pbi.PebBaseAddress;

    SIZE_T Written;
    DWORD64 CrossProcessFlags = -1;
    ReadProcessMemory(hProcess, (PBYTE)pPEB + 0x50, (LPVOID)&CrossProcessFlags, sizeof(DWORD64), &Written);

    return (CrossProcessFlags & 0x4);
}

// https://anti-debug.checkpoint.com/techniques/object-handles.html#createfile
bool check_create_file() {
    CHAR szFileName[MAX_PATH];
    if (0 == GetModuleFileNameA(NULL, szFileName, sizeof(szFileName)))
        return false;

    return INVALID_HANDLE_VALUE == CreateFileA(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
}

// https://anti-debug.checkpoint.com/techniques/object-handles.html#closehandle
bool check_close_handle() {
    __try {
        CloseHandle((HANDLE)0xDEADBEEF);
        return false;
    }
    __except(EXCEPTION_INVALID_HANDLE == GetExceptionCode() ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return true;
    }
}

// https://anti-debug.checkpoint.com/techniques/object-handles.html#loadlibrary
bool check_load_library()
{
    CHAR szBuffer[] = { "C:\\Windows\\System32\\calc.exe" };
    LoadLibraryA(szBuffer);
    return INVALID_HANDLE_VALUE == CreateFileA(szBuffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
}

bool ####FUNCTION####(){
    return (veh_check(GetCurrentProcessId()) || check_create_file() || check_close_handle() || check_load_library());
}