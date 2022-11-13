#define _CRT_SECURE_NO_WARNINGS 1

#include <Windows.h>
#include <tchar.h>
#include <shlobj.h>
#include <iostream>

//####SHELLCODE####

bool is_FileExists(TCHAR* szPath)
{
    DWORD dwAttrib = GetFileAttributes(szPath);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

bool is_DirectoryExists(TCHAR* szPath)
{
    DWORD dwAttrib = GetFileAttributes(szPath);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES) && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

bool IsWoW64() {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    return ((si.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_IA64) || (si.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_AMD64));
}

bool checkVMWareFiles()
{
    /* Array of strings of blacklisted paths */
    const TCHAR* szPaths[] = {
        _T("system32\\drivers\\vmmouse.sys"),
        _T("system32\\drivers\\vmnet.sys"),
        _T("system32\\drivers\\vmxnet.sys"),
        _T("system32\\drivers\\vmhgfs.sys"),
        _T("system32\\drivers\\vmx86.sys"),
        _T("system32\\drivers\\hgfs.sys"),
    };

    /* Getting Windows Directory */
    WORD dwlength = sizeof(szPaths) / sizeof(szPaths[0]);
    TCHAR szWinDir[MAX_PATH] = _T("");
    TCHAR szPath[MAX_PATH] = _T("");
    GetWindowsDirectory(szWinDir, MAX_PATH);

    for (int i = 0; i < dwlength; i++)
    {
        _tcscpy(szPath, szWinDir);
        _tcscat(szPath, _T("\\"));
        _tcscat(szPath, szPaths[i]);
        if (is_FileExists(szPath))
            return true;
    }
    return false;
}

bool checkVMWareDirectory()
{
    TCHAR szProgramFile[MAX_PATH];
    TCHAR szPath[MAX_PATH] = _T("");
    TCHAR szTarget[MAX_PATH] = _T("VMware\\");
    if (IsWoW64()) {
        ExpandEnvironmentStrings(_T("%ProgramW6432%"), szProgramFile, ARRAYSIZE(szProgramFile));
    }
    else
        SHGetSpecialFolderPath(NULL, szProgramFile, CSIDL_PROGRAM_FILES, FALSE);
    _tcscpy(szPath, szProgramFile);
    _tcscat(szPath, _T("\\"));
    _tcscat(szPath, szTarget);
    return is_DirectoryExists(szPath);
}

bool ####FUNCTION####(){
    return (checkVMWareFiles() || checkVMWareDirectory());
}