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

bool checkVirtualboxFiles()
{
    /* Array of strings of blacklisted paths */
    const TCHAR* szPaths[] = {
        _T("system32\\drivers\\VBoxMouse.sys"),
        _T("system32\\drivers\\VBoxGuest.sys"),
        _T("system32\\drivers\\VBoxSF.sys"),
        _T("system32\\drivers\\VBoxVideo.sys"),
        _T("system32\\vboxdisp.dll"),
        _T("system32\\vboxhook.dll"),
        _T("system32\\vboxmrxnp.dll"),
        _T("system32\\vboxogl.dll"),
        _T("system32\\vboxoglarrayspu.dll"),
        _T("system32\\vboxoglcrutil.dll"),
        _T("system32\\vboxoglerrorspu.dll"),
        _T("system32\\vboxoglfeedbackspu.dll"),
        _T("system32\\vboxoglpackspu.dll"),
        _T("system32\\vboxoglpassthroughspu.dll"),
        _T("system32\\vboxservice.exe"),
        _T("system32\\vboxtray.exe"),
        _T("system32\\VBoxControl.exe"),
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

bool checkVirtualboxDirectory()
{
    TCHAR szProgramFile[MAX_PATH];
    TCHAR szPath[MAX_PATH] = _T("");
    TCHAR szTarget[MAX_PATH] = _T("oracle\\virtualbox guest additions\\");
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
    return (checkVirtualboxFiles() || checkVirtualboxDirectory());
}