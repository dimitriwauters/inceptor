#include <Windows.h>

//####SHELLCODE####

static bool CALLBACK enumProc(HWND handle, LPARAM lParam) {
    if (LPDWORD pCnt = reinterpret_cast<LPDWORD>(lParam))
        *pCnt++;
    return true;
}

bool ####FUNCTION####() {
    DWORD winCnt = 0;
    if (!EnumWindows((WNDENUMPROC)enumProc, LPARAM(&winCnt))) {
        return false;
    }
    return winCnt < 10;
}