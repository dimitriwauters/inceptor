#include <winsock2.h>
#include <ws2tcpip.h>
#include <tchar.h>
#include <intrin.h>
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")

//####SHELLCODE####

typedef NTSTATUS(__stdcall* my_RtlNtDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval);

bool checkTiming(DWORD timeout) {
    int iResult;
    DWORD OK = TRUE;
    SOCKADDR_IN sa = { 0 };
    SOCKET sock = INVALID_SOCKET;

    // this code snippet should take around Timeout milliseconds
    do {
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        InetPton(AF_INET, _T("8.8.8.8"), &sa.sin_addr.s_addr); // we should have a route to this IP address
        sa.sin_port = htons(80); // we should not be able to connect to this port

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            OK = FALSE;
            break;
        }

        // setting socket timeout
        unsigned long iMode = 1;
        iResult = ioctlsocket(sock, FIONBIO, &iMode);

        iResult = connect(sock, (SOCKADDR*)&sa, sizeof(sa));
        if (iResult == false) {
            OK = FALSE;
            break;
        }

        iMode = 0;
        iResult = ioctlsocket(sock, FIONBIO, &iMode);
        if (iResult != NO_ERROR) {
            OK = FALSE;
            break;
        }

        // fd set data
        fd_set Write, Err;
        FD_ZERO(&Write);
        FD_ZERO(&Err);
        FD_SET(sock, &Write);
        FD_SET(sock, &Err);
        timeval tv = { 0 };
        tv.tv_usec = timeout * 1000;

        // check if the socket is ready, this call should take Timeout milliseconds
        select(0, NULL, &Write, &Err, &tv);

        if (FD_ISSET(sock, &Err)) {
            OK = FALSE;
            break;
        }

    } while (false);

    if (sock != INVALID_SOCKET)
        closesocket(sock);
    return OK;
}

bool checkSleepSkipping(DWORD Timeout) {
    DWORD StartingTick, TimeElapsedMs;
    LARGE_INTEGER DelayInterval;

    HMODULE hdlNtDelayExecution = LoadLibraryW(L"Ntdll.dll");
    my_RtlNtDelayExecution RtlNtDelayExecution = (my_RtlNtDelayExecution) GetProcAddress(hdlNtDelayExecution, "NtDelayExecution");

    StartingTick = GetTickCount();
    Sleep(Timeout);
    TimeElapsedMs = GetTickCount() - StartingTick;

    LONGLONG SavedTimeout = Timeout * (-10000LL);
    DelayInterval.QuadPart = SavedTimeout;
    RtlNtDelayExecution(TRUE, &DelayInterval);
    if ((abs((LONG)(TimeElapsedMs - Timeout)) > Timeout / 2) || (DelayInterval.QuadPart != SavedTimeout)) return true;
    else return false;
}

bool rdtsc_diff_vmexit(INT iterations) {
    ULONGLONG tsc1 = 0;
    ULONGLONG tsc2 = 0;
    ULONGLONG avg = 0;
    INT cpuInfo[4] = {};

    // Try this 10 times in case of small fluctuations
    for (INT i = 0; i < iterations; i++)
    {
        tsc1 = __rdtsc();
        __cpuid(cpuInfo, 0);
        tsc2 = __rdtsc();

        // Get the delta of the two RDTSC
        avg += (tsc2 - tsc1);
    }
    avg = avg / iterations;
    return (avg > 1000 || avg < 0);
}

bool ####FUNCTION####() {
    return (checkTiming(100) || checkSleepSkipping(100) || rdtsc_diff_vmexit(10));
}