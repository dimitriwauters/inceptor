#include <Windows.h>
#include <tlhelp32.h>
#include <tchar.h>

//####SHELLCODE####

DWORD GetProcessIdFromName(const char* name) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);
    char buf[MAX_PATH]={0};
    size_t charsConverted = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if(Process32First(snapshot, &entry)) {
        while(Process32Next(snapshot, &entry)) {
            wcstombs_s(&charsConverted, buf, entry.szExeFile, MAX_PATH);
            if(_stricmp(buf, name) == 0) {
                return entry.th32ProcessID;
            }
        }
    }
    return NULL;
}

DWORD GetCsrssProcessId() {
    /*if (API::IsAvailable(API_IDENTIFIER::API_CsrGetProcessId)) {
        auto CsrGetProcessId = static_cast<pCsrGetId>(API::GetAPI(API_IDENTIFIER::API_CsrGetProcessId));
        return CsrGetProcessId();
    }
    else*/
        return GetProcessIdFromName("csrss.exe");
}

bool CanOpenCsrss() {
    HANDLE hCsrss = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCsrssProcessId());
    if (hCsrss != NULL) {
        CloseHandle(hCsrss);
        return true;
    }
    else return false;
}

/*bool CheckUnbalancedStack() {
    usf_t f = {
        { lib_name_t(L"ntdll"), {
            {sizeof(void *), NULL, "ZwDelayExecution", ARG_ITEM(kZwDelayExecutionArgs) }
        }}
    };
    const uint8_t canary[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF };

  uint32_t args_size;
  const void *args_buff;
  uint32_t reserved_size;
  uint32_t reserved_size_after_call;
  uint32_t canary_size;
  FARPROC func;
  bool us_detected;
  void *canary_addr = (void *)&canary[0];

  static_assert((sizeof(canary) % sizeof(void *)) == 0, "Invalid canary alignement");

  for (auto it = f.begin(), end = f.end(); it != end; ++it) {
    for (auto &vi : it->second) {
      vi.func_addr = GetProcAddress(GetModuleHandleW(it->first.c_str()), vi.func_name.c_str());

      // call to Unbalanced Stack
      args_size = vi.args_size;
      args_buff = vi.args_buff;
      canary_size = sizeof(canary);
      reserved_size = sizeof(void *) + vi.local_vars_size + canary_size;
      reserved_size_after_call = reserved_size + args_size;
      func = vi.func_addr;
      us_detected = false;

      __asm {
        pusha
        mov ecx, args_size
        sub esp, ecx
        mov esi, args_buff
        mov edi, esp
        cld
        rep movsb
        sub esp, reserved_size
        mov ecx, canary_size
        mov esi, canary_addr
        mov edi, esp
        rep movsb
        add esp, reserved_size
        mov eax, func
        call eax
        sub esp, reserved_size_after_call
        mov ecx, canary_size
        mov esi, canary_addr
        mov edi, esp
        repz cmpsb
        cmp ecx, 0
        setnz us_detected
        add esp, reserved_size_after_call
        popa
      }

      if (us_detected)
        return true;
    }
  }

  return false;
}*/

bool ####FUNCTION####() {
    return (CanOpenCsrss());
}