#include <Windows.h>
#include <winternl.h>

//####SHELLCODE####

typedef VOID(NTAPI* my_RtlInitUnicodeString)(PUNICODE_STRING DestinationString, __drv_aliasesMem PCWSTR SourceString);
 typedef int (WINAPI * NtCreateFileFunc)(PHANDLE,DWORD,POBJECT_ATTRIBUTES,PVOID,PVOID,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);

bool checkVirtualDevice(LPWSTR lpDeviceName, ACCESS_MASK DesiredAccess, PHANDLE phDevice) {
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iost;
    UNICODE_STRING uDevName;
    HANDLE hDevice;
    NTSTATUS Status;

    if (phDevice) {
        *phDevice = NULL;
    }
    if (lpDeviceName == NULL) {
        return FALSE;
    }

    hDevice = NULL;
    HMODULE hdlNtCreateFile = LoadLibraryW(L"Ntdll.dll");
    my_RtlInitUnicodeString RtlInitUnicodeString = (my_RtlInitUnicodeString) GetProcAddress(hdlNtCreateFile, "RtlInitUnicodeString");
    NtCreateFileFunc NtCreateFile = (NtCreateFileFunc) GetProcAddress(hdlNtCreateFile, "NtCreateFile");
    RtlSecureZeroMemory(&uDevName, sizeof(uDevName));
    RtlInitUnicodeString(&uDevName, lpDeviceName);
    InitializeObjectAttributes(&attr, &uDevName, OBJ_CASE_INSENSITIVE, 0, NULL);

    Status = NtCreateFile(&hDevice, DesiredAccess, &attr, &iost, NULL, 0, 0, FILE_OPEN, 0, NULL, 0);
    if (NT_SUCCESS(Status)) {
        if (phDevice != NULL) {
            *phDevice = hDevice;
        }
    }

    return NT_SUCCESS(Status);
}

bool ####FUNCTION####() {
    HANDLE hDummy = NULL;
    return (checkVirtualDevice(const_cast<LPWSTR>(L"\\\\.\\VBoxMiniRdDN"), GENERIC_READ, &hDummy) ||
            checkVirtualDevice(const_cast<LPWSTR>(L"\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, &hDummy) ||
            checkVirtualDevice(const_cast<LPWSTR>(L"\\\\.\\VBoxGuest"), GENERIC_READ, &hDummy) ||
            checkVirtualDevice(const_cast<LPWSTR>(L"\\\\.\\VBoxTrayIPC"), GENERIC_READ, &hDummy) ||
            checkVirtualDevice(const_cast<LPWSTR>(L"\\\\.\\VBoxMouse"), GENERIC_READ, &hDummy) ||
            checkVirtualDevice(const_cast<LPWSTR>(L"\\\\.\\VBoxVideo"), GENERIC_READ, &hDummy) ||
            checkVirtualDevice(const_cast<LPWSTR>(L"\\\\.\\HGFS"), GENERIC_READ, &hDummy) ||
            checkVirtualDevice(const_cast<LPWSTR>(L"\\\\.\\vmci"), GENERIC_READ, &hDummy) ||
            checkVirtualDevice(const_cast<LPWSTR>(L"\\\\.\\pipe\\VBoxMiniRdDN"), GENERIC_READ, &hDummy) ||
            checkVirtualDevice(const_cast<LPWSTR>(L"\\\\.\\pipe\\VBoxTrayIPC"), GENERIC_READ, &hDummy)
           );
}