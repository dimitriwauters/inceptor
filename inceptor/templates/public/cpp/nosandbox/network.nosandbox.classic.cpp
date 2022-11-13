#include <stdio.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#pragma comment(lib, "IPHLPAPI.lib")

//####SHELLCODE####

bool checkMAC(const char* macAddress) {
    unsigned long alist_size = 0, ret;
    ret = GetAdaptersAddresses(AF_UNSPEC, 0, 0, 0, &alist_size);

    if (ret == ERROR_BUFFER_OVERFLOW) {
        IP_ADAPTER_ADDRESSES* palist = (IP_ADAPTER_ADDRESSES*)LocalAlloc(LMEM_ZEROINIT, alist_size);
        void* palist_free = palist;

        if (palist) {
            GetAdaptersAddresses(AF_UNSPEC, 0, 0, palist, &alist_size);
            char mac[6]={0};
            while (palist){
                if (palist->PhysicalAddressLength == 0x6) {
                    memcpy(mac, palist->PhysicalAddress, 0x6);
                    if (!memcmp(macAddress, mac, 3)) {  /* First 3 bytes are the same */
                        LocalFree(palist_free);
                        return true;
                    }
                }
                palist = palist->Next;
            }
            LocalFree(palist_free);
        }
    }
    return false;
}

bool checkMACs() {
    return (checkMAC("\x00\x1C\x42") ||
            checkMAC("\x08\x00\x27") ||
            checkMAC("\x00\x05\x69") ||
            checkMAC("\x00\x0C\x29") ||
            checkMAC("\x00\x1C\x14") ||
            checkMAC("\x00\x50\x56") ||
            checkMAC("\x00\x16\xE3")
           );
}

bool ####FUNCTION####() {
    return checkMACs();
}