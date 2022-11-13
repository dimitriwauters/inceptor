#include <Windows.h>
#include <iostream>
#include <cctype>

#ifndef KEY_WOW64_32KEY
#define KEY_WOW64_32KEY 0x0200
#endif

#ifndef KEY_WOW64_64KEY
#define KEY_WOW64_64KEY 0x0100
#endif

//####SHELLCODE####

bool IsWoW64() {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    return ((si.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_IA64) || (si.wProcessorArchitecture & PROCESSOR_ARCHITECTURE_AMD64));
}

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

HKEY getRegKey(HKEY hKey, const char* regkey_s) {
    HKEY regkey;
	LONG ret;

    if(IsWoW64()) {
        ret = RegOpenKeyExA(hKey, regkey_s, 0, KEY_READ | KEY_WOW64_64KEY, &regkey);
    } else {
        ret = RegOpenKeyExA(hKey, regkey_s, 0, KEY_READ, &regkey);
    }

    if (ret == ERROR_SUCCESS) {
        return regkey;
    }
    return NULL;
}

HKEY searchRegKey(HKEY hKey, const char* regkey_path, const char* regkey_start) {
    HKEY regkey = getRegKey(hKey, regkey_path);
    if (regkey != NULL) {
        LONG ret;
        DWORD cName = 255;
        for(DWORD Index=0; ; Index++)
        {
            char SubKeyName[255];
            ret = RegEnumKeyExA(regkey, Index, SubKeyName, &cName, NULL, NULL, NULL, NULL);
            if(ret != ERROR_SUCCESS)
                break;

            if(isSameCaseInsensitiveString(SubKeyName, regkey_start)) {
                char result[1024];
                RegCloseKey(regkey);
                strcpy_s(result, sizeof(result), regkey_path);
                strcat_s(result, sizeof(result)-strlen(result), regkey_start);
                return getRegKey(hKey, result);
            }
        }
        RegCloseKey(regkey);
    }
    return NULL;
}

bool searchRegKeyValue(HKEY hKey, const char* searchedCategory, const char* searchedValue) {
    LONG ret;
    DWORD size;
    char value[1024];
    size = sizeof(value);
    ret = RegQueryValueExA(hKey, searchedCategory, NULL, NULL, (BYTE*)value, &size);
    if (ret == ERROR_SUCCESS) {
        return isSameCaseInsensitiveString(value, searchedValue);
    }
    return false;
}

bool checkRegKeyExists(HKEY hKey, const char* regkey_s) {
    HKEY regkey = getRegKey(hKey, regkey_s);
	if(regkey != NULL) {
	    RegCloseKey(regkey);
	    return true;
	} else return false;
}

bool searchRegKeyExists(HKEY hKey, const char* regkey_path, const char* regkey_start) {
    HKEY regkey = searchRegKey(hKey, regkey_path, regkey_start);
	if(regkey != NULL) {
	    RegCloseKey(regkey);
	    return true;
	} else return false;
}

bool checkValueRegKeyExists(HKEY hKey, const char* regkey_s, const char* category, const char* value) {
    HKEY regkey = getRegKey(hKey, regkey_s);
	if(regkey != NULL) {
	    bool result = searchRegKeyValue(regkey, category, value);
	    RegCloseKey(regkey);
	    return result;
	} else return false;
}

bool searchValueRegKey(HKEY hKey, const char* regkey_path, const char* regkey_start, const char* category, const char* value) {
    HKEY regkey = searchRegKey(hKey, regkey_path, regkey_start);
	if(regkey != NULL) {
	    bool result = searchRegKeyValue(regkey, category, value);
	    RegCloseKey(regkey);
	    return result;
	} else return false;
}

bool checkKeysExists() {
    return (searchRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\PCI\\", "VEN_80EE") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT\\VBOX__") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\FADT\\VBOX__") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\RSDT\\VBOX__") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxGuest") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxMouse") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxService") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxSF") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxVideo")
           );
}

bool checkKeyValues() {
    return (checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VBOX") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VBOX") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VBOX") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\Description\\System", "SystemBiosVersion", "VBOX") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\Description\\System", "VideoBiosVersion", "VIRTUALBOX") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\Description\\System\\BIOS", "SystemProductName", "VIRTUAL") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "DeviceDesc", "VBOX") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "FriendlyName", "VBOX") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "DeviceDesc", "VBOX") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "FriendlyName", "VBOX") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet003\\Services\\Disk\\Enum", "DeviceDesc", "VBOX") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet003\\Services\\Disk\\Enum", "FriendlyName", "VBOX") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", "VIRTUAL") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", "VIRTUALBOX")
           );
}

bool ####FUNCTION####(){
    return (checkKeysExists() || checkKeyValues());
}