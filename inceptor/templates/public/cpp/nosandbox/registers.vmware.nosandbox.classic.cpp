#include <Windows.h>
#include <iostream>

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
    return (searchRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\PCI\\", "VEN_15AD") ||
            checkRegKeyExists(HKEY_CURRENT_USER, "SOFTWARE\\VMware, Inc.\\VMware Tools") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\vmdebug") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\vmmouse") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VMTools") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VMMEMCTL") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\vmware") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\vmci") ||
            checkRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\vmx86") ||
            searchRegKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\IDE\\", "CdRomNECVMWar_VMware_IDE_CD") ||
            searchRegKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\IDE\\", "CdRomNECVMWar_VMware_SATA_CD") ||
            searchRegKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\IDE\\", "DiskVMware_Virtual_IDE_Hard_Drive") ||
            searchRegKey(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\IDE\\", "DiskVMware_Virtual_SATA_Hard_Drive")
           );
}

bool checkKeyValues() {
    return (checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VMWARE") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VMWARE") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VMWARE") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\Description\\System", "SystemBiosVersion", "VMWARE") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\Description\\System", "SystemBiosVersion", "INTEL - 6040000") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\Description\\System", "VideoBiosVersion", "VMWARE") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "HARDWARE\\Description\\System\\BIOS", "SystemProductName", "VMware") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "0", "VMware") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "1", "VMware") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "DeviceDesc", "VMware") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "FriendlyName", "VMware") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "DeviceDesc", "VMware") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "FriendlyName", "VMware") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet003\\Services\\Disk\\Enum", "DeviceDesc", "VMware") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet003\\Services\\Disk\\Enum", "FriendlyName", "VMware") ||
            checkValueRegKeyExists(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "DisplayName", "vmware tools") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "DisplayName", "vmware tools") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "CoInstallers32", "vmx") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "DriverDesc", "VMware") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "InfSection", "vmx") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "ProviderName", "VMware") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\Settings", "Device Description", "VMware") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", "VMWARE") ||
            checkValueRegKeyExists(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "Device Description", "VMware") ||
            checkValueRegKeyExists(HKEY_CURRENT_USER, "Installer\\Products", "ProductName", "vmware tools")
           );
}

bool ####FUNCTION####(){
    return (checkKeysExists() || checkKeyValues());
}