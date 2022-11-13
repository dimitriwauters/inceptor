#include <Windows.h>

//####SHELLCODE####

void get_cpuid_vendor(char *vendor_id) {
  __asm {
    ; save non-volatile register
    push ebx

    ; nullify output registers
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx

    ; call cpuid with argument in EAX
    mov eax, 0x40000000
    cpuid

    ; store vendor_id ptr to destination
    mov edi, vendor_id

    ; move string parts to destination
    mov eax, ebx  ; part 1 of 3 from EBX
    stosd
    mov eax, ecx  ; part 2 of 3 from ECX
    stosd
    mov eax, edx  ; part 3 of 3 from EDX
    stosd

    ; restore saved non-volatile register
    pop ebx

    ; return from function
    retn
  };
}

bool ####FUNCTION####() {

}