#include <Windows.h>

//####SHELLCODE####

// https://anti-debug.checkpoint.com/techniques/exceptions.html (section 2)
bool check_raise_exception() {
    __try {
        RaiseException(DBG_CONTROL_C, 0, 0, NULL);
        return true;
    }
    __except(DBG_CONTROL_C == GetExceptionCode() ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return false;
    }
}

bool ####FUNCTION####(){
    return (check_raise_exception());
}