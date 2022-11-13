#include <Windows.h>

//####SHELLCODE####

bool checkMouseMovement() {
    POINT position1, position2;
    GetCursorPos(&position1);
    Sleep(5000);
    GetCursorPos(&position2);
    return ((position1.x == position2.x) && (position1.y == position2.y));
}

bool checkLastMovement(DWORD sleepTime) {
    Sleep(sleepTime);
    DWORD ticks = GetTickCount();
    LASTINPUTINFO li;
    li.cbSize = sizeof(LASTINPUTINFO);
    BOOL res = GetLastInputInfo(&li);
    return (ticks - li.dwTime > sleepTime/2);
}

bool ####FUNCTION####() {
    return (checkMouseMovement() || checkLastMovement(4000));
}