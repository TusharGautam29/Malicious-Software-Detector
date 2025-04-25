#include <windows.h>
#include <iostream>
#include <string>

#define PIPE_NAME L"\\\\.\\pipe\\WindowCapturePipe"

DWORD WINAPI MonitorWindows(LPVOID) {
    HWND hwnd;
    DWORD lastState = 0;

    while (true) {
        hwnd = FindWindowW(NULL, L"testemp");
        if (hwnd) {
            DWORD affinity = 0;
            if (GetWindowDisplayAffinity(hwnd, &affinity) && affinity == WDA_EXCLUDEFROMCAPTURE) {
                if (lastState != affinity) {
                    // send pipe message only once per change
                    HANDLE hPipe = CreateFile(PIPE_NAME, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                    if (hPipe != INVALID_HANDLE_VALUE) {
                        const wchar_t* msg = L"Protected window detected!";
                        DWORD bw;
                        WriteFile(hPipe, msg, (DWORD)(wcslen(msg) + 1) * sizeof(wchar_t), &bw, NULL);
                        CloseHandle(hPipe);
                    }
                    lastState = affinity;
                }
            }
            else lastState = 0;
        }
        Sleep(1000);
    }
    return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, MonitorWindows, NULL, 0, NULL);
    }
    return TRUE;
}
