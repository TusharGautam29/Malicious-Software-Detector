#include <windows.h>
#include <iostream>

DWORD WINAPI WorkerThread(LPVOID lpParam);

void LogToDebugger(const std::wstring& msg) {
    OutputDebugStringW(msg.c_str());
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule); // Speeds up attach/detach handling
        CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
    }
    return TRUE;
}

DWORD WINAPI WorkerThread(LPVOID lpParam) {
    MessageBoxW(NULL, L"Injected DLL is running inside WorkerThread!", L"Info", MB_OK);

    // Later, here we will initialize named pipe server

    for (int i = 0; i < 10; i++) {
        LogToDebugger(L"[DLL THREAD] Still alive...");
        Sleep(1000);
    }

    LogToDebugger(L"[DLL THREAD] Worker exiting...");
    return 0;
}
