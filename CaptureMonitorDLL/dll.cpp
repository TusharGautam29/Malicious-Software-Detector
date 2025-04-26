#include <windows.h>
#include <iostream>

#define PIPE_NAME L"\\\\.\\pipe\\CaptureMonitorPipe"

DWORD WINAPI WorkerThread(LPVOID lpParam) {
    HANDLE hPipe = CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        512, 512,
        0,
        NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        OutputDebugStringW(L"Failed to create pipe.\n");
        return 1;
    }

    OutputDebugStringW(L"Pipe created, waiting for client to connect...\n");

    BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

    if (connected) {
        OutputDebugStringW(L"Client connected to pipe!\n");

        wchar_t buffer[128];
        DWORD bytesRead;
        while (ReadFile(hPipe, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, NULL)) {
            buffer[bytesRead / sizeof(wchar_t)] = 0;
            OutputDebugStringW(buffer); // log whatever client sent

            const wchar_t* reply = L"Server received your message!";
            DWORD bytesWritten;
            WriteFile(hPipe, reply, (wcslen(reply) + 1) * sizeof(wchar_t), &bytesWritten, NULL);
        }
    }
    else {
        OutputDebugStringW(L"Failed to connect to client.\n");
    }

    CloseHandle(hPipe);
    return 0;
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
    }
    return TRUE;
}
