#include <windows.h>
#include <iostream>
#include <string>
#include <thread>

#define PIPE_NAME L"\\\\.\\pipe\\WindowCapturePipe"

void PipeServer() {
    HANDLE hPipe = CreateNamedPipe(
        PIPE_NAME,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        512, 512, 0, NULL
    );

    std::wcout << L"Waiting for connection..." << std::endl;
    ConnectNamedPipe(hPipe, NULL);

    wchar_t buffer[512];
    DWORD bytesRead;
    while (true) {
        if (ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, NULL) != 0) {
            std::wcout << L"Received: " << buffer << std::endl;
        }
    }

    CloseHandle(hPipe);
}

int main() {
    std::thread serverThread(PipeServer);
    serverThread.join();

    return 0;
}
