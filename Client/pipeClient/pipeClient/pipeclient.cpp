#include <windows.h>
#include <iostream>

#define PIPE_NAME L"\\\\.\\pipe\\CaptureMonitorPipe"

int main() {
    HANDLE hPipe;
    while (true) {
        hPipe = CreateFileW(
            PIPE_NAME,      // pipe name
            GENERIC_READ | GENERIC_WRITE, // read and write access
            0,              // no sharing
            NULL,           // default security attributes
            OPEN_EXISTING,  // opens existing pipe
            0,              // default attributes
            NULL);          // no template file

        if (hPipe != INVALID_HANDLE_VALUE)
            break;

        if (GetLastError() != ERROR_PIPE_BUSY) {
            std::cerr << "Could not open pipe. GLE=" << GetLastError() << std::endl;
            return 1;
        }

        if (!WaitNamedPipeW(PIPE_NAME, 5000)) {
            std::cerr << "Could not wait for pipe. GLE=" << GetLastError() << std::endl;
            return 1;
        }
    }

    std::cout << "Connected to pipe server!" << std::endl;

    wchar_t buffer[128];
    DWORD bytesRead;
    if (ReadFile(hPipe, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, NULL)) {
        buffer[bytesRead / sizeof(wchar_t)] = 0; // null-terminate
        std::wcout << L"Received from server: " << buffer << std::endl;
    }
    else {
        std::cerr << "ReadFile failed. GLE=" << GetLastError() << std::endl;
    }

    CloseHandle(hPipe);
    return 0;
}
