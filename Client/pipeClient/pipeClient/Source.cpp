#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

#define PIPE_NAME L"\\\\.\\pipe\\CaptureMonitorPipe"

int main() {
    HANDLE hPipe;
    while (true) {
        hPipe = CreateFileW(
            PIPE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

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

    // Send a message to the server first
    const wchar_t* message = L"Hello from client! Please run all checks.";
    DWORD bytesWritten;
    if (!WriteFile(hPipe, message, (wcslen(message) + 1) * sizeof(wchar_t), &bytesWritten, NULL)) {
        std::cerr << "WriteFile failed. GLE=" << GetLastError() << std::endl;
        CloseHandle(hPipe);
        return 1;
    }

    // Read the server's response using a more robust approach
    std::vector<wchar_t> responseBuffer;
    const int CHUNK_SIZE = 4096;
    wchar_t buffer[CHUNK_SIZE];
    DWORD bytesRead;
    bool readSuccess = true;

    std::wcout << L"Receiving check results:" << std::endl;

    do {
        if (ReadFile(hPipe, buffer, (CHUNK_SIZE - 1) * sizeof(wchar_t), &bytesRead, NULL)) {
            if (bytesRead > 0) {
                // Add this chunk to our response buffer
                size_t currentSize = responseBuffer.size();
                responseBuffer.resize(currentSize + bytesRead / sizeof(wchar_t));
                memcpy(responseBuffer.data() + currentSize, buffer, bytesRead);
            }
            else {
                // No more data
                break;
            }
        }
        else {
            if (GetLastError() == ERROR_MORE_DATA) {
                // More data is available, continue reading
                continue;
            }
            else {
                std::cerr << "ReadFile failed. GLE=" << GetLastError() << std::endl;
                readSuccess = false;
                break;
            }
        }
    } while (bytesRead == CHUNK_SIZE - 1);

    if (readSuccess && !responseBuffer.empty()) {
        // Ensure null termination
        responseBuffer.push_back(0);
        std::wcout << responseBuffer.data() << std::endl;
    }

    std::cout << "Communication complete." << std::endl;

    CloseHandle(hPipe);
    return 0;
}