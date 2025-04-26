#include <windows.h>
#include <iostream>
#include <string>

bool InjectDLL(DWORD processID, const std::wstring& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL) {
        std::wcerr << L"Error: Could not open target process with PID: " << processID << std::endl;
        return false;
    }

    // Calculate the buffer size for the wide string (DLL path)
    size_t bufferSize = (dllPath.length() + 1) * sizeof(wchar_t);

    // Allocate memory in the target process for the DLL path
    LPVOID allocMem = VirtualAllocEx(hProcess, NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
    if (allocMem == NULL) {
        std::wcerr << L"Error: Memory allocation failed in the target process" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write the DLL path to the allocated memory in the target process
    if (!WriteProcessMemory(hProcess, allocMem, dllPath.c_str(), bufferSize, NULL)) {
        std::wcerr << L"Error: Failed to write DLL path to memory" << std::endl;
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get the address of LoadLibraryW in kernel32.dll
    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (loadLibraryAddr == NULL) {
        std::wcerr << L"Error: Could not find LoadLibraryW function" << std::endl;
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create a remote thread in the target process to load the DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, allocMem, 0, NULL);
    if (hThread == NULL) {
        std::wcerr << L"Error: Failed to create remote thread in the target process. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Wait for the remote thread to finish execution
    WaitForSingleObject(hThread, INFINITE);

    // Clean up resources
    VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}

DWORD FindProcessId(const std::wstring& windowTitle) {
    HWND hwnd = FindWindowW(NULL, windowTitle.c_str());
    if (hwnd == NULL) {
        std::wcerr << L"Error: Window with title \"" << windowTitle << L"\" not found!" << std::endl;
        return 0;
    }

    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    return pid;
}

int main() {
    std::wstring targetWindow = L"testemp";  // Window title to search for
    std::wstring dllPath = L"C:\\Users\\Hp\\source\\repos\\x\\x64\\Debug\\CaptureMonitorDLL.dll";  // DLL path

    // Find the process ID by the window title
    DWORD pid = FindProcessId(targetWindow);
    if (pid == 0) {
        std::wcerr << L"Error: Failed to find the process ID" << std::endl;
        return 1;
    }

    // Inject the DLL into the target process
    std::wcout << L"Injecting DLL into process with PID: " << pid << std::endl;
    if (InjectDLL(pid, dllPath)) {
        std::wcout << L"DLL injected successfully!" << std::endl;
    }
    else {
        std::wcerr << L"DLL injection failed." << std::endl;
        return 1;
    }

    return 0;
}
