#include <windows.h>
#include <iostream>
#include <sstream>
#include <psapi.h>
#include <dwmapi.h>

#pragma comment(lib, "dwmapi.lib")

#define PIPE_NAME L"\\\\.\\pipe\\CaptureMonitorPipe"

void LogToDebugger(const std::wstring& msg) {
    OutputDebugStringW(msg.c_str());
}

// Check for WDA_EXCLUDEFROMCAPTURE flag
bool IsWindowExcludedFromCapture(HWND hwnd) {
    DWORD affinity;
    if (GetWindowDisplayAffinity(hwnd, &affinity)) {
        return (affinity == WDA_EXCLUDEFROMCAPTURE);
    }
    return false;
}

// Check if window is hidden from taskbar
bool IsHiddenFromTaskbar(HWND hwnd) {
    LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
    return (exStyle & WS_EX_TOOLWINDOW) != 0 || (GetWindowLong(hwnd, GWL_STYLE) & WS_VISIBLE) == 0;
}

// Check if window is hidden from Alt+Tab
bool IsHiddenFromAltTab(HWND hwnd) {
    LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
    return (exStyle & WS_EX_TOOLWINDOW) != 0 || (exStyle & WS_EX_NOACTIVATE) != 0;
}

// Check if window has transparent/invisible regions
bool HasTransparentRegions(HWND hwnd) {
    BYTE alpha;
    DWORD flags;
    BOOL result = GetLayeredWindowAttributes(hwnd, NULL, &alpha, &flags);
    return result && (flags & LWA_ALPHA) && alpha < 255;
}

// Check if window is using DirectComposition for transparency
bool IsUsingDirectComposition(HWND hwnd) {
    BOOL enabled = FALSE;
    DwmIsCompositionEnabled(&enabled);
    if (!enabled) return false;

    // Check if the window has a cloaked state
    DWORD cloaked = 0;
    HRESULT hr = DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, &cloaked, sizeof(cloaked));
    if (SUCCEEDED(hr) && cloaked != 0) {
        return true;
    }

    return false;
}

// Check if window is clipped or has reduced size
bool IsClippedOrReduced(HWND hwnd) {
    RECT windowRect, clientRect;
    GetWindowRect(hwnd, &windowRect);
    GetClientRect(hwnd, &clientRect);

    // Check if window dimensions are unusually small
    int windowWidth = windowRect.right - windowRect.left;
    int windowHeight = windowRect.bottom - windowRect.top;

    return (windowWidth < 200 || windowHeight < 200);
}

// Check if process is trying to hide from task manager
bool IsHidingFromTaskManager(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) return true; // Can't open process - might be hiding

    wchar_t processName[MAX_PATH];
    if (GetModuleFileNameEx(hProcess, NULL, processName, MAX_PATH) == 0) {
        CloseHandle(hProcess);
        return true; // Can't get process name - suspicious
    }

    // Check if process name has been changed to something misleading
    // This is a simple check that could be expanded
    std::wstring name = processName;
    std::wstring fileName = name.substr(name.find_last_of(L"\\") + 1);
    std::wstring sysProcesses[] = { L"explorer.exe", L"svchost.exe", L"system.exe", L"winlogon.exe" };

    for (const auto& sysProc : sysProcesses) {
        if (_wcsicmp(fileName.c_str(), sysProc.c_str()) == 0) {
            // Process is named like a system process but isn't in system directory
            if (name.find(L"System32") == std::wstring::npos &&
                name.find(L"Windows") == std::wstring::npos) {
                CloseHandle(hProcess);
                return true;
            }
        }
    }

    CloseHandle(hProcess);
    return false;
}

// Check if window disables PrintScreen
bool DisablesPrintScreen(HWND hwnd) {
    // This is a bit tricky to detect directly
    // One approach is to try to take a screenshot and see if it succeeds
    // For simplicity, we'll check if any keyboard hooks are installed
    HHOOK hook = SetWindowsHookEx(WH_KEYBOARD_LL, NULL, NULL, 0);
    if (hook == NULL) {
        return true; // Might indicate hooks are already installed
    }
    UnhookWindowsHookEx(hook);
    return false;
}

// Get the main window of the current process
HWND GetProcessMainWindow() {
    DWORD processId = GetCurrentProcessId();
    HWND hwnd = NULL;

    // Find windows belonging to this process
    HWND currentWindow = FindWindowExW(NULL, NULL, NULL, NULL);
    while (currentWindow != NULL) {
        DWORD windowProcessId = 0;
        GetWindowThreadProcessId(currentWindow, &windowProcessId);

        if (windowProcessId == processId && IsWindowVisible(currentWindow)) {
            // Check if this is a top-level window
            if (GetWindow(currentWindow, GW_OWNER) == NULL) {
                hwnd = currentWindow;
                break;
            }
        }

        currentWindow = FindWindowExW(NULL, currentWindow, NULL, NULL);
    }

    return hwnd;
}

// Check all windows of the process
std::wstring CheckAllWindowsOfProcess() {
    std::wstringstream results;
    DWORD processId = GetCurrentProcessId();
    int windowCount = 0;

    // Enumerate all windows
    HWND hwnd = NULL;
    while ((hwnd = FindWindowEx(NULL, hwnd, NULL, NULL)) != NULL) {
        DWORD windowProcessId = 0;
        GetWindowThreadProcessId(hwnd, &windowProcessId);

        if (windowProcessId == processId) {
            windowCount++;

            wchar_t windowTitle[256] = L"";
            GetWindowTextW(hwnd, windowTitle, 256);

            results << L"Window " << windowCount << L": \"" << windowTitle << L"\"\n";
            results << L"  - Excluded from capture: " << (IsWindowExcludedFromCapture(hwnd) ? L"YES" : L"NO") << L"\n";
            results << L"  - Hidden from taskbar: " << (IsHiddenFromTaskbar(hwnd) ? L"YES" : L"NO") << L"\n";
            results << L"  - Hidden from Alt+Tab: " << (IsHiddenFromAltTab(hwnd) ? L"YES" : L"NO") << L"\n";
            results << L"  - Has transparent regions: " << (HasTransparentRegions(hwnd) ? L"YES" : L"NO") << L"\n";
            results << L"  - Using DirectComposition: " << (IsUsingDirectComposition(hwnd) ? L"YES" : L"NO") << L"\n";
            results << L"  - Clipped or reduced size: " << (IsClippedOrReduced(hwnd) ? L"YES" : L"NO") << L"\n";
        }
    }

    // Add process-level checks
    results << L"\nProcess-level checks:\n";
    results << L"  - Hiding from task manager: " << (IsHidingFromTaskManager(processId) ? L"YES" : L"NO") << L"\n";
    results << L"  - Print screen disabled: " << (DisablesPrintScreen(NULL) ? L"YES" : L"NO") << L"\n";

    return results.str();
}

DWORD WINAPI WorkerThread(LPVOID lpParam) {
    HANDLE hPipe = CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        4096, 4096, // Increased buffer size for larger messages
        0,
        NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        LogToDebugger(L"Failed to create pipe.\n");
        return 1;
    }

    LogToDebugger(L"Pipe created, waiting for client to connect...\n");

    BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (connected) {
        LogToDebugger(L"Client connected to pipe!\n");

        wchar_t buffer[128];
        DWORD bytesRead;

        // Wait for client message first
        if (ReadFile(hPipe, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, NULL)) {
            buffer[bytesRead / sizeof(wchar_t)] = 0;
            LogToDebugger(L"Received from client: ");
            LogToDebugger(buffer);

            // Perform all checks
            std::wstring checkResults = CheckAllWindowsOfProcess();
            LogToDebugger(L"Check results:\n");
            LogToDebugger(checkResults.c_str());

            // Send the results to the client
            DWORD bytesWritten;
            WriteFile(hPipe, checkResults.c_str(),
                (checkResults.length() + 1) * sizeof(wchar_t),
                &bytesWritten, NULL);
        }
    }
    else {
        LogToDebugger(L"Failed to connect to client.\n");
    }

    CloseHandle(hPipe);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
    }
    return TRUE;
}