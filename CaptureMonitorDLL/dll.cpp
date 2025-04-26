#include <windows.h>
#include <iostream>
#include <sstream>
#include <psapi.h>
#include <dwmapi.h>
#include <thread>
#include <atomic>
#include <winreg.h>  // For registry functions

#pragma comment(lib, "dwmapi.lib")

#define PIPE_NAME L"\\\\.\\pipe\\CaptureMonitorPipe"

// Global variables for app locking
std::atomic<bool> g_appLocked(false);
HHOOK g_keyboardHook = NULL;
HHOOK g_mouseHook = NULL;
HWND g_mainAppWindow = NULL;
WNDPROC g_originalWndProc = NULL;

// Add a monitoring thread handle
HANDLE g_monitoringThread = NULL;
std::atomic<bool> g_stopMonitoring(false);

void LogToDebugger(const std::wstring& msg) {
    OutputDebugStringW(msg.c_str());
}

// Function prototypes
bool IsWindowExcludedFromCapture(HWND hwnd);
bool IsHiddenFromTaskbar(HWND hwnd);
bool IsHiddenFromAltTab(HWND hwnd);
bool HasTransparentRegions(HWND hwnd);
bool IsUsingDirectComposition(HWND hwnd);
bool IsClippedOrReduced(HWND hwnd);
bool IsHidingFromTaskManager(DWORD processId);
bool DisablesPrintScreen(HWND hwnd);
std::wstring CheckAllWindowsOfProcess();
bool LockApplication(HWND mainWindow);
void UnlockApplication();

// Function to check if the window is excluded from capture
bool IsWindowExcludedFromCapture(HWND hwnd) {
    DWORD affinity = 0;
    BOOL result = GetWindowDisplayAffinity(hwnd, &affinity);

    if (!result) {
        DWORD error = GetLastError();
        wchar_t errorMsg[256];
        swprintf_s(errorMsg, L"GetWindowDisplayAffinity failed with error code: %d\n", error);
        LogToDebugger(errorMsg);
        return false;
    }

    return (affinity == WDA_EXCLUDEFROMCAPTURE);
}

// Check if window is hidden from taskbar
bool IsHiddenFromTaskbar(HWND hwnd) {
    LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
    LONG style = GetWindowLong(hwnd, GWL_STYLE);
    return (exStyle & WS_EX_TOOLWINDOW) != 0 || (style & WS_VISIBLE) == 0;
}

// Check if window is hidden from Alt+Tab
bool IsHiddenFromAltTab(HWND hwnd) {
    LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
    return (exStyle & WS_EX_TOOLWINDOW) != 0 || (exStyle & WS_EX_NOACTIVATE) != 0;
}

// Check if window has transparent/invisible regions
bool HasTransparentRegions(HWND hwnd) {
    LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
    if ((exStyle & WS_EX_LAYERED) == 0) {
        return false;  // Not a layered window
    }

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

    wchar_t processName[MAX_PATH] = L"";
    if (GetModuleFileNameEx(hProcess, NULL, processName, MAX_PATH) == 0) {
        CloseHandle(hProcess);
        return true; // Can't get process name - suspicious
    }

    // Check if process name has been changed to something misleading
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

// Low-level keyboard hook procedure to block keyboard input
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && g_appLocked) {
        // Block all keyboard input when the app is locked
        // Except for a special key combination for admin override (Ctrl+Alt+Shift+U)
        KBDLLHOOKSTRUCT* kbStruct = (KBDLLHOOKSTRUCT*)lParam;

        // Allow a special key combination for emergency unlock (Ctrl+Alt+Shift+U)
        if (kbStruct->vkCode == 'U' &&
            (GetAsyncKeyState(VK_CONTROL) & 0x8000) &&
            (GetAsyncKeyState(VK_MENU) & 0x8000) &&
            (GetAsyncKeyState(VK_SHIFT) & 0x8000)) {
            // Emergency unlock sequence detected
            UnlockApplication();
            return CallNextHookEx(NULL, nCode, wParam, lParam);
        }

        // Block Alt+F4, Ctrl+Alt+Del, etc.
        return 1; // Block the keystroke
    }

    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// Low-level mouse hook procedure to block mouse input
LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && g_appLocked) {
        // Block all mouse input when app is locked
        return 1; // Block the mouse message
    }

    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// Check if PrintScreen functionality is disabled for the window
bool DisablesPrintScreen(HWND hwnd) {
    // Method 1: Check for hooks that might block PrintScreen
    HHOOK hHook = SetWindowsHookEx(WH_KEYBOARD_LL, NULL, NULL, 0);
    if (!hHook) {
        // If we can't set a hook, someone else might have hooked PrintScreen
        return true;
    }
    UnhookWindowsHookEx(hHook);

    // Method 2: Check if the window is excluded from capture
    DWORD affinity = 0;
    if (GetWindowDisplayAffinity(hwnd, &affinity)) {
        if (affinity == WDA_EXCLUDEFROMCAPTURE) {
            return true;
        }
    }

    // Method 3: Check if system-wide PrintScreen is disabled via registry
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD value = 0;
        DWORD size = sizeof(DWORD);
        if (RegQueryValueEx(hKey, L"DisablePrintScreen", NULL, NULL,
            (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return value != 0;
        }
        RegCloseKey(hKey);
    }

    // Method 4: Check for layered windows that might obscure content
    if (hwnd) {
        LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);
        if ((exStyle & WS_EX_LAYERED) && (exStyle & WS_EX_TRANSPARENT)) {
            return true;
        }
    }

    return false;
}

// New window procedure to intercept window messages
LRESULT CALLBACK CustomWndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (g_appLocked) {
        // Block window closing and other messages
        switch (uMsg) {
        case WM_CLOSE:
        case WM_SYSCOMMAND:
            if (wParam == SC_CLOSE)
                return 0; // Block window closing
        case WM_DESTROY:
        case WM_QUIT:
            return 0; // Block these messages
        }
    }

    // Call the original window procedure for other messages
    return CallWindowProc(g_originalWndProc, hwnd, uMsg, wParam, lParam);
}

// Function to periodically display a warning message
DWORD WINAPI WarningMessageThread(LPVOID lpParam) {
    const wchar_t* warningMessage = L"APPLICATION LOCKED: Suspicious activity detected!\n\n"
        L"This application has been locked due to detection of potential interview cheating methods.\n\n"
        L"The application will remain locked and this incident will be reported.";

    while (g_appLocked) {
        if (g_mainAppWindow != NULL && IsWindow(g_mainAppWindow)) {
            // Display warning message on top of the application
            MessageBoxW(g_mainAppWindow, warningMessage, L"SECURITY VIOLATION",
                MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND);
        }

        // Wait before showing the message again
        Sleep(30000); // Show message every 30 seconds
    }

    return 0;
}
// New function to send notifications to client if it's connected
void SendDetectionNotificationToPipe(const std::wstring& message) {
    // Create a named pipe to communicate with any monitoring client that might be running
    HANDLE hPipe = CreateFileW(
        PIPE_NAME,
        GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    if (hPipe != INVALID_HANDLE_VALUE) {
        // Client is running, send notification
        DWORD bytesWritten;
        WriteFile(hPipe, message.c_str(),
            (DWORD)(message.length() + 1) * sizeof(wchar_t),
            &bytesWritten, NULL);
        CloseHandle(hPipe);
    }
    // If pipe can't be opened, client isn't running - that's fine, we lock independently
}
// Lock the application to prevent user interaction
bool LockApplication(HWND mainWindow) {
    if (g_appLocked) return true; // Already locked

    g_mainAppWindow = mainWindow;
    LogToDebugger(L"Locking application due to cheating detection...\n");

    // 1. Install keyboard and mouse hooks to block input
    g_keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);
    g_mouseHook = SetWindowsHookEx(WH_MOUSE_LL, LowLevelMouseProc, NULL, 0);

    if (!g_keyboardHook || !g_mouseHook) {
        LogToDebugger(L"Failed to install input hooks\n");
        // Continue anyway, we'll still try other locking methods
    }

    // 2. Subclass the window to intercept close messages
    if (mainWindow && IsWindow(mainWindow)) {
        g_originalWndProc = (WNDPROC)SetWindowLongPtr(mainWindow, GWLP_WNDPROC, (LONG_PTR)CustomWndProc);
        if (!g_originalWndProc) {
            LogToDebugger(L"Failed to subclass window\n");
        }

        // 3. Disable the close button and other system menu items
        HMENU hMenu = GetSystemMenu(mainWindow, FALSE);
        if (hMenu) {
            EnableMenuItem(hMenu, SC_CLOSE, MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);
        }

        // 4. Prevent the window from being minimized or moved
        LONG style = GetWindowLong(mainWindow, GWL_STYLE);
        SetWindowLong(mainWindow, GWL_STYLE, style & ~(WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU));

        // 5. Force the window to stay on top
        SetWindowPos(mainWindow, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    }

    // 6. Start a thread to periodically show warning messages
    CreateThread(NULL, 0, WarningMessageThread, NULL, 0, NULL);

    g_appLocked = true;
    LogToDebugger(L"Application locked successfully\n");

    // Optional: Send notification to pipe client if it's connected
    SendDetectionNotificationToPipe(L"Application locked due to suspicious activity");

    return true;
}



// Unlock the application (only used for emergency override)
void UnlockApplication() {
    if (!g_appLocked) return;

    LogToDebugger(L"Unlocking application...\n");

    // Remove hooks
    if (g_keyboardHook) {
        UnhookWindowsHookEx(g_keyboardHook);
        g_keyboardHook = NULL;
    }

    if (g_mouseHook) {
        UnhookWindowsHookEx(g_mouseHook);
        g_mouseHook = NULL;
    }

    // Restore original window procedure
    if (g_mainAppWindow && IsWindow(g_mainAppWindow) && g_originalWndProc) {
        SetWindowLongPtr(g_mainAppWindow, GWLP_WNDPROC, (LONG_PTR)g_originalWndProc);

        // Restore window style
        LONG style = GetWindowLong(g_mainAppWindow, GWL_STYLE);
        SetWindowLong(g_mainAppWindow, GWL_STYLE, style | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU);

        // Re-enable system menu items
        HMENU hMenu = GetSystemMenu(g_mainAppWindow, FALSE);
        if (hMenu) {
            EnableMenuItem(hMenu, SC_CLOSE, MF_BYCOMMAND | MF_ENABLED);
        }

        // Remove always-on-top state
        SetWindowPos(g_mainAppWindow, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    }

    g_appLocked = false;
    LogToDebugger(L"Application unlocked\n");
}

// Check all windows of the process and lock if cheating detected
std::wstring CheckAllWindowsOfProcess() {
    std::wstringstream results;
    DWORD processId = GetCurrentProcessId();
    bool cheatDetected = false;
    HWND mainAppWindow = NULL;

    // First, get the process name
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    wchar_t processName[MAX_PATH] = L"Unknown";
    if (hProcess) {
        GetModuleFileNameEx(hProcess, NULL, processName, MAX_PATH);
        CloseHandle(hProcess);
    }

    results << L"Process: " << processName << L" (PID: " << processId << L")\n\n";

    // Enumerate all top-level windows
    int windowCount = 0;
    std::wstringstream topLevelWindows;

    HWND hwnd = NULL;
    while ((hwnd = FindWindowEx(NULL, hwnd, NULL, NULL)) != NULL) {
        DWORD windowProcessId = 0;
        GetWindowThreadProcessId(hwnd, &windowProcessId);

        if (windowProcessId == processId) {
            windowCount++;

            wchar_t windowTitle[256] = L"";
            GetWindowTextW(hwnd, windowTitle, 256);

            wchar_t className[256] = L"";
            GetClassName(hwnd, className, 256);

            // Skip IME windows - they are legitimate Windows components
            if (wcsstr(windowTitle, L"IME") != NULL || wcsstr(className, L"IME") != NULL) {
                topLevelWindows << L"Window " << windowCount << L": \"" << windowTitle << L"\" (Class: " << className << L") - IME Window (skipping)\n\n";
                continue;
            }

            // Remember the first non-IME window as the main app window
            if (mainAppWindow == NULL && wcslen(windowTitle) > 0) {
                mainAppWindow = hwnd;
            }

            // Log window details
            topLevelWindows << L"Window " << windowCount << L": \"" << windowTitle << L"\" (Class: " << className << L")\n";

            // Check for all possible cheating techniques
            bool excludedFromCapture = IsWindowExcludedFromCapture(hwnd);
            bool hiddenFromTaskbar = IsHiddenFromTaskbar(hwnd);
            bool hiddenFromAltTab = IsHiddenFromAltTab(hwnd);
            bool hasTransparentRegions = HasTransparentRegions(hwnd);
            bool usingDirectComp = IsUsingDirectComposition(hwnd);
            bool clippedOrReduced = IsClippedOrReduced(hwnd);

            // Check if any cheating methods are detected in this window
            if (excludedFromCapture) {
                cheatDetected = true;
                topLevelWindows << L"  *** CHEAT DETECTED: Window excluded from capture ***\n";
            }

            if (!wcsstr(windowTitle, L"IME") && (hiddenFromTaskbar || hiddenFromAltTab)) {
                cheatDetected = true;
                topLevelWindows << L"  *** CHEAT DETECTED: Window hiding techniques detected ***\n";
            }

            // Log window attributes
            topLevelWindows << L"  - Excluded from capture: " << (excludedFromCapture ? L"YES" : L"NO") << L"\n";
            topLevelWindows << L"  - Hidden from taskbar: " << (hiddenFromTaskbar ? L"YES" : L"NO") << L"\n";
            topLevelWindows << L"  - Hidden from Alt+Tab: " << (hiddenFromAltTab ? L"YES" : L"NO") << L"\n";
            topLevelWindows << L"  - Has transparent regions: " << (hasTransparentRegions ? L"YES" : L"NO") << L"\n";
            topLevelWindows << L"  - Using DirectComposition: " << (usingDirectComp ? L"YES" : L"NO") << L"\n";
            topLevelWindows << L"  - Clipped or reduced size: " << (clippedOrReduced ? L"YES" : L"NO") << L"\n";

            // Get window styles for debugging
            LONG style = GetWindowLong(hwnd, GWL_STYLE);
            LONG exStyle = GetWindowLong(hwnd, GWL_EXSTYLE);

            topLevelWindows << L"  - Window Style: 0x" << std::hex << style << std::dec << L"\n";
            topLevelWindows << L"  - Window Ex-Style: 0x" << std::hex << exStyle << std::dec << L"\n\n";
        }
    }

    results << L"Found " << windowCount << L" windows belonging to the process\n\n";
    results << topLevelWindows.str();

    // Add process-level checks
    bool hidesFromTaskMgr = IsHidingFromTaskManager(processId);
    bool disablesPrintScreen = DisablesPrintScreen(NULL);

    results << L"\nProcess-level checks:\n";
    results << L"  - Hiding from task manager: " << (hidesFromTaskMgr ? L"YES" : L"NO") << L"\n";
    results << L"  - PrintScreen disabled: " << (disablesPrintScreen ? L"YES" : L"NO") << L"\n";

    if (hidesFromTaskMgr) {
        cheatDetected = true;
        results << L"  *** CHEAT DETECTED: Process hiding from task manager ***\n";
    }

    if (disablesPrintScreen) {
        cheatDetected = true;
        results << L"  *** CHEAT DETECTED: PrintScreen functionality disabled ***\n";
    }

    // Check for system-wide hooks
    results << L"\nPossible keyboard/mouse hooks: ";
    HHOOK testHook = SetWindowsHookEx(WH_KEYBOARD_LL, NULL, NULL, 0);
    if (testHook == NULL) {
        results << L"DETECTED (keyboard low-level hooks may be installed)\n";
        cheatDetected = true;
        results << L"  *** CHEAT DETECTED: System-wide keyboard hooks detected ***\n";
    }
    else {
        UnhookWindowsHookEx(testHook);
        results << L"None detected\n";
    }

    // Summary of potential cheating methods found
    results << L"\nSUMMARY OF POTENTIAL ISSUES:\n";
    results << L"-----------------------------\n";

    if (windowCount == 0) {
        results << L"- Process has no visible windows (highly suspicious)\n";
        cheatDetected = true;
    }

    // If cheating methods are detected, lock the application
    if (cheatDetected) {
        results << L"\n!!! CHEATING DETECTED - APPLICATION WILL BE LOCKED !!!\n";

        // Lock the application if a main window was found
        if (mainAppWindow != NULL) {
            if (LockApplication(mainAppWindow)) {
                results << L"Application successfully locked.\n";
            }
            else {
                results << L"Failed to lock application.\n";
            }
        }
        else {
            results << L"No main window found to lock.\n";
        }
    }
    else {
        results << L"No cheating methods detected.\n";
    }

    return results.str();
}

// New function for periodic monitoring
DWORD WINAPI MonitoringThread(LPVOID lpParam) {
    const int CHECK_INTERVAL_MS = 5000; // Check every 5 seconds

    LogToDebugger(L"Starting automatic monitoring thread...\n");

    while (!g_stopMonitoring) {
        // Don't run checks if already locked
        if (!g_appLocked) {
            LogToDebugger(L"Running automatic cheat detection check...\n");
            CheckAllWindowsOfProcess();
            // Note: The CheckAllWindowsOfProcess function will lock the app if cheating is detected
        }

        // Wait for next check interval
        Sleep(CHECK_INTERVAL_MS);
    }

    LogToDebugger(L"Monitoring thread terminated.\n");
    return 0;
}

// Original pipe server thread - keep this for backward compatibility with the client
DWORD WINAPI PipeServerThread(LPVOID lpParam) {
    HANDLE hPipe = CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        8192, 8192, // Increased buffer size for larger messages
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
            LogToDebugger(L"Check results prepared, sending to client...\n");

            // Send the results to the client in chunks if necessary
            const wchar_t* pData = checkResults.c_str();
            size_t remainingBytes = (checkResults.length() + 1) * sizeof(wchar_t);

            while (remainingBytes > 0) {
                DWORD bytesToWrite = (remainingBytes > 4096) ? 4096 : (DWORD)remainingBytes;
                DWORD bytesWritten;

                if (!WriteFile(hPipe, pData, bytesToWrite, &bytesWritten, NULL)) {
                    LogToDebugger(L"WriteFile failed.\n");
                    break;
                }

                pData += bytesWritten / sizeof(wchar_t);
                remainingBytes -= bytesWritten;
            }

            LogToDebugger(L"Results sent to client.\n");
        }
    }
    else {
        LogToDebugger(L"Failed to connect to client.\n");
    }

    CloseHandle(hPipe);

    // Create another pipe server instance for future connections
    CreateThread(NULL, 0, PipeServerThread, NULL, 0, NULL);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Start the monitoring thread for automatic detection
        g_monitoringThread = CreateThread(NULL, 0, MonitoringThread, NULL, 0, NULL);

        // Also start the pipe server thread for backward compatibility
        CreateThread(NULL, 0, PipeServerThread, NULL, 0, NULL);

        LogToDebugger(L"Anti-cheating DLL initialized with automatic monitoring\n");
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        // Clean up resources
        g_stopMonitoring = true;

        if (g_monitoringThread) {
            // Wait for monitoring thread to exit
            WaitForSingleObject(g_monitoringThread, 1000);
            CloseHandle(g_monitoringThread);
        }

        if (g_keyboardHook) UnhookWindowsHookEx(g_keyboardHook);
        if (g_mouseHook) UnhookWindowsHookEx(g_mouseHook);

        LogToDebugger(L"Anti-cheating DLL detached\n");
    }
    return TRUE;
}