#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <psapi.h>
#include <tchar.h>
#include <memory>
#include <sstream>

// RAII wrappers for Windows handles
class HandleGuard {
private:
    HANDLE& m_handle;
    bool m_owned;

public:
    HandleGuard(HANDLE& handle) : m_handle(handle), m_owned(true) {}

    ~HandleGuard() {
        if (m_owned && m_handle != NULL && m_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_handle);
            m_handle = NULL;
        }
    }

    // Release ownership (don't close handle in destructor)
    void release() {
        m_owned = false;
    }
};

// Helper to get Windows error message
std::wstring GetLastErrorAsString() {
    DWORD error = GetLastError();

    if (error == 0) {
        return L"No error";
    }

    LPWSTR bufPtr = NULL;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&bufPtr, 0, NULL);

    if (bufPtr) {
        std::wstring message(bufPtr);
        LocalFree(bufPtr);

        // Remove newline if present
        size_t pos = message.find_last_not_of(L"\r\n");
        if (pos != std::wstring::npos) {
            message.erase(pos + 1);
        }

        return message;
    }

    // If FormatMessage failed
    std::wstringstream ss;
    ss << L"Error code: " << error;
    return ss.str();
}

// Function to inject DLL into a process
bool InjectDLL(DWORD processID, const std::wstring& dllPath) {
    // Skip system processes to avoid crashes or security issues
    if (processID == 0 || processID == 4) {
        return false; // System and System Idle Process
    }

    // Try to open the process with reduced access first - this helps avoid permission issues
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, processID);

    if (hProcess == NULL) {
        std::wcout << L"Skipping process ID " << processID
            << L" (access denied: " << GetLastErrorAsString() << L")" << std::endl;
        return false;
    }

    // Create a guard for the process handle to ensure it gets closed
    HandleGuard processGuard(hProcess);

    // Get process name for reporting
    WCHAR processName[MAX_PATH] = L"Unknown";
    DWORD size = MAX_PATH;
    BOOL nameResult = QueryFullProcessImageNameW(hProcess, 0, processName, &size);

    // Report process information
    if (nameResult) {
        // Extract just the filename from the path
        WCHAR* fileName = wcsrchr(processName, L'\\');
        if (fileName) {
            fileName++; // Move past the backslash
        }
        else {
            fileName = processName;
        }
        std::wcout << L"Injecting into process: " << fileName << L" (PID: " << processID << L")" << std::endl;
    }
    else {
        std::wcout << L"Injecting into process ID: " << processID << L" (name unknown)" << std::endl;
    }

    // Allocate memory in the target process for the DLL path
    size_t bufferSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID allocMem = VirtualAllocEx(hProcess, NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);

    if (allocMem == NULL) {
        std::wcout << L"  Error: Memory allocation failed - " << GetLastErrorAsString() << std::endl;
        return false;
    }

    // Custom cleanup for allocated memory
    struct MemoryGuard {
        HANDLE process;
        LPVOID memory;

        MemoryGuard(HANDLE p, LPVOID m) : process(p), memory(m) {}

        ~MemoryGuard() {
            if (process != NULL && memory != NULL) {
                VirtualFreeEx(process, memory, 0, MEM_RELEASE);
            }
        }
    };

    MemoryGuard memGuard(hProcess, allocMem);

    // Write the DLL path to the allocated memory in the target process
    if (!WriteProcessMemory(hProcess, allocMem, dllPath.c_str(), bufferSize, NULL)) {
        std::wcout << L"  Error: Failed to write DLL path to memory - "
            << GetLastErrorAsString() << std::endl;
        return false;
    }

    // Get the address of LoadLibraryW in kernel32.dll
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) {
        std::wcout << L"  Error: Could not get handle to kernel32.dll - "
            << GetLastErrorAsString() << std::endl;
        return false;
    }

    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    if (loadLibraryAddr == NULL) {
        std::wcout << L"  Error: Could not find LoadLibraryW function - "
            << GetLastErrorAsString() << std::endl;
        return false;
    }

    // Create a remote thread in the target process to load the DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, allocMem, 0, NULL);
    if (hThread == NULL) {
        std::wcout << L"  Error: Failed to create remote thread - "
            << GetLastErrorAsString() << std::endl;
        return false;
    }

    // Create a guard for the thread handle
    HandleGuard threadGuard(hThread);

    // Wait for the remote thread to finish execution with a timeout
    DWORD waitResult = WaitForSingleObject(hThread, 3000); // Wait up to 3 seconds
    if (waitResult == WAIT_FAILED) {
        std::wcout << L"  Error: Wait for thread failed - " << GetLastErrorAsString() << std::endl;
        return false;
    }
    else if (waitResult == WAIT_TIMEOUT) {
        std::wcout << L"  Warning: Wait timed out, but injection may have succeeded" << std::endl;
        return true; // Injection might have worked, thread just took too long
    }

    // Get thread exit code to check if LoadLibrary succeeded
    DWORD exitCode = 0;
    if (GetExitCodeThread(hThread, &exitCode) && exitCode != 0) {
        std::wcout << L"  Injection successful!" << std::endl;
        return true;
    }
    else {
        std::wcout << L"  Warning: Thread completed but may not have loaded the DLL successfully" << std::endl;
        return false;
    }
}

// Safer callback function for EnumWindows
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    if (!IsWindow(hwnd)) return TRUE; // Skip invalid windows

    std::set<DWORD>* processIds = reinterpret_cast<std::set<DWORD>*>(lParam);
    if (processIds == NULL) return FALSE; // Stop enumeration if parameter is invalid

    // Skip invisible windows
    if (!IsWindowVisible(hwnd)) {
        return TRUE;
    }

    // Get window title
    WCHAR windowTitle[256] = L"";
    if (GetWindowTextW(hwnd, windowTitle, 256) > 0) {
        // Get process ID for this window
        DWORD processId = 0;
        GetWindowThreadProcessId(hwnd, &processId);
        if (processId != 0) {
            // Insert into our set to avoid duplicates
            processIds->insert(processId);
        }
    }

    return TRUE; // Continue enumeration
}

// Function to check if a process is a system process
bool IsSystemProcess(DWORD processId) {
    if (processId == 0 || processId == 4) {
        return true; // System and System Idle Process
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        return false; // Can't open process, assume it's not a system process
    }

    // RAII for process handle
    HandleGuard processGuard(hProcess);

    WCHAR processName[MAX_PATH] = L"";
    if (!GetModuleFileNameExW(hProcess, NULL, processName, MAX_PATH)) {
        return false;
    }

    // Convert to lowercase for case-insensitive comparison
    std::wstring procNameLower = processName;
    for (auto& c : procNameLower) {
        c = towlower(c);
    }

    // Check if it's a system process by path
    if (procNameLower.find(L"\\windows\\system32\\") != std::wstring::npos ||
        procNameLower.find(L"\\windows\\syswow64\\") != std::wstring::npos) {
        return true;
    }

    // Check system processes by name (common system processes)
    const wchar_t* systemProcessNames[] = {
        L"explorer.exe", L"lsass.exe", L"services.exe", L"svchost.exe",
        L"winlogon.exe", L"csrss.exe", L"smss.exe", L"wininit.exe",
        L"dwm.exe", L"taskhost.exe", L"taskhostw.exe", L"rundll32.exe"
    };

    // Extract just filename from path
    wchar_t* fileName = wcsrchr(processName, L'\\');
    if (fileName) {
        fileName++; // Move past the backslash
    }
    else {
        fileName = processName;
    }

    // Compare with known system process names
    for (const auto& sysProc : systemProcessNames) {
        if (_wcsicmp(fileName, sysProc) == 0) {
            return true;
        }
    }

    return false;
}

// Get all active processes with visible windows
std::vector<DWORD> GetAllWindowProcesses() {
    std::set<DWORD> processIds;

    // Enumerate all top-level windows and get their process IDs
    if (!EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&processIds))) {
        std::wcout << L"Error enumerating windows: " << GetLastErrorAsString() << std::endl;
    }

    // Convert set to vector, filtering out system processes
    std::vector<DWORD> result;
    for (DWORD pid : processIds) {
        if (!IsSystemProcess(pid)) {
            result.push_back(pid);
        }
    }

    return result;
}

// Check if running as administrator
bool IsElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    return isElevated != FALSE;
}

int main() {
    // Request admin privileges for better injection success
    if (!IsElevated()) {
        std::wcout << L"Warning: Not running with administrator privileges. Some injections may fail." << std::endl;
        std::wcout << L"Consider restarting the application as administrator." << std::endl << std::endl;
    }

    // Get the full path of the DLL
    WCHAR execPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, execPath, MAX_PATH) == 0) {
        std::wcerr << L"Error getting module path: " << GetLastErrorAsString() << std::endl;
        std::wcout << L"Press Enter to exit..." << std::endl;
        std::cin.get();
        return 1;
    }

    // Replace the injector's filename with the DLL's filename
    std::wstring fullDllPath = execPath;
    size_t lastBackslash = fullDllPath.find_last_of(L'\\');
    if (lastBackslash != std::wstring::npos) {
        fullDllPath = fullDllPath.substr(0, lastBackslash + 1) + L"CaptureMonitorDLL.dll";
    }

    // Check if DLL exists
    DWORD fileAttrs = GetFileAttributesW(fullDllPath.c_str());
    if (fileAttrs == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"Error: DLL not found at path: " << fullDllPath << std::endl;
        std::wcerr << L"Please ensure the DLL is in the same directory as this injector." << std::endl;

        // Prompt for manual path input
        std::wcout << L"Enter full path to CaptureMonitorDLL.dll: ";
        std::getline(std::wcin, fullDllPath);

        // Check again
        fileAttrs = GetFileAttributesW(fullDllPath.c_str());
        if (fileAttrs == INVALID_FILE_ATTRIBUTES) {
            std::wcerr << L"Error: DLL still not found. Exiting." << std::endl;
            std::wcout << L"Press Enter to exit..." << std::endl;
            std::cin.get();
            return 1;
        }
    }

    std::wcout << L"Using DLL path: " << fullDllPath << std::endl;
    std::wcout << L"Scanning for running applications..." << std::endl;

    // Get all processes with visible windows
    std::vector<DWORD> processes = GetAllWindowProcesses();

    if (processes.empty()) {
        std::wcout << L"No suitable target processes found." << std::endl;
        std::wcout << L"Press Enter to exit..." << std::endl;
        std::cin.get();
        return 1;
    }

    std::wcout << L"Found " << processes.size() << L" potential target processes." << std::endl;

    // Inject DLL into each process
    int successCount = 0;
    for (DWORD pid : processes) {
        if (InjectDLL(pid, fullDllPath)) {
            successCount++;
        }
    }

    std::wcout << L"\nDLL injection completed. Successfully injected into " << successCount
        << L" out of " << processes.size() << L" processes." << std::endl;

    std::wcout << L"Press Enter to exit..." << std::endl;
    std::cin.get();
    return 0;
}