# Anti-Cheat & Malicious Software Detection System

A Windows-based anti-cheating and malicious behavior detection system. The application scans for suspicious processes and, upon identification, injects a control DLL into them to lock out user interaction and prevent further malicious behavior.

## 🔐 Features

- **Process Scanning**: Actively monitors running processes for suspicious signatures or behavior patterns.
- **DLL Injection**: Injects a lockdown DLL into the flagged process to neutralize it.
- **User Interaction Block**: Suspicious applications are rendered non-interactive.
- **Real-Time Monitoring**: Constant surveillance of system activity for rapid threat response.
- **Stealth Mode** *(optional)*: Can run silently in the background.


## 🛠️ How It Works

1. **Detection**: The app scans all running processes for blacklisted names, suspicious windows, or behavioral patterns (e.g., overlay hooks, rapid file access).
2. **Injection**: Once a process is flagged, a precompiled DLL is injected into its memory space.
3. **Lockout**: The injected DLL disables input (mouse/keyboard) to the window and optionally renders a visual warning.
4. **Logging**: Every detection is logged with a timestamp and process metadata.

## ⚙️ Technologies Used

- **Win32 API** (process & window management)
- **C++** (core application)

## ⚠️ Disclaimer

This tool is intended for **ethical use only** — such as monitoring and controlling known cheating software in controlled environments or securing systems from unauthorized software. Unauthorized use against user-installed software without consent may violate laws or software EULAs.
---

Made with grit, paranoia, and way too many `CreateRemoteThread` calls.
