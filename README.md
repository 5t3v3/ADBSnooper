# ADBSnooper - Sensitive Data Scanner for Android Apps

## Overview
**ADBSnooper** is a command-line tool that helps security researchers and developers analyze an Android app's data directory for potential sensitive information. It utilizes **ADB (Android Debug Bridge)** to connect to a rooted Android device, scan files for sensitive data patterns, and categorize files based on their type.

## Features
- 🚀 **Detects and lists sensitive data** such as API keys, passwords, tokens, and other secrets.
- 📂 **Categorizes files** into databases (`.db`), XML files (`.xml`), JSON files (`.json`), data files, and other types.
- 🔍 **Displays file types** for all scanned files.
- 🔑 **Root ADB Execution:** Automatically restarts ADB as root and remounts the filesystem if necessary.
- ✨ **Supports custom sensitive data patterns** through user input.
- 📊 **Progress bar support** for efficient scanning.

## Prerequisites
Ensure you have the following before running ADBSnooper:

- **ADB (Android Debug Bridge)** installed on your system.
- A **rooted Android device** or an emulator with root access.
- USB Debugging enabled on the Android device.
- Python 3 installed with the required dependencies:
```sh
pip install tqdm colorama
```
## Installation

Clone this repository and navigate to the directory:

```sh
git clone https://github.com/5t3v3/ADBSnooper.git
cd ADBSnooper
pip install -r requirements.txt
```

## Usage

Run the script and provide the package name of the app you want to scan:

```sh
python3 adbsnooper.py
```

You will be prompted to enter:
- The **package name** of the target app (e.g., `com.example.app`).
- Any **custom sensitive keywords** (comma-separated, optional).

### Example Output
```sh
Enter the package name of the app: com.example.app
Enter custom sensitive keywords (comma-separated): secret, api_key
ADB is now running with root privileges.
File system is now remounted with write permissions.
Found data directory for com.example.app: /data/data/com.example.app
Scanning for sensitive data...

### Sensitive Data Found ###
File: /data/data/com.example.app/files/user.json
Content: {"username":"admin", "password":"supersecret"}
---------------
```

## File Categories

The tool organizes scanned files into the following categories:

- **🔐 Sensitive Data:** Files containing predefined sensitive patterns (e.g., passwords, API keys, tokens).
- **📁 Database Files:** SQLite `.db` files.
- **📜 XML Files:** Configuration and preference `.xml` files.
- **📄 JSON Files:** `.json` files that may store application data.
- **📊 Data Files:** Files detected with type "data."
- **📂 Other Files:** Miscellaneous files with their file types displayed.

## Notes

- ⚠️ The tool requires **root access** to scan the app's data directory.
- 🔎 If no sensitive data is found, it means no predefined patterns matched the scanned files.
- 🔒 Some files might be **binary/encrypted**, making text extraction difficult.

## Disclaimer

This tool is intended for **security research and educational purposes only**. Do not use it on systems or applications without proper authorization.

## Contributing

If you would like to contribute, feel free to submit a pull request or open an issue in the repository.

---
### Author: Abhijith A
GitHub: [5t3v3](https://github.com/5t3v3)
