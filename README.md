# File Integrity Monitor

A lightweight Python script that detects file changes using SHA-256 hashing.

## Features
- Tracks modifications to files
- Alerts when EXE/DLL files change
- Configurable check intervals (default: 30 sec)
- Logs changes to `logs/file_changes.log`

# Monitor specific files
python main.py filename.dll --interval 60

