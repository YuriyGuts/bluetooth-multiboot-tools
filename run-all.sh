#!/usr/bin/env bash

chmod +x btkeys.py
btconvert.py --source-format linux   --destination-format linux   ~/Downloads/Bluetooth-Linux   ~/Downloads/Bluetooth-Linux-2-Linux
btconvert.py --source-format linux   --destination-format windows ~/Downloads/Bluetooth-Linux   ~/Downloads/Bluetooth-Linux-2-Windows
btconvert.py --source-format linux   --destination-format macos   ~/Downloads/Bluetooth-Linux   ~/Downloads/Bluetooth-Linux-2-macOS
btconvert.py --source-format windows --destination-format linux   ~/Downloads/Bluetooth-Windows ~/Downloads/Bluetooth-Windows-2-Linux
btconvert.py --source-format windows --destination-format windows ~/Downloads/Bluetooth-Windows ~/Downloads/Bluetooth-Windows-2-Windows
btconvert.py --source-format windows --destination-format macos   ~/Downloads/Bluetooth-Windows ~/Downloads/Bluetooth-Windows-2-macOS
btconvert.py --source-format macos   --destination-format linux   ~/Downloads/Bluetooth-macOS   ~/Downloads/Bluetooth-macOS-2-Linux
btconvert.py --source-format macos   --destination-format windows ~/Downloads/Bluetooth-macOS   ~/Downloads/Bluetooth-macOS-2-Windows
btconvert.py --source-format macos   --destination-format macos   ~/Downloads/Bluetooth-macOS   ~/Downloads/Bluetooth-macOS-2-macOS
