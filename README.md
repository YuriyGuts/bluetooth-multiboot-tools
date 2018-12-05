# bluetooth-multiboot-tools

Utility to read and convert Bluetooth pairing key configurations between different OS formats.

Copyright © 2018 Yuriy Guts

## Dependencies

`btconvert.py` requires only vanilla Python 3.6 or above. No third-party packages need to be installed.

## Preparing Input Files

### Linux

1. Copy the contents of '/var/lib/bluetooth' folder:

```bash
sudo cp -r /var/lib/bluetooth/* <source_dir>
```

### Windows

[Detailed instructions on how to export using SysInternals tools](https://unix.stackexchange.com/questions/255509/bluetooth-pairing-on-dual-boot-of-windows-linux-mint-ubuntu-stop-having-to-p)

1. Export `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices`
   to `<source_dir>/BluetoothDevices.reg`.
2. Export `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Keys`
   to `<source_dir>/BluetoothKeys.reg`.

### macOS

1. Copy the binary .plist file with device info:

```bash
sudo cp /Library/Preferences/com.apple.Bluetooth.plist <source_dir>
```

2. Copy the binary .plist file with keys:

```bash
sudo cp /private/var/root/Library/Preferences/com.apple.bluetoothd.plist <source_dir>
```

## Usage

```
btconvert.py [-h] --source-format FMT --destination-format FMT source_dir destination_dir

positional arguments:

  source_dir            Path to the directory containing Bluetooth configuration files
                        to convert. The format of the files depends on the source OS.
  destination_dir       Path to the directory where the converted output will
                        be written. The format of the files depends on the destination OS.

optional arguments:

-h, --help            show this help message and exit
  --source-format FMT   Source operating system (linux, windows, macos)
  --destination-format FMT
                        Destination operating system (linux, windows, macos)
```

## Example

Exporting Bluetooth config files on Linux and converting them to Windows Registry files:

```bash
sudo cp -r /var/lib/bluetooth/* ~/bt-linux
sudo chown -R `whoami` ~/bt-linux
python btconvert.py --source-format linux --destination-format windows ~/bt-linux ~/bt-windows
```
