#!/usr/bin/env python3
"""
Utility to read and convert Bluetooth pairing key configurations between different OS formats.
Copyright (c) 2018 Yuriy Guts

----------------------------------------------------------------------------------------------
Preparing input files:
----------------------------------------------------------------------------------------------

Windows

Use SysInternals toold to export the registry keys responsible for Bluetooth configuration.
Note: use full directory paths!

psexec -s -i reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT\
                        Parameters\Devices <source_dir_full_path>\BluetoothDevices.reg
psexec -s -i reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT\
                        Parameters\Keys <source_dir_full_path>\BluetoothKeys.reg

Linux

1. Copy the contents of '/var/lib/bluetooth' folder:
   sudo cp -r /var/lib/bluetooth/* <source_dir>

macOS

1. Copy the binary .plist file with device info:
   sudo cp /Library/Preferences/com.apple.Bluetooth.plist <source_dir>

2. Copy the binary .plist file with keys:
   sudo cp /private/var/root/Library/Preferences/com.apple.bluetoothd.plist <source_dir>

----------------------------------------------------------------------------------------------
Usage
----------------------------------------------------------------------------------------------

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

----------------------------------------------------------------------------------------------
Example
----------------------------------------------------------------------------------------------

python btconvert.py --source-format linux --destination-format windows ~/bt-linux ~/bt-windows

"""

import abc
import argparse
import configparser
import plistlib
import re
import sys

from pathlib import Path


class MACAddress(object):
    def __init__(self, mac_bytes):
        if len(mac_bytes) != 6:
            raise ValueError('MAC addresses must have exactly 6 bytes')
        self.bytes = mac_bytes

    def __eq__(self, other):
        if isinstance(other, MACAddress):
            return self.bytes == other.bytes
        return False

    def __str__(self):
        return ':'.join(f'{byte:02X}' for byte in self.bytes)

    def __hash__(self):
        return hash(str(self))

    @classmethod
    def parse(cls, text):
        return MACAddress(parse_separated_byte_string(text))


class BluetoothKey(object):
    def __init__(self, ltk, irk, csrk, counter, erand, ediv):
        self.ltk = ltk
        self.irk = irk
        self.csrk = csrk
        self.counter = counter
        self.erand = erand
        self.ediv = ediv


class BluetoothDevice(object):
    def __init__(self, mac_address, name, vendor_id, product_id, version, supports_le):
        self.mac_address = mac_address
        self.name = name
        self.vendor_id = vendor_id
        self.product_id = product_id
        self.version = version
        self.supports_le = supports_le

    def __str__(self):
        if self.name:
            return f'{self.mac_address} ({self.name})'
        return f'{self.mac_address}'

    def __hash__(self):
        return hash(self.mac_address)


class BluetoothAdapter(object):
    def __init__(self, mac_address):
        self.mac_address = mac_address
        self.devices = {}

    def add_device(self, device, key):
        self.devices[device] = key

    def remove_device(self, device):
        if device in self.devices:
            del self.devices[device]

    def __str__(self):
        return f'{self.mac_address} (Devices: {",".join(str(device) for device in self.devices)})'


class BluetoothConfig(object):
    def __init__(self):
        self.adapters = {}

    def add_adapter(self, adapter):
        self.adapters[adapter.mac_address] = adapter

    def remove_adapter(self, adapter):
        del self.adapters[adapter.mac_address]


class BluetoothConfigAdapter(abc.ABC):
    """
    Abstract base class for config adapters.
    """
    @abc.abstractmethod
    def read_from_dir(self, input_dir):
        """
        Parse Bluetooth configuration files (in the format understood by this adapter)
        from the specified directory.

        Parameters
        ----------
        input_dir : str
            Path to the input directory.

        Returns
        -------
        BluetoothConfig
        """
        pass

    @abc.abstractmethod
    def write_to_dir(self, config, output_dir):
        """
        Save Bluetooth configuration files (in the format understood by this adapter)
        to the specified directory.

        Parameters
        ----------
        config : BluetoothConfig
            Platform-agnostic config model returned by `read_from_dir`.
        output_dir : str
            Path to the output directory. If does not exist, will be created.
        """
        pass


class LinuxBluetoothConfigAdapter(BluetoothConfigAdapter):
    """
    Reads and writes Linux Bluetooth configuration files.
    """
    DEVICE_INFO_FILENAME = 'info'

    @staticmethod
    def _create_config_parser():
        parser = configparser.RawConfigParser()
        parser.optionxform = lambda option: option
        return parser

    def read_from_dir(self, input_dir):
        """
        Parse Linux Bluetooth configuration files from the specified directory.

        Parameters
        ----------
        input_dir : str
            Path to the input directory.

        Returns
        -------
        BluetoothConfig
        """
        input_path = Path(input_dir)
        config = BluetoothConfig()

        adapter_macs = [
            subdir.name
            for subdir in input_path.iterdir()
            if subdir.is_dir() and ':' in subdir.name
        ]

        if len(adapter_macs) == 0:
            raise FileNotFoundError('Should have at least one directory named as a MAC address')

        for adapter_mac_str in adapter_macs:
            adapter = BluetoothAdapter(mac_address=MACAddress.parse(adapter_mac_str))
            config.add_adapter(adapter)

            adapter_path = input_path / adapter_mac_str
            device_subdirs = [
                subdir
                for subdir in adapter_path.iterdir()
                if subdir.is_dir() and ':' in subdir.name
            ]

            for device_subdir in device_subdirs:
                parser = self._create_config_parser()
                parser.read([device_subdir / self.DEVICE_INFO_FILENAME])

                device = BluetoothDevice(
                    mac_address=MACAddress.parse(device_subdir.name),
                    name=parser['General'].get('Name', device_subdir.name),
                    vendor_id=parser['DeviceID'].get('Vendor', None),
                    product_id=parser['DeviceID'].get('Product', None),
                    version=parser['DeviceID'].get('Version', None),
                    supports_le='LE' in parser['General'].get('SupportedTechnologies', ''),
                )

                has_irk = 'IdentityResolvingKey' in parser
                has_csrk = 'LocalSignatureKey' in parser
                key = BluetoothKey(
                    ltk=bytes.fromhex(parser['LongTermKey']['Key']),
                    irk=bytes.fromhex(parser['IdentityResolvingKey']['Key']) if has_irk else None,
                    csrk=bytes.fromhex(parser['LocalSignatureKey']['Key']) if has_csrk else None,
                    counter=parser['LocalSignatureKey']['Counter'] if has_csrk else None,
                    erand=int(parser['LongTermKey']['Rand']).to_bytes(8, 'big'),
                    ediv=int(parser['LongTermKey']['EDiv']).to_bytes(4, 'big'),
                )
                adapter.add_device(device, key)
                pass

        return config

    def write_to_dir(self, config, output_dir):
        """
        Save Linux Bluetooth configuration files to the specified directory.

        Parameters
        ----------
        config : BluetoothConfig
            Platform-agnostic config model returned by `read_from_dir`.
        output_dir : str
            Path to the output directory. If does not exist, will be created.
        """
        output_path = Path(output_dir)
        for adapter_mac, adapter in config.adapters.items():
            adapter_mac_str = ':'.join(f'{byte:02X}' for byte in adapter_mac.bytes)
            adapter_path = output_path / adapter_mac_str
            adapter_path.mkdir(parents=True, exist_ok=True)

            for device, key in adapter.devices.items():
                device_mac_str = ':'.join(f'{byte:02X}' for byte in device.mac_address.bytes)
                device_path = adapter_path / device_mac_str
                device_path.mkdir(parents=True, exist_ok=True)

                parser = self._create_config_parser()
                parser['General'] = {
                    'Name': device.name,
                    'Trusted': 'true',
                    'Blocked': 'false',
                }
                if device.supports_le:
                    parser['General']['SupportedTechnologies'] = 'LE;'

                device_id = {}
                if device.vendor_id:
                    device_id['Vendor'] = device.vendor_id
                if device.product_id:
                    device_id['Product'] = device.product_id
                if device.version:
                    device_id['Version'] = device.version

                if device_id:
                    parser['DeviceID'] = device_id

                if key.irk:
                    parser['IdentityResolvingKey'] = {
                        'Key': key.irk.hex().upper(),
                    }
                if key.csrk:
                    parser['LocalSignatureKey'] = {
                        'Key': key.csrk.hex().upper(),
                        'Counter': key.counter,
                        'Authenticated': 'false',
                    }

                parser['LongTermKey'] = {
                    'Key': key.ltk.hex().upper(),
                    'Authenticated': 0,
                    'EncSize': 16,
                    'EDiv': int.from_bytes(key.ediv, 'big', signed=False),
                    'Rand': int.from_bytes(key.erand, 'big', signed=False),
                }

                parser['ConnectionParameters'] = {
                    'MinInterval': 6,
                    'MaxInterval': 9,
                    'Latency': 44,
                    'Timeout': 216,
                }

                with open(device_path / self.DEVICE_INFO_FILENAME, 'w') as fp:
                    parser.write(fp, space_around_delimiters=False)


class WindowsBluetoothConfigAdapter(BluetoothConfigAdapter):
    """
    Reads and writes Windows Bluetooth configuration files.
    """
    DEVICE_CONFIG_FILENAME = 'BluetoothDevices.reg'
    KEY_CONFIG_FILENAME = 'BluetoothKeys.reg'

    FILE_HEADER = 'Windows Registry Editor Version 5.00'
    REGISTRY_PATH = [
        'HKEY_LOCAL_MACHINE', 'SYSTEM', 'CurrentControlSet', 'Services', 'BTHPORT', 'Parameters',
    ]
    DEFAULT_ENCODING = 'utf-16le'
    DEFAULT_BOM = '\ufeff'

    @staticmethod
    def parse_reg_key_value_line(line):
        """
        Extract the key and the value from a REG key-value pair line.
        """
        key, value = line.split('=')
        key = key.replace('"', '')
        value = WindowsBluetoothConfigAdapter.parse_reg_value(value)
        return key, value

    @staticmethod
    def parse_reg_value(text):
        """
        Parse the value from a REG key-value pair line.
        """
        parts = text.split(':')
        dtype = parts[0].lower()
        value = ''.join(parts[1:])

        if dtype in ['dword', 'qword']:
            return int.from_bytes(parse_separated_byte_string(value), 'big')
        elif dtype == 'hex':
            return parse_separated_byte_string(value)
        elif dtype == 'hex(b)':
            return bytes(reversed(parse_separated_byte_string(value)))

        # String.
        return text.replace('"', '')

    @staticmethod
    def parse_reg_file(text):
        """
        Parse the contents of a REG file into to a dict.
        """
        root = {}
        current_key = root
        lines = text.replace('\r', '').split('\n')

        for line in lines:
            # If it's a path, make sure the root dictionary contains all keys.
            if line.startswith('['):
                current_key = root
                parts = line.replace('[', '').replace(']', '').split('\\')
                for part in parts:
                    if part not in current_key:
                        current_key[part] = {}
                    current_key = current_key[part]
            # If it's a key-value pair, parse both.
            elif line.startswith('"'):
                key, value = WindowsBluetoothConfigAdapter.parse_reg_key_value_line(line)
                current_key[key] = value

        return root

    @staticmethod
    def format_reg_key_value_line(key, value, dtype):
        """
        Format a single key-value line for a REG file.
        """
        key_text = f'"{key}"'
        dtype = dtype.lower()
        if dtype == 'dword':
            if len(value) < 4:
                value = (bytes(4) + value)[-4:]
            value_text = value.hex()
        elif dtype == 'qword':
            if len(value) < 8:
                value = (bytes(8) + value)[-8:]
            value_text = value.hex()
        elif dtype == 'hex':
            value_text = ','.join(f'{byte:02x}' for byte in value)
        elif dtype == 'hex(b)':
            value_text = ','.join(f'{byte:02x}' for byte in bytes(reversed(value)))
        else:
            value_text = f'"{value}"'
        return f'{key_text}={dtype}:{value_text}\r\n'

    def read_from_dir(self, input_dir):
        """
        Parse Windows Bluetooth configuration files from the specified directory.

        Parameters
        ----------
        input_dir : str
            Path to the input directory.

        Returns
        -------
        BluetoothConfig
        """
        input_path = Path(input_dir)
        device_config_path = input_path / self.DEVICE_CONFIG_FILENAME
        key_config_path = input_path / self.KEY_CONFIG_FILENAME

        config = BluetoothConfig()
        if not device_config_path.exists():
            raise FileNotFoundError(f'File {device_config_path} not found')
        if not key_config_path.exists():
            raise FileNotFoundError(f'File {key_config_path} not found')

        # Read both .reg files.
        with open(device_config_path, encoding=self.DEFAULT_ENCODING) as fp:
            device_config = WindowsBluetoothConfigAdapter.parse_reg_file(fp.read())
        with open(key_config_path, encoding=self.DEFAULT_ENCODING) as fp:
            key_config = WindowsBluetoothConfigAdapter.parse_reg_file(fp.read())

        device_config_devices = {}
        device_cache = device_config
        for path in self.REGISTRY_PATH + ['Devices']:
            device_cache = device_cache[path]

        # Process the Devices registry section.
        for device_mac_str, device_meta in device_cache.items():
            try:
                device_mac = MACAddress.parse(device_mac_str)
            except ValueError:
                continue

            device = BluetoothDevice(
                mac_address=device_mac,
                name=''.join(chr(code) for code in device_meta['Name'] if 32 <= code <= 127),
                vendor_id=device_meta.get('VID'),
                product_id=device_meta.get('PID'),
                version=device_meta.get('Version'),
                supports_le='LEName' in device_meta,
            )
            device_config_devices[device_mac] = device

        # Process the Keys section and match the devices with the ones from the device cache.
        key_cache = key_config
        for path in self.REGISTRY_PATH + ['Keys']:
            key_cache = key_cache[path]

        for adapter_mac_str, device_keys in key_cache.items():
            adapter = BluetoothAdapter(mac_address=MACAddress.parse(adapter_mac_str))
            config.add_adapter(adapter)

            for device_mac_str, device_meta in device_keys.items():
                try:
                    device_mac = MACAddress.parse(device_mac_str)
                    device_meta.get('LTK')
                except (ValueError, AttributeError):
                    continue

                key = BluetoothKey(
                    ltk=device_meta.get('LTK'),
                    irk=device_meta.get('IRK'),
                    csrk=device_meta.get('CSRK'),
                    counter=device_meta.get('OutboundSignCounter'),
                    erand=device_meta.get('ERand'),
                    ediv=int(device_meta.get('EDIV')).to_bytes(4, 'big'),
                )
                if device_mac in device_config_devices:
                    adapter.add_device(device_config_devices[device_mac], key)

        return config

    def write_to_dir(self, config, output_dir):
        """
        Save Windows Bluetooth configuration files to the specified directory.

        Parameters
        ----------
        config : BluetoothConfig
            Platform-agnostic config model returned by `read_from_dir`.
        output_dir : str
            Path to the output directory. If does not exist, will be created.
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        encoding = self.DEFAULT_ENCODING
        reg_kv = self.format_reg_key_value_line

        # Write the device metadata REG file.
        with open(output_path / self.DEVICE_CONFIG_FILENAME, 'w', encoding=encoding) as fp:
            fp.write(self.DEFAULT_BOM)
            fp.write(f'{self.FILE_HEADER}\r\n\r\n')
            key_prefix = '\\'.join(self.REGISTRY_PATH + ['Devices'])
            fp.write(f'[{key_prefix}]\r\n\r\n')

            for adapter_mac, adapter in config.adapters.items():
                for device, key in adapter.devices.items():
                    device_mac_string = device.mac_address.bytes.hex()
                    fp.write(f'[{key_prefix}\\{device_mac_string}]\r\n')
                    if device.name:
                        name_bytes = bytes(device.name, encoding='utf-8') + bytes([0])
                        fp.write(reg_kv('Name', name_bytes, 'hex'))
                    if device.vendor_id:
                        fp.write(reg_kv('VID', int(device.vendor_id).to_bytes(4, 'big'), 'dword'))
                    if device.product_id:
                        fp.write(reg_kv('PID', int(device.product_id).to_bytes(4, 'big'), 'dword'))
                    if device.version:
                        fp.write(reg_kv('Version', int(device.version).to_bytes(4, 'big'), 'dword'))
                    fp.write('\r\n')

        # Write the keys REG file.
        with open(output_path / self.KEY_CONFIG_FILENAME, 'w', encoding=encoding) as fp:
            fp.write(self.DEFAULT_BOM)
            fp.write(f'{self.FILE_HEADER}\r\n\r\n')
            key_prefix = '\\'.join(self.REGISTRY_PATH + ['Keys'])
            fp.write(f'[{key_prefix}]\r\n\r\n')

            for adapter_mac, adapter in config.adapters.items():
                adapter_mac_string = adapter.mac_address.bytes.hex()
                fp.write(f'[{key_prefix}\\{adapter_mac_string}]\r\n\r\n')

                for device, key in adapter.devices.items():
                    device_mac_string = device.mac_address.bytes.hex()

                    fp.write(f'[{key_prefix}\\{adapter_mac_string}\\{device_mac_string}]\r\n')
                    fp.write(reg_kv('LTK', key.ltk, 'hex'))
                    fp.write(reg_kv('KeyLength', bytes([0]), 'dword'))
                    fp.write(reg_kv('ERand', key.erand, 'hex(b)'))
                    fp.write(reg_kv('EDIV', key.ediv, 'dword'))

                    if key.irk:
                        fp.write(reg_kv('IRK', key.irk, 'hex'))

                    fp.write(reg_kv('Address', bytes([0, 0]) + device.mac_address.bytes, 'hex(b)'))
                    fp.write(reg_kv('AddressType', bytes([1]), 'dword'))

                    if key.csrk:
                        fp.write(reg_kv('CSRK', key.csrk, 'hex'))
                    if key.counter is not None:
                        counter_int = int(key.counter).to_bytes(4, 'big')
                        fp.write(reg_kv('OutboundSignCounter', counter_int, 'dword'))

                    fp.write('\r\n')
                fp.write('\r\n')


class MacOSBluetoothConfigAdapter(BluetoothConfigAdapter):
    """
    Reads and writes macOS Bluetooth configuration files.
    """
    DEVICE_CONFIG_FILENAME = 'com.apple.Bluetooth.plist'
    KEY_CONFIG_FILENAME = 'com.apple.bluetoothd.plist'

    def read_from_dir(self, input_dir):
        """
        Parse macOS Bluetooth configuration files from the specified directory.

        Parameters
        ----------
        input_dir : str
            Path to the input directory.

        Returns
        -------
        BluetoothConfig
        """
        input_path = Path(input_dir)
        device_config_path = input_path / self.DEVICE_CONFIG_FILENAME
        key_config_path = input_path / self.KEY_CONFIG_FILENAME

        config = BluetoothConfig()
        if not device_config_path.exists():
            raise FileNotFoundError(f'File {device_config_path} not found')
        if not key_config_path.exists():
            raise FileNotFoundError(f'File {key_config_path} not found')

        # Read both .plist files.
        with open(device_config_path, 'rb') as fp:
            device_config_plist = plistlib.load(fp)
        with open(key_config_path, 'rb') as fp:
            key_config_plist = plistlib.load(fp)

        device_cache = device_config_plist['DeviceCache']
        device_cache_devices = {}

        # Parse the device cache file.
        for device_mac_str, device_meta in device_cache.items():
            device_mac = MACAddress.parse(device_mac_str)
            device = BluetoothDevice(
                mac_address=device_mac,
                name=device_meta.get('Name', str(device_mac)),
                vendor_id=device_meta.get('VendorID'),
                product_id=device_meta.get('ProductID'),
                version=None,
                supports_le=any(
                    key
                    for key in device_meta if key.startswith('LowEnergy')
                    and device_meta[key]
                ),
            )
            device_cache_devices[device_mac] = device

        # Parse the key file and match the devices with the ones from the device cache.
        for adapter_mac_str, device_keys in key_config_plist['SMPDistributionKeys'].items():
            adapter = BluetoothAdapter(mac_address=MACAddress.parse(adapter_mac_str))
            config.add_adapter(adapter)

            for device_mac_str, device_meta in device_keys.items():
                device_mac = MACAddress.parse(device_mac_str)
                key = BluetoothKey(
                    ltk=device_meta.get('LTK'),
                    irk=device_meta.get('IRK'),
                    csrk=bytes(16),
                    counter=0,
                    erand=device_meta.get('RAND'),
                    ediv=device_meta.get('EDIV'),
                )
                if device_mac in device_cache_devices:
                    adapter.add_device(device_cache_devices[device_mac], key)

        return config

    def write_to_dir(self, config, output_dir):
        """
        Save macOS configuration files to the specified directory.

        Parameters
        ----------
        config : BluetoothConfig
            Platform-agnostic config model returned by `read_from_dir`.
        output_dir : str
            Path to the output directory. If does not exist, will be created.
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        device_config_path = output_path / self.DEVICE_CONFIG_FILENAME
        key_config_path = output_path / self.KEY_CONFIG_FILENAME

        device_cache = {}
        adapter_config = {}

        for adapter_mac, adapter in config.adapters.items():
            adapter_mac_str = '-'.join(f'{byte:02x}' for byte in adapter_mac.bytes)
            adapter_config[adapter_mac_str] = {}

            for device, key in adapter.devices.items():
                device_mac_str = '-'.join(f'{byte:02x}' for byte in device.mac_address.bytes)
                device_meta = {
                    'Name': device.name,
                }
                if device.vendor_id:
                    device_meta['VendorID'] = device.vendor_id
                if device.product_id:
                    device_meta['ProductID'] = device.product_id

                device_key_config = {
                    'Address': device.mac_address.bytes,
                    'AddressType': 0,
                    'EDIV': key.ediv,
                    'LTK': key.ltk,
                    'LTKLength': bytes([len(key.ltk)]),
                    'OriginalAddressType': 1,
                    'RAND': key.erand,
                    'SecureConnection': bytes([1]),
                }
                if key.irk:
                    device_key_config['IRK'] = key.irk

                device_cache[device_mac_str] = device_meta
                adapter_config[adapter_mac_str][device_mac_str] = device_key_config

        device_config = {
            'DeviceCache': device_cache,
        }
        key_config = {
            'SMPDistributionKeys': adapter_config,
        }

        with open(device_config_path, 'wb') as fp:
            plistlib.dump(device_config, fp, fmt=plistlib.FMT_XML, sort_keys=True)
        with open(key_config_path, 'wb') as fp:
            plistlib.dump(key_config, fp, fmt=plistlib.FMT_XML, sort_keys=True)


def parse_separated_byte_string(text):
    text = re.sub(r'[^0-9a-fA-F]', '', text)
    return bytes.fromhex(text)


def create_adapter(os_code):
    if os_code == 'linux':
        return LinuxBluetoothConfigAdapter()
    elif os_code == 'windows':
        return WindowsBluetoothConfigAdapter()
    elif os_code == 'macos':
        return MacOSBluetoothConfigAdapter()
    raise ValueError('Unknown OS code')


def parse_command_line_args(args):
    """
    Parse the arguments passed via the command line.

    Parameters
    ----------
    args : str
        Raw command line arguments.

    Returns
    -------
    argparse.Namespace
        Parsed command line arguments.
    """
    parser = argparse.ArgumentParser(
        description='Utility to read and convert Bluetooth pairing key configurations across OS.'
    )
    parser.add_argument(
        'source_dir',
        help=(
            'Path to the directory containing Bluetooth configuration files to convert. '
            'The format of the files depends on the source OS'
        )
    )
    parser.add_argument(
        'destination_dir',
        help=(
            'Path to the directory where the converted output will be written. '
            'The format of the files depends on the destination OS'
        )
    )
    parser.add_argument(
        '--source-format',
        help='Source operating system (linux, windows, macos)',
        required=True,
        metavar='FMT',
        choices=['linux', 'windows', 'macos'],
    )
    parser.add_argument(
        '--destination-format',
        help='Destination operating system (linux, windows, macos)',
        required=True,
        metavar='FMT',
        choices=['linux', 'windows', 'macos'],
    )

    parsed_args = parser.parse_args(args)
    return parsed_args


def main():
    parsed_args = parse_command_line_args(sys.argv[1:])

    source_adapter = create_adapter(parsed_args.source_format)
    destination_adapter = create_adapter(parsed_args.destination_format)

    print(f'Reading {parsed_args.source_format} files from "{parsed_args.source_dir}"...')
    config = source_adapter.read_from_dir(parsed_args.source_dir)
    print(f'Writing {parsed_args.destination_format} files to "{parsed_args.destination_dir}"...')
    destination_adapter.write_to_dir(config, parsed_args.destination_dir)
    print('Done')


if __name__ == '__main__':
    main()
