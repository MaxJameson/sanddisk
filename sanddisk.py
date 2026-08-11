#!/usr/bin/env python3

import subprocess
import json
import os
import sys
from fastapi.concurrency import asynccontextmanager
import pyudev
import shutil
import tempfile
from fastapi import FastAPI, logger
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import time
from typing import List, Optional
import shlex
from threading import Thread
import uuid
from fastapi.responses import StreamingResponse
import logging
from enum import Enum
import math
from typing import Optional
from pydantic import BaseModel



DRIVE_PATH = os.getenv("DRIVE_PATH") # Default path if not set

class Device(BaseModel):
    node: str
    number: Optional[str] = None
    fstype: Optional[str] = None
    label: Optional[str] = None
    size: Optional[int] = None
    size_human: Optional[str] = None

class Selection(BaseModel):
    device: Device

class CopyRequest(BaseModel):
    src_folder: str
    dst_folder: str

class scanRequest(BaseModel):
    folder: str

class partitionRequest(BaseModel):
    drive: dict
    partName: str
    fileFormat: str

class jobStates(Enum):
    WIPING = "WIPING"
    IDLE = "IDLE"
    COPYING = "COPYING"
    SCANNING = "SCANNING"
    FORMATTING = "FORMATTING"
    PARTITIONING = "PARTITIONING"

class apiManager:
    def __init__(self):
        self.activityMessage = jobStates.IDLE.value
        self.status = jobStates.IDLE
        self.process = None

global apiObj 
apiObj = apiManager()

global previousStatus
previousStatus = None
global previousMessage
previousMessage = None

def av_scan_parition(device_node):

    mountPoint = get_mountpoint(device_node)
    if not mountPoint:
        logger.error("Device is not mounted; cannot scan with ClamAV. Please mount the device and try again.")
        apiObj.activityMessage = "Scan failed: device not mounted"
        return False
    
    if apiObj.status != jobStates.IDLE:
        logger.error("Another job is currently running. Please wait until it finishes.")
        apiObj.activityMessage = f"Scan failed: another job {apiObj.status.value} is running"
        return False
    else:
        apiObj.status = jobStates.SCANNING
        apiObj.activityMessage = f"Scanning {device_node} for viruses..."

    cmd = ['clamscan', f'-r', mountPoint]
    if os.geteuid() != 0:
        cmd = ['sudo'] + cmd
    logger.info("Running: %s", ' '.join(cmd))
    try:
        apiObj.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
        import re
        last_pass = None
        # Read lines as they arrive and print them; try to extract pass number
        infected_files = 0
        for raw in apiObj.process.stdout:
            line = raw.rstrip('\r\n')
            # Print raw nwipe output so user sees messages
            if "infected files" in line.lower():
                infected_files = int(line.split(":")[-1].strip())
                if infected_files > 0:
                    logger.error(f"Infected files found: {infected_files}")
                else:
                    logger.info("No infected files found.")

            low = line.lower()

        if apiObj.process == None:
            logger.error("Scan Termintated")
            apiObj.status = jobStates.IDLE
            apiObj.activityMessage = "Scan Terminated"
            return False

        ret = apiObj.process.wait()

        if ret == 0:
            logger.info("Scan completed successfully with no infections found.")
            apiObj.status = jobStates.IDLE
            apiObj.activityMessage = "Scan complete: no infections found"
            return True
        if ret == 1:
            logger.error(f"Scan completed with infections found: {infected_files} infected files.")
            apiObj.status = jobStates.IDLE
            apiObj.activityMessage = f"Scan complete: {infected_files} infected files found"
            return False
        elif ret == -9:
            apiObj.activityMessage = "Scan cancelled"
            logger.info("Scan was cancelled by the user.")
            apiObj.status = jobStates.IDLE
            return False
        else:
            logger.error("Scan completed with non-zero exit code: %d", ret)
            apiObj.status = jobStates.IDLE
            apiObj.activityMessage = "Scan completed with issues"
            return False

    except Exception as e:
        logger.error("Scan Termintated: %s", e)
        apiObj.status = jobStates.IDLE
        apiObj.activityMessage = "Scan Terminated"
        return False

def av_scan_folder(folder_path):

    
    if apiObj.status != jobStates.IDLE:
        logger.error("Another job is currently running. Please wait until it finishes.")
        apiObj.activityMessage = f"Scan failed: another job {apiObj.status.value} is running"
        return False
    else:
        apiObj.status = jobStates.SCANNING
        apiObj.activityMessage = f"Scanning {folder_path} for viruses..."

    cmd = ['clamscan', f'-r', folder_path]
    if os.geteuid() != 0:
        cmd = ['sudo'] + cmd
    logger.info("Running: %s", ' '.join(cmd))
    try:
        apiObj.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
        import re
        last_pass = None
        # Read lines as they arrive and print them; try to extract pass number
        infected_files = 0
        for raw in apiObj.process.stdout:
            line = raw.rstrip('\r\n')
            # Print raw nwipe output so user sees messages
            if "infected files" in line.lower():
                infected_files = int(line.split(":")[-1].strip())
                if infected_files > 0:
                    logger.error(f"Infected files found: {infected_files}")
                else:
                    logger.info("No infected files found.")
            
            low = line.lower()

        if apiObj.process == None:
            logger.error("Scan Termintated")
            apiObj.status = jobStates.IDLE
            apiObj.activityMessage = "Scan Terminated"
            return False

        ret = apiObj.process.wait()

        if ret == 0:
            logger.info("Scan completed successfully with no infections found.")
            apiObj.status = jobStates.IDLE
            apiObj.activityMessage = "Scan complete: no infections found"
            return True
        if ret == 1:
            logger.error(f"Scan completed with infections found: {infected_files} infected files.")
            apiObj.status = jobStates.IDLE
            apiObj.activityMessage = f"Scan complete: {infected_files} infected files found"
            return False
        elif ret == -9:
            apiObj.activityMessage = "Scan cancelled"
            logger.info("Scan was cancelled by the user.")
            apiObj.status = jobStates.IDLE
            return False
        else:
            logger.error("Scan completed with non-zero exit code: %d", ret)
            apiObj.status = jobStates.IDLE
            apiObj.activityMessage = "Scan completed with issues"
            return False

    except Exception as e:
        logger.error("Scan Termintated: %s", e)
        apiObj.status = jobStates.IDLE
        apiObj.activityMessage = "Scan Terminated"
        return False


def _entropy(data: bytes) -> float:
    """Shannon entropy (0 = uniform, 8 = fully random for bytes)."""
    if not data:
        return 0.0

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    ent = 0.0
    length = len(data)

    for count in freq:
        if count:
            p = count / length
            ent -= p * math.log2(p)

    return ent

def audit_passed(result):
    return (
        result["filesystem_detected"] is None
        and not result["has_nonzero_data"]
        and all(e <= 0.5 for e in result["entropy_samples"])
        and result["all_zero_start"]
    )

def audit_disk(device, sample_size=1024 * 1024, samples=5):
    """
    Audit a disk/partition:
      - checks filesystem presence
      - checks zeroed regions
      - computes entropy across samples

    Returns dict with results.
    """
    logger.info(f"Auditing device {device} with sample size {sample_size} and {samples} samples.")

    result = {
        "device": device,
        "filesystem_detected": None,
        "has_nonzero_data": False,
        "entropy_samples": [],
        "all_zero_start": False,
    }

    # --- 1. filesystem detection (blkid) ---
    try:
        blkid_out = subprocess.check_output(
            ["blkid", "-o", "value", "-s", "TYPE", device],
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()
        result["filesystem_detected"] = blkid_out if blkid_out else None
    except Exception:
        result["filesystem_detected"] = None

    # --- 2. open device ---
    size = os.stat(device).st_size if os.path.exists(device) else None

    with open(device, "rb") as f:

        for i in range(samples):
            if size:
                offset = int((size / samples) * i)
                f.seek(offset)

            data = f.read(sample_size)

            if not data:
                continue

            # --- zero check ---
            if any(b != 0 for b in data):
                result["has_nonzero_data"] = True

            # --- entropy ---
            ent = _entropy(data)
            result["entropy_samples"].append(ent)

            # --- first sample zero check ---
            if i == 0:
                result["all_zero_start"] = all(b == 0 for b in data)

    
    logger.info(f"Audit result for {device}: {json.dumps(result, indent=2)}")

    return result,audit_passed(result)

def get_mountpoint(device):
    """Return mountpoint for a device (e.g. /dev/sdb1) if mounted, else None.

    Parses /proc/mounts to find the mountpoint for the given device node.
    """
    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == device:
                    return parts[1]
    except Exception:
        pass
    return None



def _human_size(num_bytes):
    """Convert a byte count to a human-readable string.

    Args:
        num_bytes (int|float): Number of bytes to format.

    Returns:
        str: Human readable size string (e.g. "1.23 GB").

    Notes:
        Uses 1024 base for unit conversion and returns 'PB' for very large values.
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} PB"

def _is_usb_device(device):
    current = device

    while current is not None:
        if current.subsystem == "usb":
            return True

        if current.properties.get("ID_BUS") == "usb":
            return True

        current = current.parent

    return False

def get_usb_drives():
    """Discover USB-connected block devices and return metadata."""
    context = pyudev.Context()
    drives = []

    for device in context.list_devices(subsystem="block", DEVTYPE="disk"):
        if not device.device_node:
            continue

        # Skip non-USB devices
        if not _is_usb_device(device):
            continue

        devnode = device.device_node

        # Read size from sysfs (512-byte sectors)
        size_bytes = None
        try:
            base = os.path.basename(devnode)
            with open(f"/sys/block/{base}/size") as f:
                sectors = int(f.read().strip())
            size_bytes = sectors * 512
        except Exception:
            pass

        drives.append({
            "node": devnode,
            "vendor": device.properties.get("ID_VENDOR"),
            "model": device.properties.get("ID_MODEL"),
            "serial": (
                device.properties.get("ID_SERIAL_SHORT")
                or device.properties.get("ID_SERIAL")
            ),
            "size": size_bytes,
            "size_human": _human_size(size_bytes),
        })

    return drives


def choose_drive(drives):
    """Prompt user to select one drive from a list.

    Args:
        drives (list[dict]): List of drive dicts as returned by get_usb_drives().

    Returns:
        dict|None: Selected drive dict or None if the user quits.

    Notes:
        Prints a numbered list and accepts a numeric choice; accepts 'q' to quit.
    """
    if not drives:
        logger.info("No USB drives found.")
        return None
    logger.info("Available USB drives:")
    for i, d in enumerate(drives, start=1):
        logger.info(f"{i}) {d['node']}  {d.get('vendor','')} {d.get('model','')}  Size: {d['size_human']}")
        # show partitions for this drive (if any)
        try:
            parts = get_partitions(d['node'])
        except Exception:
            parts = []
        if parts:
            for p in parts:
                label = p.get('label') or ''
                fstype = p.get('fstype') or ''
                logger.info(f"    - {label} {fstype}  Size: {p['size_human']}")

    while True:
        choice = input(f"Select a drive [1-{len(drives)}] or 'q' to quit: ").strip()
        if choice.lower() in ('q', 'quit', 'exit'):
            return None
        if not choice.isdigit():
            logger.info("Please enter a number.")
            continue
        idx = int(choice) - 1
        if 0 <= idx < len(drives):
            return drives[idx]
        logger.info("Selection out of range.")


def get_partitions(drive_node):
    """Return partition metadata for partitions on a given drive.

    Args:
        drive_node (str): The parent drive node (e.g. '/dev/sdb').

    Returns:
        list[dict]: Partition dictionaries with keys:
            - node (str): partition node (e.g. '/dev/sdb1')
            - number (str|None): partition number if available
            - fstype (str|None)
            - label (str|None)
            - size (int|None): bytes
            - size_human (str)
    """
    context = pyudev.Context()
    parts = []
    for device in context.list_devices(subsystem='block', DEVTYPE='partition'):
        devnode = device.device_node
        if not devnode:
            continue
        # match partitions that belong to the drive (e.g. /dev/sdb1 startswith /dev/sdb)
        if not devnode.startswith(drive_node):
            continue
        size_bytes = None
        try:
            base = os.path.basename(devnode)
            with open(f"/sys/class/block/{base}/size", "r") as f:
                sectors = int(f.read().strip())
                size_bytes = sectors * 512
        except Exception:
            size_bytes = None
        parts.append({
            'node': devnode,
            'number': device.get('PARTN'),
            'fstype': device.get('ID_FS_TYPE'),
            'label': device.get('ID_FS_LABEL') or device.get('ID_PART_ENTRY_NAME'),
            'size': size_bytes,
            'size_human': _human_size(size_bytes) if size_bytes else 'Unknown',
        })
    return parts


def choose_partition(parts):
    """Prompt user to select a partition from a list.

    Args:
        parts (list[dict]): List of partition dicts as returned by get_partitions.

    Returns:
        dict|None: Selected partition dict or None if user quits.
    """
    if not parts:
        logger.info("No partitions found on the selected drive.")
        return None
    logger.info("Available partitions:")
    for i, p in enumerate(parts, start=1):
        logger.info(f"{i}) {p.get('label','')} {p.get('fstype','')}  Size: {p['size_human']}")
    while True:
        choice = input(f"Select a partition [1-{len(parts)}] or 'q' to quit: ").strip()
        if choice.lower() in ('q', 'quit', 'exit'):
            return None
        if not choice.isdigit():
            logger.info("Please enter a number.")
            continue
        idx = int(choice) - 1
        if 0 <= idx < len(parts):
            return parts[idx]
        logger.info("Selection out of range.")


def _mkfs_command_for(fs_type, device, label=None):
    """Build the mkfs command list for a given filesystem type.

    Args:
        fs_type (str): Filesystem type, e.g. 'ext4', 'vfat', 'exfat', 'ntfs'.
        device (str): block device node to format (e.g. '/dev/sdb1').
        label (str|None): optional filesystem label to set.

    Returns:
        list[str]: Command and arguments to run (not joined).

    Notes:
        The caller should prepend 'sudo' if required.
    """
    # build an appropriate mkfs command for common filesystems
    if fs_type in ('vfat', 'fat', 'fat32'):
        cmd = ['mkfs.vfat']
        if label:
            cmd += ['-n', label]
        cmd += [device]
    elif fs_type in ('ntfs',):
        cmd = ['mkfs.ntfs', '-F']
        if label:
            cmd += ['-L', label]
        cmd += [device]
    elif fs_type in ('exfat', 'exfatfs'):
        # mkfs.exfat (from exfatprogs) does not accept uppercase -F; use -L for label
        cmd = ['mkfs.exfat']
        if label:
            cmd += ['-L', label]
        cmd += [device]
    else:
        # default to mkfs.<type>
        cmd = [f'mkfs.{fs_type}']
        if label:
            cmd += ['-L', label]
        # some mkfs variants require -F to force; include it for safety
        cmd += ['-F', device]
    return cmd


def get_mounted_devices():
    """Return device nodes currently mounted by parsing /proc/mounts.

    Returns:
        list[str]: list of mounted source device nodes (first column of /proc/mounts).
    """
    mounts = []
    try:
        with open('/proc/mounts', 'r') as f:
            for line in f:
                parts = line.split()
                if parts:
                    mounts.append(parts[0])
    except Exception:
        pass
    return mounts


def is_mounted(node):
    """Return True if the given device node or any of its partitions is mounted.

    Args:
        node (str): device node (e.g. '/dev/sdb' or '/dev/sdb1').

    Returns:
        bool: True if mounted, False otherwise.
    """
    mounts = get_mounted_devices()
    for m in mounts:
        if m == node or m.startswith(node):
            return True
    return False


def unmount_devices_for(node):
    """Attempt to unmount any mounted nodes that match the given node.

    Args:
        node (str): device node to unmount partitions for.

    Returns:
        bool: True if there were no mounts or all unmounts succeeded; False on error.
    """
    mounts = get_mounted_devices()
    to_unmount = [m for m in mounts if m == node or m.startswith(node)]
    if not to_unmount:
        logger.info("No unmount required")
        return True
    logger.info("Device mounted, unmounting")
    for m in to_unmount:
        cmd = ['umount', m]
        if os.geteuid() != 0:
            cmd = ['sudo'] + cmd
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            logger.error("Failed to unmount")
            return False
    logger.info("Unount successfull")
    return True


def format_drive(device_node, fs_type='ext4', label=None, apiCheck=True):
    """Format the given device node with the chosen filesystem.

    Returns True on success, False otherwise.
    """
    if apiCheck:
        if apiObj.status != jobStates.IDLE:
            logger.info("Another job is currently running. Please wait until it finishes.")
            return False
        else:
            apiObj.status = jobStates.FORMATTING

    apiObj.activityMessage = f"Formatting {device_node} as {fs_type}..."

    # Check for mounted partitions/devices first
    if is_mounted(device_node):
        if not unmount_devices_for(device_node):
            if apiCheck:
                apiObj.status = jobStates.IDLE
            return False

    logger.info(f"About to format {device_node} as {fs_type}.")
    cmd = _mkfs_command_for(fs_type, device_node, label)
    if os.geteuid() != 0:
        cmd = ['sudo'] + cmd
    logger.info("Running: format")
    try:
        subprocess.run(cmd, check=True)
        logger.info("Formatting finished.")
        if apiCheck:
            apiObj.status = jobStates.IDLE
        apiObj.activityMessage = "Formatting complete"
        return True
    except subprocess.CalledProcessError as e:
        # need to log this
        logger.error("Formatting failed:", e)
        if apiCheck:
            apiObj.status = jobStates.IDLE
        apiObj.activityMessage = "Formatting failed"
        return False


def run_nwipe(device_node, method='is5enh', orig_fs=None, orig_label=None):

    if apiObj.status != jobStates.IDLE:
        logger.error("Another job is currently running. Please wait until it finishes.")
        return False
    
    apiObj.status = jobStates.WIPING
    apiObj.activityMessage = "Initialising wipe..."
    """Run nwipe on the given device and stream its text output.

    Requires --nogui/--autonuke for parseable text output. Prints nwipe lines live
    and shows the current pass number when detected.
    """
    if is_mounted(device_node):
        if not unmount_devices_for(device_node):
            apiObj.status = jobStates.IDLE
            apiObj.activityMessage = "Wipe failed: unable to unmount device"
            logger.error("Unable to unmount device for wiping.")
            return False

    nwipe = shutil.which('nwipe')
    if not nwipe:
        apiObj.status = jobStates.IDLE
        apiObj.activityMessage = "nwipe not found. Install nwipe to use secure wipe (e.g. sudo apt install nwipe)."
        logger.error("nwipe not found. Install nwipe to use secure wipe (e.g. sudo apt install nwipe).")
        return False

    apiObj.activityMessage = "Initialising wipe..."

    logger.info("Running: wipe")
    try:

        cmd = [
            "stdbuf",
            "-oL",   # line-buffer stdout
            "-eL",   # line-buffer stderr
            nwipe,
            f"--method={method}",
            "--verify=all",
            "--nogui",
            "--autonuke",
            device_node,
        ]

        if os.geteuid() != 0:
            cmd = ["sudo"] + cmd

        apiObj.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        import re
        last_pass = None
        # Read lines as they arrive and print them; try to extract pass number.
        while True:
            raw = apiObj.process.stdout.readline()
            if not raw:
                break
            line = raw.rstrip('\r\n')
            # Print raw nwipe output so user sees messages
            low = line.lower()
            # Detect final-random-pattern message and print a concise status
            logger.info(line)
            if 'blanking device' in low:
                apiObj.activityMessage = "Wiping in progress... (blanking device)"
                logger.info("NWipe: blanking device")
                continue

            if 'verifying that' in low:
                apiObj.activityMessage = "Wiping in progress... (verifying)"
                logger.info("NWipe: verifying that device is wiped")
                continue

            if 'waiting for wipe thread to cancel for' in low:
                logger.info("NWipe: waiting for wipe thread to cancel")
                apiObj.activityMessage = "Wiping complete, finishing up..."
                continue

            # Try to parse "pass" number from common nwipe text lines
            m = re.search(r'pass[:\s]*([0-9]+)', line, re.I) or re.search(r'Pass[:\s]*([0-9]+)', line, re.I)
            if not m:
                # Some versions print "Pass X/Y" or "X/Y passes"
                m = re.search(r'(\d+)\s*/\s*\d+\s+pass', line, re.I) or re.search(r'Pass\s+(\d+)\s*/\s*\d+', line, re.I)
            if m:
                try:
                    p = int(m.group(1))
                    if p != last_pass:
                        last_pass = p
                        apiObj.activityMessage = f"Wiping in progress... (pass {p})"
                        logger.info(f"NWipe: currently on pass {p}")
                except Exception:
                    pass

        if apiObj.process == None:
            logger.error("Wipe Termintated")
            apiObj.status = jobStates.IDLE
            apiObj.activityMessage = "Wipe Terminated"
            return False

        ret = apiObj.process.wait()

        if ret == 0:
            apiObj.activityMessage = "Wipe finished. Auditing device..."
            audit_result,audit_passed = audit_disk(device_node)

            # log this to a file somewhere
            logger.info("Audit result after wipe: %s", json.dumps(audit_result, indent=2))

            if audit_passed:
                apiObj.activityMessage = "Wipe successful"
            else:
                apiObj.activityMessage = "Wipe completed but audit failed"
            # After a destructive wipe the filesystem and label are gone — recreate them.
            logger.info(f"Restoring filesystem {orig_fs} and label {orig_label!s} on {device_node} ...")
            ok = format_drive(device_node, fs_type=orig_fs, label=orig_label,apiCheck=False)
            if not ok:
                logger.error("Failed to restore filesystem/label after wipe.")
                return False
            apiObj.status = jobStates.IDLE
            logger.info("Wipe and audit completed successfully.")
            return audit_passed
        elif ret == -9:
            apiObj.activityMessage = "Wipe cancelled"
            logger.info("Wipe was cancelled by the user.")
            apiObj.status = jobStates.IDLE
            return False
        else:
            apiObj.activityMessage = "Wipe failed"
            # need to log this
            logger.error("Wipe failed, exit code: %d", ret)
            apiObj.status = jobStates.IDLE
            return False
    except Exception as e:
        apiObj.activityMessage = "Wipe Terminted"
        # need to log this
        logger.error("Wipe terminated:", e)
        apiObj.status = jobStates.IDLE
        return False

def drives_No_Paritions():
    drives = get_usb_drives()
    emptyDrives = []

    for d in drives:
        try:
            parts = get_partitions(d['node'])
        except Exception:
            parts = []
        if not parts:
            emptyDrives.append(d)
    return emptyDrives

def partition_Drive(drive,partName,fileFormat='ext4'):

    if apiObj.status != jobStates.IDLE:
        logger.error("Another job is currently running. Please wait until it finishes.")
        return False
    
    apiObj.status = jobStates.PARTITIONING
    apiObj.activityMessage = "Initialising partitioning..."
    logger.info(f"Partitioning drive {drive['node']} with partition name: {partName}")

    try:
    
        filesystem_label = partName.upper()
        disk = drive['node']
        def run(cmd):
            subprocess.run(cmd, check=True)

        # Create a new GPT partition table
        apiObj.activityMessage = "Creating new GPT partition table..."
        run(["sudo", "parted", "-s", disk, "mklabel", "gpt"])

        # Create a 4 GiB partition
        apiObj.activityMessage = "Creating 4 GiB partition..."
        run([
            "sudo", "parted", "-s",
            disk,
            "mkpart",
            "primary",
            fileFormat,
            "1MiB",
            "4097MiB",
        ])

        # Name the partition
        apiObj.activityMessage = "Naming partition..."
        run([
            "sudo", "parted", "-s",
            disk,
            "name",
            "1",
            partName,
        ])

        # Notify the kernel of the partition table change
        apiObj.activityMessage = "Notifying kernel of partition table change..."
        run(["sudo", "partprobe", disk])

        partition = f"{disk}1"

        # Optionally format it
        if filesystem_label:
            run([
                "sudo",
                "mkfs." + fileFormat,
                "-F",
                "-L",
                filesystem_label,
                partition,
            ])

        apiObj.status = jobStates.IDLE
        apiObj.activityMessage = "Drive partitioned successfully"
        logger.info(f"Partition created successfully: {partition} with label {filesystem_label}")

        return True

    except Exception as e:
        apiObj.status = jobStates.IDLE
        apiObj.activityMessage = "Partitioning failed"
        logger.error("Error occurred while partitioning drive: %s", e)
        return False

def localWipeLogic():
    """
    Main logic for local wipe operation.
    """
    drives = get_usb_drives()
    picked = choose_drive(drives)
    if not picked:
        sys.exit(0)

    partitions = get_partitions(picked['node'])
    if not partitions:
        # No partitions: treat the whole drive as the selected device
        chosen_part = {
            'node': picked['node'],
            'number': None,
            'fstype': None,
            'label': None,
            'size': picked.get('size'),
            'size_human': picked.get('size_human'),
        }
        print(f"No partitions found on {picked['node']}; using whole device.")
    else:
        chosen_part = choose_partition(partitions)
        if not chosen_part:
            print("No partition selected. Exiting.")
            sys.exit(0)

    print("Selected partition/device:", chosen_part)

    # save original detected fs/label so we can restore them after wipe
    orig_fs = chosen_part.get('fstype') or 'ext4'
    orig_label = chosen_part.get('label') or None

    if not run_nwipe(chosen_part['node'], orig_fs=orig_fs, orig_label=orig_label):
        print("Wipe failed or was cancelled. Exiting.")
        sys.exit(1)


def find_media_name(drive):
    result = subprocess.run(
        ["findmnt", "-n", "-o", "TARGET", drive],
        capture_output=True,
        text=True
        )

    return result.stdout.strip()


app = FastAPI()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Runs on startup
    if os.geteuid() != 0:
        print("This application must be run as root (sudo).")
        sys.exit(1)
    yield  # app runs here


app = FastAPI(lifespan=lifespan)

# Enable CORS for development/testing so the Test Site page can fetch the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger = logging.getLogger("uvicorn")

file_handler = logging.FileHandler("sanddisk.log")
file_handler.setLevel(logging.INFO)

formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s"
)
file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

logger.info("\n=====================================\n\nAPPLICATION STARTED\n\n=====================================")

@app.get("/drives")
def read_drives():
    """
    Get a list of USB drives.
    """
    logger.info("Fetching USB drives")
    return get_usb_drives()

@app.get("/drives_with_partitions")
def read_drives_with_partitions():
    """Return USB drives with their detected partitions.

    Each drive dict will include a 'partitions' key containing a list of
    partition dicts as returned by get_partitions().
    """
    logger.info("Fetching drives with partitions")
    drives = get_usb_drives()
    for d in drives:
        try:
            d['partitions'] = get_partitions(d['node'])
        except Exception:
            d['partitions'] = []
    logger.info(f"Found drives with partitions: {drives}")
    return drives



@app.post("/select_partition")
def select_partition(selection: Selection):
    """Receive a selected partition/device from the web UI.

    This endpoint currently echoes back the device node. It can be extended
    to trigger formatting/wiping operations as needed.
    """
    logger.info(f"Received partition selection: {selection.device.node}")
    return {"selected": selection.device}

@app.post("/wipe_device")
def wipe_device(selection: Selection):
    device = selection.device

    orig_fs = device.fstype or "ext4"
    orig_label = device.label

    logger.info(f"Received request to wipe device: {device.node}")

    if not run_nwipe(
        device.node,
        orig_fs=orig_fs,
        orig_label=orig_label
    ):
        logger.error(f"Wipe initiation failed for device: {device.node}")
        return {"status": "wipe failed to start"}

    logger.info(f"Wipe started for device: {device.node}")
    return {"status": "wipe started"}

@app.post("/scan_device")
def scan_device(selection: Selection):
    device = selection.device

    logger.info(f"Received request to scan device: {device.node}")

    if not av_scan_parition(device.node):
        return {"status": "scan failed or infections found"}
    logger.info(f"Scan completed successfully for device: {device.node}")
    return {"status": "scan complete, no infections found"}

@app.post("/scan_folder")
def scan_folder(req: scanRequest):

    if DRIVE_PATH is None:
        logger.error("DRIVE_PATH is not set. Cannot scan folder.")
        return {"status": "error", "message": "DRIVE_PATH is not set"}

    folder_path = os.path.join(DRIVE_PATH, req.folder)

    logger.info(f"Received request to scan folder: {folder_path}")

    if not av_scan_folder(folder_path):
        return {"status": "scan failed or infections found"}
    logger.info(f"Scan completed successfully for folder: {folder_path}")
    return {"status": "scan complete, no infections found"}

# modify copy_device to create job and monitor
@app.post("/copy_device")
def copy_device(req: CopyRequest):

    if DRIVE_PATH is None:
        logger.error("DRIVE_PATH is not set. Cannot copy folder.")
        return {"status": "error", "message": "DRIVE_PATH is not set"}
    
    logger.info(f"Received request to copy from {req.src_folder} to {req.dst_folder}")
    src_path = os.path.join(DRIVE_PATH, req.src_folder)
    dst_path = os.path.join(DRIVE_PATH, req.dst_folder)

    if not os.path.isdir(src_path):
        return {"status": "error", "message": "Source folder not found"}

    if not os.path.isdir(dst_path):
        return {"status": "error", "message": "Destination folder not found"}

    try:
        apiObj.status = jobStates.COPYING
        apiObj.activityMessage = "Copy in progress..."

        for item in os.listdir(src_path):

            source = os.path.join(src_path, item)
            dest = os.path.join(dst_path, item)

            if os.path.isdir(source):
                shutil.copytree(
                    source,
                    dest,
                    dirs_exist_ok=True
                )
            else:
                shutil.copy2(
                    source,
                    dest
                )

        apiObj.activityMessage = "Copy complete"
        apiObj.status = jobStates.IDLE

        logger.info(f"Copy from {src_path} to {dst_path} completed successfully.")
        return {"status": "copy complete"}

    except Exception as e:
        apiObj.status = jobStates.IDLE
        apiObj.activityMessage = "Copy failed"
        logger.error(f"Copy from {src_path} to {dst_path} failed: {e}")
        return {
            "status": "copy failed",
            "error": str(e)
        }
    

@app.get('/status')
def get_status():
    global previousStatus
    global previousMessage

    if  apiObj.status.value != previousStatus or previousMessage != apiObj.activityMessage:
        logger.info(f"Status changed: {apiObj.status.value}, message: {apiObj.activityMessage}")
        previousStatus = apiObj.status.value
        previousMessage = apiObj.activityMessage

    return {"status": apiObj.status.value, "activityMessage": apiObj.activityMessage}   

@app.get("/folders")
def get_folders():


    if DRIVE_PATH is None:
        logger.error("DRIVE_PATH is not set. Cannot get folders.")
        return {"status": "error", "message": "DRIVE_PATH is not set"}

    folders = []
    logger.info(f"Looking for folders in {DRIVE_PATH}")
    for item in os.listdir(DRIVE_PATH):
        full_path = os.path.join(DRIVE_PATH, item)

        if os.path.isdir(full_path):
            folders.append(item)

    logger.info(f"Found folders: {folders}")
    return folders

@app.get("/kill_process")
def killProcesss():
    if apiObj.process and apiObj.process.poll() is None:
        logger.info("Terminating ongoing process (this may take a moment)...")
        apiObj.process.kill()
        apiObj.process.wait()
        apiObj.process = None
        apiObj.status = jobStates.IDLE
        apiObj.activityMessage = "Process terminated"
    else:
        logger.info("No ongoing process to terminate.")
        apiObj.status = jobStates.IDLE
        apiObj.activityMessage = "No process running"

@app.get("/empty_drives")
def emptyDrives():
    drives = drives_No_Paritions()
    return drives   


@app.post("/partition_drive")
def partitionDrive(partitionReq: partitionRequest):
    drive = partitionReq.drive
    partName = partitionReq.partName
    fileFormat = partitionReq.fileFormat

    logger.info(f"Received request to partition drive: {drive['node']} with partition name: {partName}")

    partition = partition_Drive(drive, partName, fileFormat)
    if partition:
        logger.info(f"Partition created successfully: {partition}")
        return {"status": "partition created", "partition": partition}
    else:
        logger.error(f"Partitioning failed for drive: {drive['node']}")
        return {"status": "partitioning failed", "error": "Unable to create partition"}
