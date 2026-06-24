#!/usr/bin/env python3

import subprocess
import json
import os
import sys
import pyudev
import shutil
import tempfile
from fastapi import FastAPI
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
    number: str
    fstype: str | None = None
    label: str | None = None
    size: int
    size_human: str

class Selection(BaseModel):
    device: Device

class CopyRequest(BaseModel):
    src_folder: str
    dst_folder: str


class jobStates(Enum):
    WIPING = "WIPING"
    IDLE = "IDLE"
    COPYING = "COPYING"
    SCANNING = "SCANNING"
    FORMATTING = "FORMATTING"

class apiManager:
    def __init__(self):
        self.activityMessage = jobStates.IDLE.value
        self.status = jobStates.IDLE

global apiObj 
apiObj = apiManager()

def av_scan(device_node):

    mountPoint = get_mountpoint(device_node)
    if not mountPoint:
        print("Device is not mounted; cannot scan with ClamAV. Please mount the device and try again.")
        return False
    
    if apiObj.status != jobStates.IDLE:
        print("Another job is currently running. Please wait until it finishes.")
        return False
    else:
        apiObj.status = jobStates.SCANNING
        apiObj.activityMessage = f"Scanning {device_node} for viruses..."

    cmd = ['clamscan', f'-r', mountPoint]
    if os.geteuid() != 0:
        cmd = ['sudo'] + cmd
    print("Running:", ' '.join(cmd))
    try:
        proc = subprocess.Popen(
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
        for raw in proc.stdout:
            line = raw.rstrip('\r\n')
            # Print raw nwipe output so user sees messages
            if "infected files" in line.lower():
                infected_files = int(line.split(":")[-1].strip())
                print(f"Infected files found: {infected_files}")

            low = line.lower()
        ret = proc.wait()

        if ret == 0:
            print("Scan completed successfully with no infections found.")
            apiObj.status = jobStates.IDLE
            apiObj.activityMessage = "Scan complete: no infections found"
            return True
        if ret == 1:
            print(f"Scan completed with infections found: {infected_files} infected files.")
            apiObj.status = jobStates.IDLE
            apiObj.activityMessage = f"Scan complete: {infected_files} infected files found"
            return False
        else:
            print("Scan completed with non-zero exit code", ret)
            apiObj.status = jobStates.IDLE
            apiObj.activityMessage = "Scan completed with issues"
            return False

    except Exception as e:
        print("Scan failed:", e)
        apiObj.status = jobStates.IDLE
        apiObj.activityMessage = "Scan failed"
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
        print("No USB drives found.")
        return None
    print("Available USB drives:")
    for i, d in enumerate(drives, start=1):
        print(f"{i}) {d['node']}  {d.get('vendor','')} {d.get('model','')}  Size: {d['size_human']}")
        # show partitions for this drive (if any)
        try:
            parts = get_partitions(d['node'])
        except Exception:
            parts = []
        if parts:
            for p in parts:
                label = p.get('label') or ''
                fstype = p.get('fstype') or ''
                print(f"    - {label} {fstype}  Size: {p['size_human']}")

    while True:
        choice = input(f"Select a drive [1-{len(drives)}] or 'q' to quit: ").strip()
        if choice.lower() in ('q', 'quit', 'exit'):
            return None
        if not choice.isdigit():
            print("Please enter a number.")
            continue
        idx = int(choice) - 1
        if 0 <= idx < len(drives):
            return drives[idx]
        print("Selection out of range.")


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
        print("No partitions found on the selected drive.")
        return None
    print("Available partitions:")
    for i, p in enumerate(parts, start=1):
        print(f"{i}) {p.get('label','')} {p.get('fstype','')}  Size: {p['size_human']}")
    while True:
        choice = input(f"Select a partition [1-{len(parts)}] or 'q' to quit: ").strip()
        if choice.lower() in ('q', 'quit', 'exit'):
            return None
        if not choice.isdigit():
            print("Please enter a number.")
            continue
        idx = int(choice) - 1
        if 0 <= idx < len(parts):
            return parts[idx]
        print("Selection out of range.")


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
        return True
    print("Mounted devices found:", ', '.join(to_unmount))
    for m in to_unmount:
        cmd = ['umount', m]
        if os.geteuid() != 0:
            cmd = ['sudo'] + cmd
        print("Running:", ' '.join(cmd))
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print("Failed to unmount", m, ":", e)
            return False
    return True


def format_drive(device_node, fs_type='ext4', label=None, apiCheck=True):
    """Format the given device node with the chosen filesystem.

    Returns True on success, False otherwise.
    """
    if apiCheck:
        if apiObj.status != jobStates.IDLE:
            print("Another job is currently running. Please wait until it finishes.")
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

    print(f"About to format {device_node} as {fs_type}.")
    cmd = _mkfs_command_for(fs_type, device_node, label)
    if os.geteuid() != 0:
        cmd = ['sudo'] + cmd
    print("Running:", ' '.join(cmd))
    try:
        subprocess.run(cmd, check=True)
        print("Formatting finished.")
        if apiCheck:
            apiObj.status = jobStates.IDLE
        apiObj.activityMessage = "Formatting complete"
        return True
    except subprocess.CalledProcessError as e:
        # need to log this
        print("Formatting failed:", e)
        if apiCheck:
            apiObj.status = jobStates.IDLE
        apiObj.activityMessage = "Formatting failed"
        return False


def run_nwipe(device_node, method='is5enh', orig_fs=None, orig_label=None):

    if apiObj.status != jobStates.IDLE:
        print("Another job is currently running. Please wait until it finishes.")
        return False
    
    apiObj.status = jobStates.WIPING
    apiObj.activityMessage = "Starting wipe..."
    """Run nwipe on the given device and stream its text output.

    Requires --nogui/--autonuke for parseable text output. Prints nwipe lines live
    and shows the current pass number when detected.
    """
    if is_mounted(device_node):
        if not unmount_devices_for(device_node):
            apiObj.status = jobStates.IDLE
            apiObj.activityMessage = "Wipe failed: unable to unmount device"
            return False

    nwipe = shutil.which('nwipe')
    if not nwipe:
        apiObj.status = jobStates.IDLE
        apiObj.activityMessage = "nwipe not found. Install nwipe to use secure wipe (e.g. sudo apt install nwipe)."
        return False

    apiObj.activityMessage = "Wiping in progress..."
    cmd = [nwipe, f'--method={method}', '--verify=all', '--nogui', '--autonuke', device_node]
    if os.geteuid() != 0:
        cmd = ['sudo'] + cmd

    print("Running:", ' '.join(cmd))
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
        import re
        last_pass = None
        # Read lines as they arrive and print them; try to extract pass number.
        for raw in proc.stdout:
            line = raw.rstrip('\r\n')
            # Print raw nwipe output so user sees messages

            low = line.lower()
            # Detect final-random-pattern message and print a concise status
            if 'blanking device' in low:
                print(low)
                apiObj.activityMessage = "Wiping in progress... (blanking device)"
                continue

            if 'verifying that' in low:
                print(low)
                apiObj.activityMessage = "Wiping in progress... (verifying)"
                continue

            if 'waiting for wipe thread to cancel for' in low:
                print(low)
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
                        print(f"NWipe: currently on pass {p}")
                except Exception:
                    pass
        ret = proc.wait()

        if ret == 0:
            apiObj.activityMessage = "Wipe finished. Auditing device..."
            audit_result,audit_passed = audit_disk(device_node)

            # log this to a file somewhere
            print("Audit result after wipe:", json.dumps(audit_result, indent=2))

            if audit_passed:
                apiObj.activityMessage = "Wipe successful"
            else:
                apiObj.activityMessage = "Wipe completed but audit failed"
            # After a destructive wipe the filesystem and label are gone — recreate them.
            print(f"Restoring filesystem {orig_fs} and label {orig_label!s} on {device_node} ...")
            ok = format_drive(device_node, fs_type=orig_fs, label=orig_label,apiCheck=False)
            if not ok:
                print("Failed to restore filesystem/label after wipe.")
                return False
            apiObj.status = jobStates.IDLE
            return audit_passed
        else:
            apiObj.activityMessage = "Wipe failed"
            # need to log this
            print("Wipe failed, exit code", ret)
            apiObj.status = jobStates.IDLE
            return False
    except Exception as e:
        apiObj.activityMessage = "Wipe failed"
        # need to log this
        print("Wipe failed:", e)
        apiObj.status = jobStates.IDLE
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


# Enable CORS for development/testing so the Test Site page can fetch the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger = logging.getLogger("uvicorn")

logger.info("Application started")

@app.get("/drives")
def read_drives():
    """
    Get a list of USB drives.
    """
    return get_usb_drives()

@app.get("/drives_with_partitions")
def read_drives_with_partitions():
    """Return USB drives with their detected partitions.

    Each drive dict will include a 'partitions' key containing a list of
    partition dicts as returned by get_partitions().
    """
    drives = get_usb_drives()
    for d in drives:
        try:
            d['partitions'] = get_partitions(d['node'])
        except Exception:
            d['partitions'] = []
    return drives



@app.post("/select_partition")
def select_partition(selection: Selection):
    """Receive a selected partition/device from the web UI.

    This endpoint currently echoes back the device node. It can be extended
    to trigger formatting/wiping operations as needed.
    """
    # placeholder: simply return the received selection
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
        return {"status": "wipe failed to start"}

    return {"status": "wipe started"}

@app.post("/scan_device")
def scan_device(selection: Selection):
    device = selection.device

    logger.info(f"Received request to scan device: {device.node}")

    if not av_scan(device.node):
        return {"status": "scan failed or infections found"}
    return {"status": "scan complete, no infections found"}

# modify copy_device to create job and monitor
@app.post("/copy_device")
def copy_device(req: CopyRequest):

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

        return {"status": "copy complete"}

    except Exception as e:
        apiObj.status = jobStates.IDLE
        apiObj.activityMessage = "Copy failed"

        return {
            "status": "copy failed",
            "error": str(e)
        }

@app.get('/status')
def get_status():
    return {"status": apiObj.status.value, "activityMessage": apiObj.activityMessage}   

@app.get("/folders")
def get_folders():
    folders = []
    logger.info(f"Looking for folders in {DRIVE_PATH}")
    for item in os.listdir(DRIVE_PATH):
        full_path = os.path.join(DRIVE_PATH, item)

        if os.path.isdir(full_path):
            folders.append(item)

    return folders

