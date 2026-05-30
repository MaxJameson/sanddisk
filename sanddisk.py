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
import threading
import uuid
from fastapi.responses import StreamingResponse


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


class CopyRequest(BaseModel):
    src: str
    dst: str
    excludes: Optional[List[str]] = None


def start_copy_in_background(src, dst, excludes=None):
    """Start a copy from src to dst in the background.

    Behaviour:
      - If src and dst are directories, use rsync with optional excludes.
      - If src and dst are block devices (/dev/...), mount them temporarily (src ro),
        rsync the files (like copy/paste) and unmount/cleanup after completion.
      - Otherwise fall back to raw dd only when neither of the above apply.

    Returns:
      dict: {'pid': <int>, 'logfile': <path>} on success or {'error': msg} on failure.
    """
    rsync = shutil.which('rsync')
    dd = shutil.which('dd')

    # helper to build exclude args
    def _exclude_args(excludes_list):
        args = []
        if not excludes_list:
            return args
        for ex in excludes_list:
            args += ['--exclude', ex]
        return args

    # 1) filesystem directories -> rsync directly
    if os.path.isdir(src) and os.path.isdir(dst):
        if not rsync:
            return {'error': 'rsync not found on system'}
        logfile = f"/tmp/sanddisk_rsync_{os.getpid()}_{int(time.time())}.log"
        # use copy/paste semantics: recursive, preserve times and symlinks, but not owner/group/perms
        cmd = [rsync, '-r', '-t', '--links', '--info=progress2'] + _exclude_args(excludes) + [src.rstrip('/') + '/', dst.rstrip('/') + '/']
        if os.geteuid() != 0:
            cmd = ['sudo'] + cmd
        try:
            logf = open(logfile, 'wb')
            proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT)
            return {'pid': proc.pid, 'logfile': logfile}
        except Exception as e:
            return {'error': str(e)}

    # 2) block device nodes -> mount temporary and rsync files (copy/paste semantics)
    if src.startswith('/dev/') and dst.startswith('/dev/'):
        if not rsync:
            return {'error': 'rsync not found on system'}
        if not os.path.exists(src):
            return {'error': f'source device not found: {src}'}
        if not os.path.exists(dst):
            return {'error': f'destination device not found: {dst}'}
        if src == dst:
            return {'error': 'source and destination are the same'}

        # check for existing mounts and reuse them when possible
        src_mp = get_mountpoint(src)
        dst_mp = get_mountpoint(dst)
        src_temp = False
        dst_temp = False
        try:
            if not src_mp:
                src_mp = tempfile.mkdtemp(prefix='sanddisk_src_')
                mount_src_cmd = ['mount', '-o', 'ro', src, src_mp]
                if os.geteuid() != 0:
                    mount_src_cmd = ['sudo'] + mount_src_cmd
                subprocess.run(mount_src_cmd, check=True)
                src_temp = True
            if not dst_mp:
                dst_mp = tempfile.mkdtemp(prefix='sanddisk_dst_')
                mount_dst_cmd = ['mount', dst, dst_mp]
                if os.geteuid() != 0:
                    mount_dst_cmd = ['sudo'] + mount_dst_cmd
                subprocess.run(mount_dst_cmd, check=True)
        except subprocess.CalledProcessError as e:
            # cleanup any created dirs if mount failed
            try:
                if src_temp and os.path.ismount(src_mp):
                    subprocess.run(['sudo','umount', src_mp])
            except Exception:
                pass
            try:
                if dst_temp and os.path.ismount(dst_mp):
                    subprocess.run(['sudo','umount', dst_mp])
            except Exception:
                pass
            try:
                if src_temp:
                    os.rmdir(src_mp)
            except Exception:
                pass
            try:
                if dst_temp:
                    os.rmdir(dst_mp)
            except Exception:
                pass
            return {'error': f'mount failed: {e}'}

        # run rsync in a shell that unmounts and removes only temp mountpoints after completion
        logfile = f"/tmp/sanddisk_rsync_{os.getpid()}_{int(time.time())}.log"
        excl = _exclude_args(excludes)
        # build rsync args safely
        # use copy/paste semantics: recursive, preserve times and symlinks, but not owner/group/perms
        rsync_args = ' '.join([shlex.quote(a) for a in ([rsync, '-r', '-t', '--links', '--info=progress2'] + excl + [src_mp.rstrip('/') + '/', dst_mp.rstrip('/') + '/'])])
        # cleanup commands: only unmount/rmdir if we created the mountpoints
        umount_src = (('sudo umount ' + shlex.quote(src_mp)) if os.geteuid() != 0 else ('umount ' + shlex.quote(src_mp))) if src_temp else ''
        umount_dst = (('sudo umount ' + shlex.quote(dst_mp)) if os.geteuid() != 0 else ('umount ' + shlex.quote(dst_mp))) if dst_temp else ''
        rmdir_src = ('rmdir ' + shlex.quote(src_mp)) if src_temp else ''
        rmdir_dst = ('rmdir ' + shlex.quote(dst_mp)) if dst_temp else ''
         # full wrapper command
        cleanup_cmds = ' ; '.join(c for c in [umount_src, umount_dst, rmdir_src, rmdir_dst] if c)
        if cleanup_cmds:
            wrapper = f"bash -lc \"{rsync_args} ; rc=$?; {cleanup_cmds} >/dev/null 2>&1 || true; exit $rc\""
        else:
            wrapper = f"bash -lc \"{rsync_args}; exit $?\""
        try:
            logf = open(logfile, 'wb')
            proc = subprocess.Popen(wrapper, shell=True, stdout=logf, stderr=subprocess.STDOUT)
            return {'pid': proc.pid, 'logfile': logfile}
        except Exception as e:
            # attempt cleanup
            try:
                if src_temp and os.path.ismount(src_mp):
                    subprocess.run(['sudo','umount', src_mp])
            except Exception:
                pass
            try:
                if dst_temp and os.path.ismount(dst_mp):
                    subprocess.run(['sudo','umount', dst_mp])
            except Exception:
                pass
            try:
                if src_temp:
                    os.rmdir(src_mp)
            except Exception:
                pass
            try:
                if dst_temp:
                    os.rmdir(dst_mp)
            except Exception:
                pass
            return {'error': str(e)}

    # 3) fallback to dd for other cases
    if not dd:
        return {'error': 'dd not found on system'}
    if not os.path.exists(src):
        return {'error': f'source device not found: {src}'}
    if not os.path.exists(dst):
        return {'error': f'destination device not found: {dst}'}
    if src == dst:
        return {'error': 'source and destination are the same'}
    if excludes:
        return {'error': 'excludes supported only for filesystem (directory) copies'}

    logfile = f"/tmp/sanddisk_copy_{os.getpid()}_{int(time.time())}.log"
    cmd = [dd, f'if={src}', f'of={dst}', 'bs=4M', 'status=progress']
    if os.geteuid() != 0:
        cmd = ['sudo'] + cmd
    try:
        logf = open(logfile, 'wb')
        proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT)
        return {'pid': proc.pid, 'logfile': logfile}
    except Exception as e:
        return {'error': str(e)}


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


def get_usb_drives():
    """Discover USB block devices and return metadata for each.

    Scans udev for block devices with DEVTYPE='disk' and ID_BUS='usb'.

    Returns:
        list[dict]: List of drive metadata dictionaries. Each dict contains keys:
            - node (str): device node (e.g. '/dev/sdb')
            - vendor (str|None)
            - model (str|None)
            - serial (str|None)
            - size (int|None): size in bytes or None if unavailable
            - size_human (str): human readable size or 'Unknown'

    Raises:
        RuntimeError: Only in rare cases if pyudev fails; most errors are handled
        and missing fields set to None.
    """
    context = pyudev.Context()
    drives = []
    for device in context.list_devices(subsystem='block', DEVTYPE='disk'):
        if device.get('ID_BUS') != 'usb':
            continue
        devnode = device.device_node
        if not devnode:
            continue
        # try to read size from sysfs (size is in 512-byte sectors)
        size_bytes = None
        try:
            base = os.path.basename(devnode)
            with open(f"/sys/block/{base}/size", "r") as f:
                sectors = int(f.read().strip())
                size_bytes = sectors * 512
        except Exception:
            size_bytes = None
        drives.append({
            'node': devnode,
            'vendor': device.get('ID_VENDOR'),
            'model': device.get('ID_MODEL'),
            'serial': device.get('ID_SERIAL_SHORT') or device.get('ID_SERIAL'),
            'size': size_bytes,
            'size_human': _human_size(size_bytes) if size_bytes else 'Unknown',
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


def format_drive(device_node, fs_type='ext4', label=None):
    """Format the given device node with the chosen filesystem.

    Returns True on success, False otherwise.
    """
    # Check for mounted partitions/devices first
    if is_mounted(device_node):
        if not unmount_devices_for(device_node):
            return False

    print(f"About to format {device_node} as {fs_type}.")
    cmd = _mkfs_command_for(fs_type, device_node, label)
    if os.geteuid() != 0:
        cmd = ['sudo'] + cmd
    print("Running:", ' '.join(cmd))
    try:
        subprocess.run(cmd, check=True)
        print("Formatting finished.")
        return True
    except subprocess.CalledProcessError as e:
        print("Formatting failed:", e)
        return False


def run_nwipe(device_node, method='ops2', orig_fs=None, orig_label=None):
    """Run nwipe on the given device and stream its text output.

    Requires --nogui/--autonuke for parseable text output. Prints nwipe lines live
    and shows the current pass number when detected.
    """
    if is_mounted(device_node):
        if not unmount_devices_for(device_node):
            return False

    nwipe = shutil.which('nwipe')
    if not nwipe:
        print("nwipe not found. Install nwipe to use secure wipe (e.g. sudo apt install nwipe).")
        return False

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
            print(line)

            low = line.lower()
            # Detect final-random-pattern message and print a concise status
            if 'writing final random pattern' in low:
                print('NWipe: writing final random pattern (finalizing)...')
                continue
            # Detect verification of final random pattern
            if 'verifying final random pattern' in low or 'verifying final pattern' in low:
                print('NWipe: verifying final random pattern...')
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
                        print(f"NWipe: currently on pass {p}")
                except Exception:
                    pass
        ret = proc.wait()
        if ret == 0:
            print("Wipe finished.")
            # After a destructive wipe the filesystem and label are gone — recreate them.
            print(f"Restoring filesystem {orig_fs} and label {orig_label!s} on {device_node} ...")
            ok = format_drive(device_node, fs_type=orig_fs, label=orig_label)
            sys.exit(0 if ok else 1)

            return True
        else:
            print("Wipe failed, exit code", ret)
            return False
    except Exception as e:
        print("Wipe failed:", e)
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




app = FastAPI()
# Enable CORS for development/testing so the Test Site page can fetch the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

class Selection(BaseModel):
    device: str


@app.post("/select_partition")
def select_partition(selection: Selection):
    """Receive a selected partition/device from the web UI.

    This endpoint currently echoes back the device node. It can be extended
    to trigger formatting/wiping operations as needed.
    """
    # placeholder: simply return the received selection
    return {"selected": selection.device}

class CopyRequest(BaseModel):
    src: str
    dst: str
    excludes: Optional[List[str]] = None


def start_copy_in_background(src, dst, excludes=None):
    """Start a copy from src to dst in the background.

    Behaviour:
      - If src and dst are directories, use rsync with optional excludes.
      - If src and dst are block devices (/dev/...), mount them temporarily (src ro),
        rsync the files (like copy/paste) and unmount/cleanup after completion.
      - Otherwise fall back to raw dd only when neither of the above apply.

    Returns:
      dict: {'pid': <int>, 'logfile': <path>} on success or {'error': msg} on failure.
    """
    rsync = shutil.which('rsync')
    dd = shutil.which('dd')

    # helper to build exclude args
    def _exclude_args(excludes_list):
        args = []
        if not excludes_list:
            return args
        for ex in excludes_list:
            args += ['--exclude', ex]
        return args

    # 1) filesystem directories -> rsync directly
    if os.path.isdir(src) and os.path.isdir(dst):
        if not rsync:
            return {'error': 'rsync not found on system'}
        logfile = f"/tmp/sanddisk_rsync_{os.getpid()}_{int(time.time())}.log"
        # use copy/paste semantics: recursive, preserve times and symlinks, but not owner/group/perms
        cmd = [rsync, '-r', '-t', '--links', '--info=progress2'] + _exclude_args(excludes) + [src.rstrip('/') + '/', dst.rstrip('/') + '/']
        if os.geteuid() != 0:
            cmd = ['sudo'] + cmd
        try:
            logf = open(logfile, 'wb')
            proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT)
            return {'pid': proc.pid, 'logfile': logfile}
        except Exception as e:
            return {'error': str(e)}

    # 2) block device nodes -> mount temporary and rsync files (copy/paste semantics)
    if src.startswith('/dev/') and dst.startswith('/dev/'):
        if not rsync:
            return {'error': 'rsync not found on system'}
        if not os.path.exists(src):
            return {'error': f'source device not found: {src}'}
        if not os.path.exists(dst):
            return {'error': f'destination device not found: {dst}'}
        if src == dst:
            return {'error': 'source and destination are the same'}

        # check for existing mounts and reuse them when possible
        src_mp = get_mountpoint(src)
        dst_mp = get_mountpoint(dst)
        src_temp = False
        dst_temp = False
        try:
            if not src_mp:
                src_mp = tempfile.mkdtemp(prefix='sanddisk_src_')
                mount_src_cmd = ['mount', '-o', 'ro', src, src_mp]
                if os.geteuid() != 0:
                    mount_src_cmd = ['sudo'] + mount_src_cmd
                subprocess.run(mount_src_cmd, check=True)
                src_temp = True
            if not dst_mp:
                dst_mp = tempfile.mkdtemp(prefix='sanddisk_dst_')
                mount_dst_cmd = ['mount', dst, dst_mp]
                if os.geteuid() != 0:
                    mount_dst_cmd = ['sudo'] + mount_dst_cmd
                subprocess.run(mount_dst_cmd, check=True)
        except subprocess.CalledProcessError as e:
            # cleanup any created dirs if mount failed
            try:
                if src_temp and os.path.ismount(src_mp):
                    subprocess.run(['sudo','umount', src_mp])
            except Exception:
                pass
            try:
                if dst_temp and os.path.ismount(dst_mp):
                    subprocess.run(['sudo','umount', dst_mp])
            except Exception:
                pass
            try:
                if src_temp:
                    os.rmdir(src_mp)
            except Exception:
                pass
            try:
                if dst_temp:
                    os.rmdir(dst_mp)
            except Exception:
                pass
            return {'error': f'mount failed: {e}'}

        # run rsync in a shell that unmounts and removes only temp mountpoints after completion
        logfile = f"/tmp/sanddisk_rsync_{os.getpid()}_{int(time.time())}.log"
        excl = _exclude_args(excludes)
        # build rsync args safely
        # use copy/paste semantics: recursive, preserve times and symlinks, but not owner/group/perms
        rsync_args = ' '.join([shlex.quote(a) for a in ([rsync, '-r', '-t', '--links', '--info=progress2'] + excl + [src_mp.rstrip('/') + '/', dst_mp.rstrip('/') + '/'])])
        # cleanup commands: only unmount/rmdir if we created the mountpoints
        umount_src = (('sudo umount ' + shlex.quote(src_mp)) if os.geteuid() != 0 else ('umount ' + shlex.quote(src_mp))) if src_temp else ''
        umount_dst = (('sudo umount ' + shlex.quote(dst_mp)) if os.geteuid() != 0 else ('umount ' + shlex.quote(dst_mp))) if dst_temp else ''
        rmdir_src = ('rmdir ' + shlex.quote(src_mp)) if src_temp else ''
        rmdir_dst = ('rmdir ' + shlex.quote(dst_mp)) if dst_temp else ''
         # full wrapper command
        cleanup_cmds = ' ; '.join(c for c in [umount_src, umount_dst, rmdir_src, rmdir_dst] if c)
        if cleanup_cmds:
            wrapper = f"bash -lc \"{rsync_args} ; rc=$?; {cleanup_cmds} >/dev/null 2>&1 || true; exit $rc\""
        else:
            wrapper = f"bash -lc \"{rsync_args}; exit $?\""
        try:
            logf = open(logfile, 'wb')
            proc = subprocess.Popen(wrapper, shell=True, stdout=logf, stderr=subprocess.STDOUT)
            return {'pid': proc.pid, 'logfile': logfile}
        except Exception as e:
            # attempt cleanup
            try:
                if src_temp and os.path.ismount(src_mp):
                    subprocess.run(['sudo','umount', src_mp])
            except Exception:
                pass
            try:
                if dst_temp and os.path.ismount(dst_mp):
                    subprocess.run(['sudo','umount', dst_mp])
            except Exception:
                pass
            try:
                if src_temp:
                    os.rmdir(src_mp)
            except Exception:
                pass
            try:
                if dst_temp:
                    os.rmdir(dst_mp)
            except Exception:
                pass
            return {'error': str(e)}

    # 3) fallback to dd for other cases
    if not dd:
        return {'error': 'dd not found on system'}
    if not os.path.exists(src):
        return {'error': f'source device not found: {src}'}
    if not os.path.exists(dst):
        return {'error': f'destination device not found: {dst}'}
    if src == dst:
        return {'error': 'source and destination are the same'}
    if excludes:
        return {'error': 'excludes supported only for filesystem (directory) copies'}

    logfile = f"/tmp/sanddisk_copy_{os.getpid()}_{int(time.time())}.log"
    cmd = [dd, f'if={src}', f'of={dst}', 'bs=4M', 'status=progress']
    if os.geteuid() != 0:
        cmd = ['sudo'] + cmd
    try:
        logf = open(logfile, 'wb')
        proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT)
        return {'pid': proc.pid, 'logfile': logfile}
    except Exception as e:
        return {'error': str(e)}


# in-memory job store
JOBS = {}


def _tail_log(path, max_lines=50):
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 1024
            data = b''
            while size > 0 and data.count(b'\n') <= max_lines:
                if size - block > 0:
                    f.seek(size - block)
                    data = f.read() + data
                else:
                    f.seek(0)
                    data = f.read() + data
                size -= block
            return data.decode(errors='ignore').splitlines()[-max_lines:]
    except Exception:
        return []


def _monitor_job(job_id, proc, logfile):
    job = JOBS.get(job_id)
    if not job:
        return
    # stream logfile periodically by updating job['lines'] and final status
    try:
        while True:
            ret = proc.poll()
            job['lines'] = _tail_log(logfile, max_lines=100)
            job['updated_at'] = time.time()
            if ret is not None:
                job['exitcode'] = ret
                job['status'] = 'completed' if ret == 0 else 'failed'
                job['lines'] = _tail_log(logfile, max_lines=200)
                job['finished_at'] = time.time()
                break
            time.sleep(1)
    except Exception as e:
        job['status'] = 'error'
        job['error'] = str(e)


@app.get('/job/{job_id}')
def get_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return {'error': 'job not found'}
    return job


@app.get('/events/{job_id}')
def events(request, job_id: str):
    def event_generator():
        if job_id not in JOBS:
            yield f"data: {json.dumps({'error':'job not found'})}\n\n"
            return
        last_sent = None
        while True:
            job = JOBS.get(job_id)
            if not job:
                yield f"data: {json.dumps({'error':'job gone'})}\n\n"
                return
            payload = {
                'status': job.get('status'),
                'pid': job.get('pid'),
                'logfile': job.get('logfile'),
                'exitcode': job.get('exitcode'),
                'lines': job.get('lines', [])
            }
            s = json.dumps(payload)
            if s != last_sent:
                yield f"data: {s}\n\n"
                last_sent = s
            if job.get('status') in ('completed', 'failed', 'error'):
                return
            # client disconnected?
            if request.scope.get('client') is None:
                return
            time.sleep(1)
    return StreamingResponse(event_generator(), media_type='text/event-stream')


# modify copy_device to create job and monitor
@app.post('/copy_device')
def copy_device(req: CopyRequest):
    res = start_copy_in_background(req.src, req.dst, req.excludes)

    if isinstance(res, dict):
        if res.get("error"):
            return res

        pid = res.get("pid")
        logfile = res.get("logfile")

        if pid is None or logfile is None:
            return {"error": f"unexpected start_copy result: {res!r}"}

        job_id = uuid.uuid4().hex

        JOBS[job_id] = {
            "id": job_id,
            "status": "running",
            "pid": pid,
            "logfile": logfile,
            "src": req.src,
            "dst": req.dst,
            "created_at": time.time(),
            "updated_at": time.time(),
            "lines": [],
        }

        # Cannot monitor with a process object because you don't have one
        return {"job_id": job_id}

    return {"error": f"unexpected start_copy result: {res!r}"}




