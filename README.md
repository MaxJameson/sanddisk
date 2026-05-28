# sanddisk

A small utility to inspect connected USB block devices, select a drive or partition, optionally securely wipe it with nwipe, and recreate a filesystem. It also exposes a simple FastAPI endpoint to list detected USB drives.

## Features
- List USB drives and partitions (via pyudev)
- Interactive selection of drive and partition
- Optional secure wipe using nwipe (--method, --verify, --nogui)
- Format the selected partition/device using the detected or chosen filesystem
- FastAPI endpoint: GET /drives returns JSON list of detected USB drives

## Requirements
- Python 3
- Python packages: pyudev, fastapi
- Utilities (Ubuntu examples):
  - exfatprogs (for exFAT support)
  - nwipe (optional, for secure erase)
  - smartmontools (optional)
  - uvicorn (to run the FastAPI app)

## Ubuntu install (recommended)
```bash
sudo apt update
sudo apt install python3 python3-pip exfatprogs nwipe smartmontools uvicorn
pip3 install pyudev fastapi
```

## Usage
- Run as a CLI tool:
  python3 sanddisk.py
  - Select a drive, then a partition (or use whole device if none)
  - Optionally wipe with nwipe and then format (the script can restore the original filesystem/label)

- Run the FastAPI endpoint (example with uvicorn):
  uvicorn sanddisk:app --reload --host 0.0.0.0 --port 8000
  GET http://localhost:8000/drives

## Notes and safety
- Wiping and formatting are destructive operations. Always confirm the selected device before proceeding.
- nwipe with `--autonuke` and `--nogui` will start immediately without additional prompts.
- mkfs tools must be present for the filesystem types you want to create (e.g. mkfs.exfat from exfatprogs).

## License
Unlicensed — use at your own risk.