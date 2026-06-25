# sanddisk
A small utility to copy, scan and wipe drives

## Features
- List USB drives and partitions (via pyudev)
- Interactive selection of drive and partition
- Secure wipe using nwipe (--method, --verify, --nogui)
- AV Scan drives
- Copy files between folders in a given directory
- FastAPI endpoint: for running above features

## Requirements
- Python 3
- Python packages: pyudev, fastapi
- Utilities:
  - nwipe (for secure erase)
  - exfatprogs (file system support)
  - smartmontools (filesystem support)
  - uvicorn (to run the FastAPI app)
  - clam (av scan)

## Ubuntu/debian install
```bash
sudo apt update
sudo apt install python3 python3-pip exfatprogs nwipe smartmontools uvicorn
sudo apt install clamav clamav-daemon
pip3 install pyudev fastapi or sudo sudo apt install python3-pyudev python3-fastapi
```

## Usage
- Ensure the clam service is running:
  - sudo systemctl status clamav-daemon
- Run the FastAPI endpoint (example with uvicorn):
  sudo PATH_VARIABLE=main/copy/folder uvicorn sanddisk:app --reload --host 0.0.0.0 --port 8000
  - the PATH_VARIABLE is used for the copy function to define where copy folders live
  - Use POST requests to access relvant endpoints (example can be found in test folder)

## Notes and safety
- Wiping and formatting are destructive operations. Always confirm the selected device before proceeding.
- nwipe with `--autonuke` and `--nogui` will start immediately without additional prompts.
- mkfs tools must be present for the filesystem types you want to create (e.g. mkfs.exfat from exfatprogs).

## License
Unlicensed — use at your own risk.