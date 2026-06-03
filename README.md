# sanddisk
A small utility to copy, scan and wipe drives

## Features
- List USB drives and partitions (via pyudev)
- Interactive selection of drive and partition
- Secure wipe using nwipe (--method, --verify, --nogui)
- FastAPI endpoint: for running above features

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
- Run the FastAPI endpoint (example with uvicorn):
  sudo uvicorn sanddisk:app --reload --host 0.0.0.0 --port 8000
  - Use POST requests to access relvant endpoints (example can be found in test folder)

## Notes and safety
- Wiping and formatting are destructive operations. Always confirm the selected device before proceeding.
- nwipe with `--autonuke` and `--nogui` will start immediately without additional prompts.
- mkfs tools must be present for the filesystem types you want to create (e.g. mkfs.exfat from exfatprogs).

## License
Unlicensed — use at your own risk.