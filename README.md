# Portscanner
This portscanner is created by **0x47root**.

## Usage:
Unix based OS:
```bash
sudo python3 main.py
```
Windows (run as Administrator):
```cmd
py main.py
```

## Possible scan types
- TCP-Connect Scan (-sT)
- UDP Scan (-sU)
- SYN Scan (-sS)
- XMAS Scan (-sX)

## Additional functionalities
- Scan range of ports
- Save scan results to XML or JSON file
- Automatically save results to SQLite database

## Requirements
- WinPcap/NPcap installed (https://www.winpcap.org/install/)
