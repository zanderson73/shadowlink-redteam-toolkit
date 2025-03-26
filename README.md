# ShadowLink - Red Team C2 Framework

**Author**: Zane Anderson (zanderson@iscsecurity.org)  
**Version**: 1.0  
**License**: MIT  

---

## Description

ShadowLink is a lightweight, modular Command & Control (C2) framework built for Red Team operators and adversary simulation. Designed for flexibility, stealth, and rapid deployment, it supports beaconing, module execution, encrypted tasking, and file transfer between C2 and agent beacons.

---

## Features

- Encrypted tasking using AES (CBC mode)
- Agent check-ins with customizable interval
- Operator command interface (terminal-based)
- Modular post-exploitation support (`modules/*.sh`)
- File upload/download via beacon
- Beacon UUID-based registration
- Logging and loot storage

---

## Setup

### Requirements
- Python 3.8+
- Flask
- PyCryptodome

Install dependencies:
```bash
sudo apt install python3-flask
sudo pip3 install pycryptodome --break-system-packages
