#!/bin/bash
echo "[+] Scanning local subnet..."
ip r | awk "/inet/ {print \$1}" | while read subnet; do
  nmap -sn \$subnet -oG - | awk "/Up/ {print \$2}"
done
