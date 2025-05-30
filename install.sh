#!/bin/bash
echo "[+] Updating packages..."
pkg update -y && pkg upgrade -y

echo "[+] Installing Python and pip..."
pkg install python -y

echo "[+] Installing required Python modules..."
pip install -r requirements.txt

echo "[✓] Instalasi selesai!"
echo "[✓] Jalankan: python3 fuzzscrape.py --help"