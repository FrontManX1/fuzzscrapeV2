#!/bin/bash
pkg update -y
pkg install python -y
pip install -r requirements.txt
echo "[✔] Install selesai!"