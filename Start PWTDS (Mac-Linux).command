#!/bin/bash
# ==== PWTDS launcher for macOS / Linux ====
cd "$(dirname "$0")" || exit 1
echo "Installing requirements (first run only)..."
python3 -m pip install -r requirements.txt --quiet 2>/dev/null || pip3 install -r requirements.txt --quiet 2>/dev/null
echo "Starting PWTDS..."
python3 app.py
