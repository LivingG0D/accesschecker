#!/usr/bin/env bash
# Check-Host TCP Scanner — Linux/macOS Launcher
# Usage: ./run_checker.sh [ips] [port]
#   or just run it interactively

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/access_checker.py" "$@"
