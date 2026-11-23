#!/usr/bin/env bash
# Linux/Kali setup: create the project venv (.venv) and install requirements.
# Usage:  bash scripts/setup.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$ROOT/.venv"
PY="$(command -v python3 || command -v python)"

echo "==> Creating virtual environment at $VENV"
"$PY" -m venv "$VENV"

echo "==> Upgrading pip"
"$VENV/bin/python" -m pip install --upgrade pip

echo "==> Installing requirements"
"$VENV/bin/python" -m pip install -r "$ROOT/requirements.txt"

echo
echo "Done. Activate with:"
echo "  source $VENV/bin/activate"
echo "Then run:"
echo "  python -m src.cli discover --domain example.com"
