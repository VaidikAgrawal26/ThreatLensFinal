#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v python >/dev/null || { echo 'Python not found' >&2; exit 1; }
command -v npm >/dev/null || { echo 'npm not found' >&2; exit 1; }
cd "$ROOT/backend"
python -m pip install -r requirements.txt
PYTHONPATH=. python -m pytest -q
cd "$ROOT/frontend"
if [[ -f package-lock.json ]]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi
npm run build
echo 'Static/build checks passed. Complete API/browser checks in docs/TESTING.md.'
