#!/usr/bin/env bash
# One-shot verification pipeline. Runs inside the `verify` image and exits
# non-zero as soon as any stage fails.
set -euo pipefail

echo "==> [1/3] Backend test suite (pytest)"
cd /app/backend
# Isolate the test suite from the shared /data volume: conftest.py falls back
# to a fresh temp dir when DATA_DIR is unset.
env -u DATA_DIR -u STATIC_DIR python -m pytest -q tests/

echo "==> [2/3] Frontend production build (tsc + vite)"
cd /app/frontend
npm run build

echo "==> [3/3] HTTP smoke tests against ${BASE_URL}"
# The smoke simulates silent disk corruption in the web service's data dir,
# which is shared into this one-shot container at /data.
DATA_DIR="${SMOKE_DATA_DIR:-/data}" python /app/verify/smoke.py

echo "==> ALL VERIFICATION STAGES PASSED"
