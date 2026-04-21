#!/usr/bin/env bash
# scripts/build.sh
# Builds the french75 binary for Linux amd64 (for deployment to vm01).
# Run this from your Mac.
#
# Usage: bash scripts/build.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."

echo "Building Tailwind CSS ..."
cd "$ROOT"
npm install --silent
npx tailwindcss -i ./static/css/input.css -o ./static/css/app.css --minify

echo "Building Go binary for Linux amd64 ..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
go build -ldflags="-s -w" -o french75-linux ./cmd/server

echo "Done: $(ls -lh french75-linux | awk '{print $5, $9}')"
