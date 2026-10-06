#!/usr/bin/env bash
# Fetches the public MPSD dataset (Fang, Zhou & Huang, Neurocomputing 2021).
# The scripts are kept outside the repository and are never committed.
set -euo pipefail
DEST="${1:-data/mpsd}"
if [ ! -d "$DEST/.git" ]; then
  git clone --depth 1 https://github.com/das-lab/mpsd "$DEST"
fi
echo "Dataset ready at $DEST"
