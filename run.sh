#!/bin/sh
# Launch vcd_shadow_cleaner.py with the project's venv, from any directory.
DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$DIR/venv/bin/python" "$DIR/vcd_shadow_cleaner.py" "$@"
