#!/usr/bin/env bash
set -euo pipefail

USAGE="Usage: $0 <codacy-log> [output_file]"
if [ "$#" -lt 1 ]; then
  echo "$USAGE"
  exit 2
fi
LOGFILE="$1"
OUTFILE="${2:-tools/codacy/failed_read_files.txt}"

mkdir -p $(dirname "$OUTFILE")
grep -oP "Failed to read file \K.*" "$LOGFILE" | sed -e 's/[[:space:]]*$//' | sort -u > "$OUTFILE" || true
echo "Wrote failed files to $OUTFILE"

exit 0
