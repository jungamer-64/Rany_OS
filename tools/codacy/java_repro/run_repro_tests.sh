#!/usr/bin/env bash
set -euo pipefail

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_DIR/java_repro"

echo "Compiling Java reproducer..."
javac *.java

echo "Creating minimal repro file..."
./create_minimal_repro.sh fixtures/minimal_incomplete_utf8.bin

echo "Running compare on docs/ARCHITECTURE.md (chunk 4) - expect bad fails, fixed succeeds"
java -cp . ChunkDecodeCompare ../../docs/ARCHITECTURE.md 4

echo "Note: first invocation above may fail because output depends on environment; the second should show 'bad fails, fixed succeeds'"

echo "Done"
