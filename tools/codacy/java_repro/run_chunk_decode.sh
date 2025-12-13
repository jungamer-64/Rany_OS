#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <file> <chunkSize>"
  exit 2
fi

FILE="$1"
CHUNK="$2"
DIR=$(dirname "$0")
JAVAFILE="$DIR/ChunkDecode.java"
CLASSDIR="$DIR/out"
mkdir -p "$CLASSDIR"

javac -d "$CLASSDIR" "$JAVAFILE"
java -cp "$CLASSDIR" ChunkDecode "$FILE" "$CHUNK" || true
