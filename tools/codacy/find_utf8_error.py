#!/usr/bin/env python3
from pathlib import Path
import sys

if len(sys.argv) == 1:
    print("Usage: find_utf8_error.py <file>")
    sys.exit(2)

p = Path(sys.argv[1])
if not p.exists():
    print("File not found", p)
    sys.exit(2)

b = p.read_bytes()
for i in range(1, len(b) + 1):
    try:
        b[:i].decode("utf-8")
    except UnicodeDecodeError as e:
        print("Decoding fails at prefix length", i, "error", str(e))
        start = max(0, i - 16)
        end = min(len(b), i + 16)
        print("Bytes around", start, end)
        print(" ".join(["%02x" % x for x in b[start:end]]))
        print(b[start:end])
        sys.exit(1)
else:
    print('File decodes cleanly')
    sys.exit(0)
