#!/usr/bin/env bash
# Create a tiny minimal file that reproduces the chunked-decode failure
# The file contains ASCII text followed by the first byte of a 3-byte UTF-8
# character (0xE4) so that decoding a chunk that ends at that byte will
# raise a MalformedInputException if the decoder is told endOfInput=true.

set -euo pipefail
out=${1:-minimal_incomplete_utf8.bin}
printf "abc " > "$out"
# write single byte 0xE4 (start of a 3-byte sequence)
printf "\xE4" >> "$out"
echo "Wrote $out (size=$(wc -c < "$out"))"
