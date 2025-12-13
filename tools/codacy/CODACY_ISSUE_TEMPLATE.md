Title: java.nio.charset.MalformedInputException in Codacy local collector when reading files (no-Docker path)

Description
-----------
When running the Codacy Analysis CLI in "local" mode (e.g., Docker not available), the Java-based file collector can throw java.nio.charset.MalformedInputException while reading files. This appears when the collector decodes files chunk-by-chunk and incorrectly treats each chunk as end-of-input (or resets the CharsetDecoder between chunks), so a multi-byte UTF-8 character split across a chunk boundary raises a MalformedInputException even though the entire file is valid UTF-8.

Reproduction
------------
We created a small reproducer in this repo under tools/codacy/java_repro:

- ChunkDecode.java — a minimal program that simulates the incorrect behavior (decoder.reset() and decode(..., endOfInput=true) per-chunk).
- ChunkDecodeFixed.java / ChunkDecodeCompare.java — fixed implementation that performs streaming decode correctly (preserve decoder state across chunks, compact ByteBuffer to preserve partial bytes, grow buffer as needed, and call decode(..., endOfInput=true) only for the final chunk).
- create_minimal_repro.sh — creates a tiny binary file that reproduces the error: it ends with an incomplete multi-byte UTF-8 sequence.

To reproduce locally:

1. Build the reproducer: javac tools/codacy/java_repro/*.java
2. Create the minimal failing file: ./tools/codacy/java_repro/create_minimal_repro.sh fixtures/minimal_incomplete_utf8.bin
3. Run the buggy approach on that file (simulate chunking with small chunk sizes):
   java -cp tools/codacy/java_repro ChunkDecode fixtures/minimal_incomplete_utf8.bin 4
   -> This should throw a MalformedInputException on the chunk that ends with the trailing byte.
4. Run the fixed streaming decoder on the same file (the fixed decoder will correctly report an error for the intentionally truncated file in the final flush, but it will not throw in intermediate chunks for valid files):
   java -cp tools/codacy/java_repro ChunkDecodeFixed docs/ARCHITECTURE.md 4

Also included: ChunkDecodeCompare which runs both bad and fixed decoders on a file and shows that the bad decoder fails while the fixed decoder succeeds for valid files where chunks split multi-byte characters.

Observed Symptoms
-----------------
- Stack trace in Codacy logs (no-Docker/local Java collector):
  java.nio.charset.MalformedInputException: Input length = 1
    at java.base/java.nio.charset.CoderResult.throwException(CoderResult.java:274)
    at <collector code>

- The Python-based partial-decode check (tools/codacy/find_utf8_error.py) shows that decoding a prefix of the file can fail at the chunk boundary (prefix length X).

Root Cause
----------
The collector appears to call CharsetDecoder.decode(ByteBuffer, CharBuffer, true) for each chunk or resets the decoder between chunks, which makes the decoder treat an incomplete byte sequence at a chunk boundary as the final input and throw MalformedInputException.

Suggested Fix
-------------
Implement streaming decode properly:

1. Create a single CharsetDecoder instance and do not reset it between chunks.
2. For each read chunk:
   - Flip the input buffer and call decode(inputBuffer, outputBuffer, false) repeatedly until it returns UNDERFLOW.
   - Compact the input buffer to move any remaining trailing incomplete bytes to the beginning of the buffer.
   - If the buffer is full of trailing bytes (no room to read more), grow the buffer (e.g., double its capacity) and copy the remaining bytes.
3. After EOF, flip the input buffer and call decode(inputBuffer, outputBuffer, true) once, then call flush() to complete decoding.

This pattern avoids throwing on intermediate chunks that end mid-character and ensures properly formed UTF-8 files are decoded even when arbitrarily chunked.

Supporting Artifacts
--------------------
- tools/codacy/java_repro/ChunkDecode.java (buggy usage example)
- tools/codacy/java_repro/ChunkDecodeFixed.java (fixed implementation)
- tools/codacy/java_repro/ChunkDecodeCompare.java (comparison harness)
- tools/codacy/java_repro/create_minimal_repro.sh (creates a minimal failing file)
- tools/codacy/find_utf8_error.py (Python helper that finds earliest failing prefix for a file)

CI and Mitigation
------------------
In this repository we added CI steps that run Codacy in Docker-enabled mode (preferred) and collect artifacts. We also added the Java reproducer and a CI helper to run the chunk-compare across files that failed to be read in local mode so maintainers can gather the data necessary to triage the issue.

If you would like, we can open a PR against the Codacy analysis CLI that implements the fixed streaming decoder for the local Java collector and include unit tests demonstrating the issue and the fix.
