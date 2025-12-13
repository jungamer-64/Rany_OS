Summary
-------
When the Codacy analysis CLI runs in local Java-based collector mode (Docker not available), some files cause the collector to throw java.nio.charset.MalformedInputException during file reading. This is caused by decoding file contents chunk-by-chunk while treating each chunk as if it were the end of input (or by resetting the CharsetDecoder between chunks). When a multi-byte UTF-8 character is split across a chunk boundary the decoder throws, even though the entire file is valid UTF-8.

Reproduction
------------
See the reproducer in this repository inside `tools/codacy/java_repro`:

- `ChunkDecode.java` — demonstrates the incorrect usage by calling `decode(..., endOfInput=true)` for each chunk.
- `ChunkDecodeFixed.java` and `ChunkDecodeCompare.java` — demonstrate the correct streaming approach and compare the results.

Quick steps:

1. javac tools/codacy/java_repro/*.java
2. ./tools/codacy/java_repro/create_minimal_repro.sh fixtures/minimal_incomplete_utf8.bin
3. java -cp tools/codacy/java_repro ChunkDecode fixtures/minimal_incomplete_utf8.bin 4  # => fails
4. java -cp tools/codacy/java_repro ChunkDecodeCompare docs/ARCHITECTURE.md 4             # => shows bad fails, fixed succeeds

Suggested Fix
-------------
Replace the per-chunk decode usage with a streaming decoder pattern:

1. Allocate a ByteBuffer (preferably >= chunkSize*2) and a single CharsetDecoder instance.
2. For each read from the file channel into the buffer:
   - Flip the buffer and call decode(buffer, output, false) repeatedly until UNDERFLOW.
   - Compact the buffer to move any remaining incomplete bytes to the beginning.
   - If the buffer is full of trailing bytes (no room to read), grow the buffer and copy the remainder to the new buffer.
3. After EOF, flip and call decode(buffer, output, true), then flush.

This pattern avoids throwing MalformedInputException on intermediate chunk boundaries and correctly decodes valid UTF-8 files regardless of read chunk boundaries.

Patch (conceptual)
------------------
Replace code like this (incorrect):

  dec.reset();
  while ((read = fc.read(bb)) > 0) {
    bb.flip();
    dec.decode(bb, cb, true); // <-- BAD: passing endOfInput=true per chunk
    dec.flush(cb);
    bb.clear();
  }

With streaming decoding (correct):

  dec.reset();
  ByteBuffer bb = ByteBuffer.allocate(chunkSize * 2);
  while (fc.read(bb) > 0) {
    bb.flip();
    while (true) {
      CoderResult cr = dec.decode(bb, cb, false);
      if (cr.isError()) cr.throwException();
      if (cr.isUnderflow()) break;
    }
    bb.compact();
    if (bb.position() == bb.capacity()) { // grow if necessary
      ByteBuffer nb = ByteBuffer.allocate(bb.capacity() * 2);
      bb.flip(); nb.put(bb); bb = nb;
    }
  }
  bb.flip();
  CoderResult cr = dec.decode(bb, cb, true);
  if (cr.isError()) cr.throwException();
  dec.flush(cb);

Notes
-----
- We can provide a minimal reproducer (the files in this repo) and an example unit test.
- The issue is only observable when the analysis CLI runs in local mode (no Docker) and uses Java-based file reading/decoding logic. When Docker is enabled, plugins run inside containers and the problem is not observed.

If helpful, we can open a PR implementing the suggested fix and adding unit tests that would have caught this bug.
