Title: MalformedInputException when reading files in local Codacy collector (chunked decode issue)

Summary:
When Codacy CLI runs without Docker (local Java collector), some files cause java.nio.charset.MalformedInputException because the file reader decodes each chunk as if it were the end of input. This fails when a UTF-8 multi-byte sequence is split across chunk boundaries.

How to reproduce:
- Compile the reproducer in `tools/codacy/java_repro` (javac *.java)
- Create a minimal failing file: `./create_minimal_repro.sh fixtures/minimal_incomplete_utf8.bin`
- Run `java -cp . ChunkDecode fixtures/minimal_incomplete_utf8.bin 4` to see the exception
- Run `java -cp . ChunkDecodeCompare path/to/failed-file 4` to compare the buggy and fixed approaches

Suggested fix (high level): use a single CharsetDecoder and stream decodes across chunks, compacting the buffer to preserve trailing bytes and only calling decode(..., true) for final flush. Also ensure the buffer has headroom (grow if needed) to accept more bytes when trailing partial sequences are present.

I can open a PR with a proposed fix and unit tests (in Java) that reproduce the issue and verify the fix. Please advise whether you'd like me to file the issue in Codacy's repo and/or open a PR with the patch and tests.

Attached reproducer files:
- tools/codacy/java_repro/*
- tools/codacy/find_utf8_error.py
- tools/codacy/CODACY_ISSUE_TEMPLATE.md (issue text and suggested patch)
