import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.io.*;

public class ChunkDecode {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ChunkDecode <file> <chunkSize>");
            System.exit(2);
        }
        Path p = Paths.get(args[0]);
        int chunkSize = Integer.parseInt(args[1]);

        byte[] all = Files.readAllBytes(p);
        try (FileChannel fc = FileChannel.open(p, StandardOpenOption.READ)) {
            ByteBuffer bb = ByteBuffer.allocate(chunkSize);
            CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder();
            dec.onMalformedInput(CodingErrorAction.REPORT);
            dec.onUnmappableCharacter(CodingErrorAction.REPORT);
            long pos = 0;
            while (true) {
                bb.clear();
                int r = fc.read(bb);
                if (r <= 0) break;
                bb.flip();
                dec.reset();
                CharBuffer cb = CharBuffer.allocate(chunkSize);
                try {
                    // Intentionally pass endOfInput=true to attempt to replicate a bad decoding scenario
                    CoderResult cr = dec.decode(bb, cb, true);
                    if (cr.isError()) {
                        cr.throwException();
                    }
                    dec.flush(cb);
                } catch (CharacterCodingException e) {
                    System.err.println("Decode failure on chunk starting at file position " + pos + " (chunk size=" + chunkSize + ")");
                    // print surrounding bytes for diagnosis
                    int start = (int)Math.max(0, pos - 16);
                    int end = (int)Math.min(all.length, pos + chunkSize + 16);
                    System.err.println("Bytes around failure (hex):");
                    System.err.println(toHex(all, start, end));
                    System.err.println("Bytes around failure (utf8 with replacement):");
                    System.err.println(new String(all, start, end - start, StandardCharsets.UTF_8));
                    System.err.println("Chunk bytes (hex):");
                    System.err.println(toHex(all, (int)pos, (int)Math.min(all.length, pos + r)));
                    e.printStackTrace();
                    System.exit(1);
                }
                pos += r;
            }
            System.out.println("Decode OK with chunk size " + chunkSize);
            System.exit(0);
        }
    }

    private static String toHex(byte[] a, int start, int end) {
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < end; i++) {
            sb.append(String.format("%02x ", a[i] & 0xff));
        }
        return sb.toString();
    }
}
