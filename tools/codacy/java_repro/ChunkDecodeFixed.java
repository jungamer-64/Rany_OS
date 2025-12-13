import java.nio.*;
import java.nio.channels.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.io.*;

public class ChunkDecodeFixed {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ChunkDecodeFixed <file> <chunkSize>");
            System.exit(2);
        }
        Path p = Paths.get(args[0]);
        int chunkSize = Integer.parseInt(args[1]);

        try (FileChannel fc = FileChannel.open(p, StandardOpenOption.READ)) {
            ByteBuffer bb = ByteBuffer.allocate(chunkSize);
            CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder();
            dec.onMalformedInput(CodingErrorAction.REPORT);
            dec.onUnmappableCharacter(CodingErrorAction.REPORT);
            dec.reset();
            CharBuffer cb = CharBuffer.allocate(chunkSize * 2);
            while (fc.read(bb) > 0) {
                long chunkStart = fc.position() - bb.position();
                bb.flip();
                System.err.println(String.format("read chunk pos=%d limit=%d capacity=%d", bb.position(), bb.limit(), bb.capacity()));
                System.err.println("chunk hex: " + toHex(bb));
                try {
                    while (true) {
                        CoderResult cr = dec.decode(bb, cb, false);
                        if (cr.isError()) cr.throwException();
                        if (cr.isUnderflow()) break;
                    }
                } catch (CharacterCodingException e) {
                    System.err.println("Decode failure (fixed decoder) on chunk starting at file position " + chunkStart);
                    e.printStackTrace();
                    System.exit(1);
                }
                // preserve any trailing partial bytes for the next read
                bb.compact();
            }

            // final decode of any remaining bytes
            bb.flip();
            try {
                CoderResult cr = dec.decode(bb, cb, true);
                if (cr.isError()) cr.throwException();
                dec.flush(cb);
            } catch (CharacterCodingException e) {
                System.err.println("Decode failure (fixed decoder) at final flush");
                e.printStackTrace();
                System.exit(1);
            }
            System.out.println("Fixed decode OK with chunk size " + chunkSize);
            System.exit(0);
        }
    }
    
    private static String toHex(ByteBuffer bb) {
        StringBuilder sb = new StringBuilder();
        for (int i = bb.position(); i < bb.limit(); i++) {
            sb.append(String.format("%02x ", bb.get(i) & 0xff));
        }
        return sb.toString();
    }
}
