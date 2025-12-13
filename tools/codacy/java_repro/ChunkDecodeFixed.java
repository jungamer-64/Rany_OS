import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class ChunkDecodeFixed {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ChunkDecodeFixed <file> <chunkSize>");
            System.exit(2);
        }
        Path p = Paths.get(args[0]);
        int chunkSize = Integer.parseInt(args[1]);

        try (FileChannel fc = FileChannel.open(p, StandardOpenOption.READ)) {
            ByteBuffer bb = ByteBuffer.allocate(Math.max(64, chunkSize * 2));
            CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder();
            dec.onMalformedInput(CodingErrorAction.REPORT);
            dec.onUnmappableCharacter(CodingErrorAction.REPORT);
            dec.reset();
            CharBuffer cb = CharBuffer.allocate(chunkSize * 2);
            while (fc.read(bb) > 0) {
                bb.flip();
                try {
                    while (true) {
                        CoderResult cr = dec.decode(bb, cb, false);
                        if (cr.isError()) cr.throwException();
                        if (cr.isUnderflow()) break;
                    }
                } catch (CharacterCodingException e) {
                    System.err.println("Decode failure (fixed decoder) during streaming decode");
                    e.printStackTrace();
                    System.exit(1);
                }
                // preserve any trailing partial bytes for the next read
                bb.compact();
                // If the buffer is full of trailing bytes (no room to read more), grow it
                if (bb.position() == bb.capacity()) {
                    int newCap = bb.capacity() * 2;
                    ByteBuffer nb = ByteBuffer.allocate(newCap);
                    bb.flip(); // prepare to read remaining
                    nb.put(bb);
                    bb = nb;
                }
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
