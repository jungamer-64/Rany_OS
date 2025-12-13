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

public class ChunkDecodeCompare {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: ChunkDecodeCompare <file> <chunkSize>");
            System.exit(2);
        }
        Path p = Paths.get(args[0]);
        int chunkSize = Integer.parseInt(args[1]);

        System.out.println("Running bad decoder (per-chunk endOfInput=true)");
        boolean badOk = badDecode(p, chunkSize);
        System.out.println("bad decoder OK=" + badOk);

        System.out.println("Running fixed streaming decoder");
        boolean fixedOk = fixedDecode(p, chunkSize);
        System.out.println("fixed decoder OK=" + fixedOk);

        if (!badOk && fixedOk) {
            System.out.println("=> Fixed decoder resolves the issue (bad fails, fixed succeeds)");
            System.exit(0);
        }
        System.out.println("=> Result: badOk=" + badOk + " fixedOk=" + fixedOk);
        System.exit((badOk && fixedOk) ? 0 : 1);
    }

    private static boolean badDecode(Path p, int chunkSize) throws Exception {
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
                // simulate incorrect usage: endOfInput=true for every chunk
                try {
                    System.err.println("badDecode: chunk start=" + pos + " r=" + r + " bytes=" + toHex(bb));
                    CoderResult cr = dec.decode(bb, cb, true);
                    if (cr.isError()) cr.throwException();
                    dec.flush(cb);
                } catch (CharacterCodingException e) {
                    System.err.println("badDecode exception at chunk start=" + pos + " bytesRemaining=" + toHex(bb));
                    throw e;
                }
                pos += r;
            }
            return true;
        } catch (CharacterCodingException e) {
            System.err.println("badDecode error: " + e.toString());
            return false;
        }
    }

    private static boolean fixedDecode(Path p, int chunkSize) throws Exception {
        try (FileChannel fc = FileChannel.open(p, StandardOpenOption.READ)) {
            ByteBuffer bb = ByteBuffer.allocate(chunkSize);
            CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder();
            dec.onMalformedInput(CodingErrorAction.REPORT);
            dec.onUnmappableCharacter(CodingErrorAction.REPORT);
            dec.reset();
            CharBuffer cb = CharBuffer.allocate(chunkSize * 2);
            int chunkNo = 0;
            while (fc.read(bb) > 0) {
                chunkNo++;
                bb.flip();
                try {
                    while (true) {
                        CoderResult cr = dec.decode(bb, cb, false);
                        if (cr.isError()) cr.throwException();
                        if (cr.isUnderflow()) break;
                    }
                } catch (CharacterCodingException e) {
                    System.err.println("fixedDecode exception during streaming at chunk=" + chunkNo + " bytesRemaining=" + toHex(bb));
                    throw e;
                }
                bb.compact();
            }
            bb.flip();
            CoderResult cr = dec.decode(bb, cb, true);
            if (cr.isError()) cr.throwException();
            dec.flush(cb);
            return true;
        } catch (CharacterCodingException e) {
            System.err.println("fixedDecode error: " + e.toString());
            return false;
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
