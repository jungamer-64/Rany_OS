import java.nio.file.Files;
import java.nio.file.Paths;

public class TestRead {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("Usage: TestRead <file> ...");
            System.exit(2);
        }
        for (String path : args) {
            try {
                Files.lines(Paths.get(path)).forEach(s -> {});
                System.out.println(path + " OK");
            } catch (Exception e) {
                System.err.println(path + " error:" + e);
                e.printStackTrace();
            }
        }
    }
}