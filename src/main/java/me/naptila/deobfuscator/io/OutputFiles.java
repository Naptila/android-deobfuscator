package me.naptila.deobfuscator.io;

import java.io.IOException;
import java.nio.file.*;

public final class OutputFiles {
    private OutputFiles() {}
    public static void checkNew(Path path) throws IOException {
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) throw new IOException("Refusing to overwrite: " + path);
        if (!Files.isDirectory(path.getParent())) throw new IOException("Output directory does not exist: " + path.getParent());
    }
    public static void writeText(Path path, String text) throws IOException {
        checkNew(path);
        Path temporary = Files.createTempFile(path.getParent(), ".deobfuscator-", ".json");
        try { Files.writeString(temporary, text); Files.move(temporary, path); }
        finally { Files.deleteIfExists(temporary); }
    }
}
