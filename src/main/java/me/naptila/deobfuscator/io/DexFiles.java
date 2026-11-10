package me.naptila.deobfuscator.io;

import java.io.*;
import java.nio.file.*;
import java.util.Arrays;
import me.naptila.deobfuscator.dex.CodeGraph;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.writer.pool.DexPool;

public final class DexFiles {
    private DexFiles() {}
    public static DexFile read(Path input) throws IOException {
        try (InputStream stream = Files.newInputStream(input)) {
            if (!Arrays.equals(stream.readNBytes(4), new byte[]{'d','e','x','\n'}))
                throw new IllegalArgumentException("Expected standalone DEX; use DeobfuscationRunner.runInput for APK input");
        }
        return DexFileFactory.loadDexFile(input.toFile(), null);
    }
    public static void write(Path output, DexFile dex) throws IOException {
        OutputFiles.checkNew(output);
        Path temporary = Files.createTempFile(output.getParent(), ".deobfuscator-", ".dex");
        try {
            DexPool.writeTo(temporary.toString(), dex);
            DexFile verified = DexFileFactory.loadDexFile(temporary.toFile(), null);
            for (var cls : verified.getClasses()) for (var method : cls.getMethods())
                if (method.getImplementation() != null) new CodeGraph(method.getImplementation());
            Files.move(temporary, output);
        } finally { Files.deleteIfExists(temporary); }
    }
}
