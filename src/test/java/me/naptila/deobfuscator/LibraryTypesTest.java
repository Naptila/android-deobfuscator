package me.naptila.deobfuscator;

import java.nio.file.*;
import java.util.*;
import java.util.jar.*;
import javax.tools.ToolProvider;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.LibraryTypes;
import me.naptila.deobfuscator.dex.MemberResolver;
import org.jf.dexlib2.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class LibraryTypesTest {
    @Rule public TemporaryFolder folder = new TemporaryFolder();
    @Test public void readsMetadataWithoutInitializingClassesAndResolvesInheritance() throws Exception {
        Path root = folder.getRoot().toPath(); Path source = root.resolve("Library.java");
        Files.writeString(source, "package probe; public class Library { static { if (true) throw new Error(\"must not run\"); } public static final long value=4; private int secret; public long twice(long x){return 2*x;} } class Child extends Library {} interface Calls { int run(); } class ViaInterface implements Calls { public int run(){return 1;} }");
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null, "-d", root.toString(), source.toString()));
        Path jar = root.resolve("library.jar");
        try(var out = new JarOutputStream(Files.newOutputStream(jar)); var files = Files.walk(root)) {
            for(Path file : files.filter(p -> p.toString().endsWith(".class")).toList()) { out.putNextEntry(new JarEntry(root.relativize(file).toString())); out.write(Files.readAllBytes(file)); out.closeEntry(); }
        }
        LibraryTypes library = new LibraryTypes(List.of(jar.toString()));
        var dex = new DexContext(new ImmutableDexFile(Opcodes.getDefault(), List.of()));
        var resolver = new MemberResolver(dex, library);
        var resolved = resolver.resolve(new ImmutableMethodReference("Lprobe/Child;", "twice", List.of("J"), "J"));
        assertEquals("Lprobe/Library;", resolved.owner()); assertTrue(AccessFlags.PUBLIC.isSet(resolved.flags()));
        assertNull(resolver.resolve(new ImmutableMethodReference("Lprobe/Child;", "twice", List.of("I"), "J")));
        var field = resolver.resolve(new ImmutableFieldReference("Lprobe/Child;", "value", "J"));
        assertTrue(AccessFlags.FINAL.isSet(field.flags())); assertTrue(AccessFlags.STATIC.isSet(field.flags()));
        assertTrue(AccessFlags.PRIVATE.isSet(resolver.resolve(new ImmutableFieldReference("Lprobe/Library;", "secret", "I")).flags()));
        assertEquals("Ljava/lang/Object;", library.get("Lprobe/Library;").parent());
    }
}
