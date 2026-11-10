package me.naptila.deobfuscator;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import me.naptila.deobfuscator.app.*;
import me.naptila.deobfuscator.config.*;
import me.naptila.deobfuscator.app.DeobfuscationRunner;
import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.*;
import me.naptila.deobfuscator.transform.*;
import me.naptila.deobfuscator.dex.DexContext;
import me.naptila.deobfuscator.dex.DexPass;
import me.naptila.deobfuscator.dex.MethodContext;
import me.naptila.deobfuscator.io.ApkArchive;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transform.TransformerProvider;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.MethodImplementationBuilder;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.immutable.*;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class ApkInputTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private Path root() { return directory.getRoot().toPath(); }
    private byte[] dex(String type, int value) throws Exception {
        var code = new MethodImplementationBuilder(1);
        code.addInstruction(new BuilderInstruction31i(Opcode.CONST, 0, value));
        code.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        var method = new ImmutableMethod(type, "value", List.of(), "I", 9, Set.of(), Set.of(), code.getMethodImplementation());
        var cls = new ImmutableClassDef(type, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(method));
        Path file = root().resolve(UUID.randomUUID() + ".dex");
        DexFiles.write(file, new ImmutableDexFile(Opcodes.forApi(28), List.of(cls)));
        return Files.readAllBytes(file);
    }
    private Path apk(String filename, Map<String, byte[]> code) throws Exception {
        Path file = root().resolve(filename);
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(file))) {
            put(out, "AndroidManifest.xml", new byte[]{1, 2, 3}, true);
            put(out, "resources.arsc", new byte[]{4, 5, 6, 7}, true);
            put(out, "lib/arm64-v8a/libfixture.so", new byte[]{9, 8, 7}, true);
            put(out, "assets/中文.txt", "中文\nresource".getBytes(StandardCharsets.UTF_8), false);
            put(out, "META-INF/services/fixture", new byte[]{42}, false);
            put(out, "META-INF/CERT.RSA", new byte[]{0}, false);
            put(out, "META-INF/CERT.SF", new byte[]{0}, false);
            put(out, "META-INF/MANIFEST.MF", new byte[]{0}, false);
            for (var entry : code.entrySet()) put(out, entry.getKey(), entry.getValue(), entry.getKey().equals("classes.dex"));
        }
        return file;
    }
    private static void put(ZipOutputStream out, String name, byte[] data, boolean stored) throws IOException {
        ZipEntry entry = new ZipEntry(name);
        if (stored) {
            CRC32 crc = new CRC32(); crc.update(data);
            entry.setMethod(ZipEntry.STORED); entry.setSize(data.length); entry.setCrc(crc.getValue());
        }
        out.putNextEntry(entry); out.write(data); out.closeEntry();
    }
    private RunConfiguration config(Path input, String output, boolean preview, List<TransformerSpec> specs) {
        return new RunConfiguration(input, root().resolve(output), root().resolve(output + ".json"), preview, 20, specs);
    }
    private DeobfuscationRunner runner() { return new DeobfuscationRunner(new Deobfuscator(TransformerRegistry.discover())); }

    @Test public void multidexIsAnalyzedTogetherAndWrittenBackToOriginalOwners() throws Exception {
        Path input = apk("input.apk", Map.of("classes.dex", dex("Lprimary/Test;", 7), "classes2.dex", dex("Lsecondary/Test;", 9)));
        boolean[] prepared = {false};
        var registry = new TransformerRegistry(List.of(new TransformerProvider() {
            public String id() { return "test.cross-dex"; }
            public String description() { return "Requires both original DEX classes"; }
            public DexPass create(TransformerOptions options) {
                return new DexPass() {
                    public String id() { return "test.cross-dex"; }
                    public void prepare(DexContext context) {
                        assertFalse(prepared[0]); prepared[0] = true;
                        assertEquals(Set.of("Lprimary/Test;", "Lsecondary/Test;"), context.classes().keySet());
                    }
                    public PassResult run(MethodContext context) {
                        var first = context.code().getInstructions().get(0);
                        if (((org.jf.dexlib2.iface.instruction.NarrowLiteralInstruction) first).getNarrowLiteral() == 73) return PassResult.unchanged();
                        context.code().replaceInstruction(0, new BuilderInstruction31i(Opcode.CONST, 0, 73));
                        return PassResult.changed(1);
                    }
                };
            }
        }));
        var config = config(input, "output.apk", false, List.of(new TransformerSpec("test.cross-dex")));
        var result = new DeobfuscationRunner(new Deobfuscator(registry)).runInput(config);
        assertTrue(prepared[0]); assertTrue(result.apk()); assertEquals(2, result.result().changedMethods());
        assertEquals(List.of("classes.dex", "classes2.dex"), result.dexEntries());
        try (ApkArchive output = new ApkArchive(config.output())) {
            assertEquals(result.classOwners(), output.classOwners());
            for (var cls : output.combined().getClasses()) for (var method : cls.getMethods()) assertEquals(73, Fixtures.execute(method, 0));
        }
        String report = Files.readString(config.report());
        assertTrue(report.contains("\"outputSigning\": \"unsigned\""));
        assertTrue(report.contains("classes2.dex"));
    }

    @Test public void resourcesCompressionAndAlignmentArePreservedButSignaturesRemoved() throws Exception {
        Path input = apk("input.apk", Map.of("classes.dex", dex("Lsample/Test;", 1)));
        var config = config(input, "output.apk", false, List.of());
        runner().runInput(config);
        try (ZipFile before = new ZipFile(input.toFile()); ZipFile after = new ZipFile(config.output().toFile())) {
            for (String name : List.of("AndroidManifest.xml", "resources.arsc", "lib/arm64-v8a/libfixture.so", "assets/中文.txt", "META-INF/services/fixture")) {
                try (InputStream a = before.getInputStream(before.getEntry(name)); InputStream b = after.getInputStream(after.getEntry(name))) {
                    assertArrayEquals(a.readAllBytes(), b.readAllBytes());
                }
                assertEquals(before.getEntry(name).getMethod(), after.getEntry(name).getMethod());
            }
            assertNull(after.getEntry("META-INF/CERT.RSA"));
            assertNull(after.getEntry("META-INF/CERT.SF"));
            assertNull(after.getEntry("META-INF/MANIFEST.MF"));
            byte[] raw = Files.readAllBytes(config.output());
            int offset = 0;
            while (u16(raw, offset) == 0x4b50 && u16(raw, offset + 2) == 0x0403) {
                int nameLength = u16(raw, offset + 26), extraLength = u16(raw, offset + 28);
                String name = new String(raw, offset + 30, nameLength, StandardCharsets.UTF_8);
                int start = offset + 30 + nameLength + extraLength;
                ZipEntry entry = after.getEntry(name);
                if (entry.getMethod() == ZipEntry.STORED) assertEquals(name, 0, start % (name.endsWith(".so") ? 16384 : 4));
                offset = start + (int) entry.getCompressedSize() + ((u16(raw, offset + 6) & 8) != 0 ? 16 : 0);
            }
        }
    }
    private static int u16(byte[] bytes, int offset) { return (bytes[offset] & 255) | (bytes[offset + 1] & 255) << 8; }

    @Test public void previewDoesNotWriteApkAndExistingOutputsAreNeverOverwritten() throws Exception {
        Path input = apk("input.apk", Map.of("classes.dex", dex("Lsample/Test;", 1)));
        var config = config(input, "preview.apk", true, List.of());
        runner().runInput(config);
        assertFalse(Files.exists(config.output()));
        assertTrue(Files.readString(config.report()).contains("not-written"));
        var blocked = config(input, "blocked.apk", false, List.of());
        Files.writeString(blocked.output(), "keep");
        assertThrows(IOException.class, () -> runner().runInput(blocked));
        assertEquals("keep", Files.readString(blocked.output()));
        assertFalse(Files.exists(blocked.report()));
    }

    @Test public void duplicateClassesAndBadSecondaryDexAbortWithoutPublishing() throws Exception {
        byte[] dex = dex("Lsample/Test;", 1);
        Path duplicate = apk("duplicate.apk", Map.of("classes.dex", dex, "classes2.dex", dex));
        Path malformed = apk("malformed.apk", Map.of("classes.dex", dex, "classes2.dex", new byte[]{1, 2, 3}));
        for (Path input : List.of(duplicate, malformed)) {
            var config = config(input, input.getFileName() + ".output.apk", false, List.of());
            assertThrows(Exception.class, () -> runner().runInput(config));
            assertFalse(Files.exists(config.output())); assertFalse(Files.exists(config.report()));
        }
    }

    @Test public void unknownGeneratedClassCannotBeSilentlyAssignedToAnotherDex() throws Exception {
        Path input = apk("input.apk", Map.of("classes.dex", dex("Lsample/Test;", 1)));
        Path output = root().resolve("output.apk");
        try (ApkArchive apk = new ApkArchive(input)) {
            Path other = root().resolve("other.dex"); Files.write(other, dex("Lunknown/Test;", 2));
            assertThrows(IOException.class, () -> apk.write(output, DexFiles.read(other)));
        }
        assertFalse(Files.exists(output));
        try (var files = Files.list(root())) { assertFalse(files.anyMatch(p -> p.getFileName().toString().startsWith(".deobfuscator-apk-"))); }
    }

    @Test public void invalidSecondaryOutputCleansStagingAndDoesNotPublishPartialApk() throws Exception {
        Path input = apk("input.apk", Map.of("classes.dex", dex("Lprimary/Test;", 1), "classes2.dex", dex("Lsecondary/Test;", 2)));
        Path output = root().resolve("output.apk");
        try (ApkArchive apk = new ApkArchive(input)) {
            var invalidCode = new ImmutableMethodImplementation(0,
                    List.of(new org.jf.dexlib2.immutable.instruction.ImmutableInstruction10t(Opcode.GOTO, 127)), List.of(), List.of());
            var method = new ImmutableMethod("Lsecondary/Test;", "broken", List.of(), "V", 9, Set.of(), Set.of(), invalidCode);
            var invalidClass = new ImmutableClassDef("Lsecondary/Test;", 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), List.of(method));
            var primary = apk.combined().getClasses().stream().filter(c -> c.getType().equals("Lprimary/Test;")).findFirst().orElseThrow();
            var invalid = new ImmutableDexFile(apk.combined().getOpcodes(), List.of(primary, invalidClass));
            assertThrows(Exception.class, () -> apk.write(output, invalid));
        }
        assertFalse(Files.exists(output));
        try (var files = Files.list(root())) { assertFalse(files.anyMatch(p -> p.getFileName().toString().startsWith(".deobfuscator-apk-"))); }
    }
}
