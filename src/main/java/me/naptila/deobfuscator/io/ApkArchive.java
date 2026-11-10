package me.naptila.deobfuscator.io;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.immutable.ImmutableDexFile;

/** APK container IO. Code is analyzed together but retains its original DEX ownership. */
public final class ApkArchive implements AutoCloseable {
    private final ZipFile zip;
    private final List<ZipEntry> entries = new ArrayList<>();
    private final Map<String, DexFile> dexes = new LinkedHashMap<>();
    private final Map<String, String> owners = new HashMap<>();
    private final List<String> removedSignatures = new ArrayList<>();
    private final DexFile combined;

    public ApkArchive(Path input) throws IOException {
        zip = new ZipFile(input.toFile());
        try {
            Set<String> names = new HashSet<>();
            var enumeration = zip.entries();
            while (enumeration.hasMoreElements()) {
                ZipEntry entry = enumeration.nextElement();
                if (!names.add(entry.getName())) throw new IOException("Duplicate APK entry: " + entry.getName());
                entries.add(entry);
                if (signature(entry.getName())) removedSignatures.add(entry.getName());
            }
            if (!names.contains("AndroidManifest.xml") || !names.contains("classes.dex"))
                throw new IOException("APK must contain AndroidManifest.xml and classes.dex");
            List<ZipEntry> code = entries.stream().filter(e -> e.getName().matches("classes(?:[2-9]|[1-9][0-9]+)?\\.dex"))
                    .sorted(Comparator.comparing(e -> dexNumber(e.getName()))).toList();
            List<ClassDef> classes = new ArrayList<>();
            for (ZipEntry entry : code) {
                DexFile dex;
                try (InputStream stream = new BufferedInputStream(zip.getInputStream(entry))) {
                    dex = DexBackedDexFile.fromInputStream(null, stream);
                }
                if (!dexes.isEmpty() && dex.getOpcodes().api != dexes.values().iterator().next().getOpcodes().api)
                    throw new IOException("Mixed DEX versions are not supported: " + entry.getName());
                dexes.put(entry.getName(), dex);
                for (ClassDef cls : dex.getClasses()) {
                    String previous = owners.putIfAbsent(cls.getType(), entry.getName());
                    if (previous != null) throw new IOException("Duplicate class " + cls.getType() + " in " + previous + " and " + entry.getName());
                    classes.add(cls);
                }
            }
            combined = new ImmutableDexFile(dexes.values().iterator().next().getOpcodes(), classes);
        } catch (IOException | RuntimeException | Error failure) {
            try { zip.close(); } catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }
    public DexFile combined() { return combined; }
    public List<String> dexNames() { return List.copyOf(dexes.keySet()); }
    public Map<String, String> classOwners() { return Map.copyOf(owners); }
    public List<String> removedSignatures() { return List.copyOf(removedSignatures); }

    public void write(Path output, DexFile transformed) throws IOException {
        OutputFiles.checkNew(output);
        Map<String, List<ClassDef>> partition = new LinkedHashMap<>();
        dexes.keySet().forEach(name -> partition.put(name, new ArrayList<>()));
        for (ClassDef cls : transformed.getClasses()) {
            String owner = owners.get(cls.getType());
            if (owner == null) throw new IOException("Cannot assign generated class to an original DEX: " + cls.getType());
            partition.get(owner).add(cls);
        }
        Path work = Files.createTempDirectory(output.getParent(), ".deobfuscator-apk-");
        try {
            Map<String, Path> replacements = new LinkedHashMap<>();
            for (var entry : partition.entrySet()) {
                Path file = work.resolve(entry.getKey()); // Only validated, root-level DEX names.
                DexFiles.write(file, new ImmutableDexFile(dexes.get(entry.getKey()).getOpcodes(), entry.getValue()));
                replacements.put(entry.getKey(), file);
            }
            Path packed = work.resolve("output.apk");
            try (CountingOutputStream counter = new CountingOutputStream(new BufferedOutputStream(Files.newOutputStream(packed)));
                 ZipOutputStream out = new ZipOutputStream(counter)) {
                for (ZipEntry original : entries) {
                    if (signature(original.getName())) continue;
                    Path replacement = replacements.get(original.getName());
                    ZipEntry target = new ZipEntry(original.getName());
                    target.setMethod(original.getMethod());
                    // A DOS-range timestamp avoids auto-generated local extra fields changing alignment.
                    target.setTimeLocal(java.time.LocalDateTime.of(2000, 1, 1, 0, 0));
                    if (original.getTimeLocal() != null && original.getTimeLocal().getYear() >= 1980
                            && original.getTimeLocal().getYear() <= 2099) target.setTimeLocal(original.getTimeLocal());
                    target.setComment(original.getComment());
                    if (target.getMethod() == ZipEntry.STORED) {
                        long size = replacement == null ? original.getSize() : Files.size(replacement);
                        long crc = replacement == null ? original.getCrc() : crc(replacement);
                        if (size >= 0xffffffffL) throw new IOException("ZIP64 stored entries are not supported");
                        target.setSize(size);
                        target.setCompressedSize(size);
                        target.setCrc(crc);
                        int alignment = original.getName().startsWith("lib/") && original.getName().endsWith(".so") ? 16384 : 4;
                        long dataOffset = counter.count + 30 + target.getName().getBytes(StandardCharsets.UTF_8).length;
                        int padding = (int) ((alignment - dataOffset % alignment) % alignment);
                        if (padding != 0) {
                            if (padding < 4) padding += alignment;
                            byte[] extra = new byte[padding];
                            extra[0] = (byte) 0xfe; extra[1] = (byte) 0xca;
                            extra[2] = (byte) (padding - 4); extra[3] = (byte) ((padding - 4) >>> 8);
                            target.setExtra(extra);
                        }
                    }
                    out.putNextEntry(target);
                    try (InputStream stream = replacement == null ? zip.getInputStream(original) : Files.newInputStream(replacement)) {
                        stream.transferTo(out);
                    }
                    out.closeEntry();
                }
            }
            Files.move(packed, output);
        } finally {
            try (var files = Files.list(work)) {
                for (Path file : files.toList()) Files.deleteIfExists(file);
            }
            Files.deleteIfExists(work);
        }
    }
    private static BigInteger dexNumber(String name) {
        return name.equals("classes.dex") ? BigInteger.ONE : new BigInteger(name.substring(7, name.length() - 4));
    }
    private static boolean signature(String name) {
        String upper = name.toUpperCase(Locale.ROOT);
        if (!upper.startsWith("META-INF/")) return false;
        String leaf = upper.substring(9);
        return !leaf.contains("/") && (leaf.equals("MANIFEST.MF") || leaf.endsWith(".SF") || leaf.endsWith(".RSA")
                || leaf.endsWith(".DSA") || leaf.endsWith(".EC") || leaf.startsWith("SIG-"));
    }
    private static long crc(Path file) throws IOException {
        CRC32 crc = new CRC32();
        try (InputStream stream = new CheckedInputStream(Files.newInputStream(file), crc)) { stream.transferTo(OutputStream.nullOutputStream()); }
        return crc.getValue();
    }
    public void close() throws IOException { zip.close(); }
    private static final class CountingOutputStream extends FilterOutputStream {
        private long count;
        CountingOutputStream(OutputStream out) { super(out); }
        public void write(int value) throws IOException { out.write(value); count++; }
        public void write(byte[] bytes, int offset, int length) throws IOException { out.write(bytes, offset, length); count += length; }
    }
}
