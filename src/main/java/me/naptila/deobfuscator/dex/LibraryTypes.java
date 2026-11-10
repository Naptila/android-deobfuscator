package me.naptila.deobfuscator.dex;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.JarFile;

/** Class-file metadata only: never defines, initializes or executes a library class. */
public final class LibraryTypes {
    public record Type(String name, int flags, String parent, List<String> interfaces, Map<String, Integer> members) {}
    private final Map<String, Type> types;
    public LibraryTypes(List<String> jars) {
        Map<String, Type> loaded = new HashMap<>();
        for (String name : jars) try (JarFile jar = new JarFile(Path.of(name).toFile())) {
            var entries = jar.entries();
            while (entries.hasMoreElements()) {
                var entry = entries.nextElement();
                if (!entry.getName().endsWith(".class") || entry.getName().startsWith("META-INF/") || entry.getName().equals("module-info.class")) continue;
                Type type;
                try (var in = new DataInputStream(new BufferedInputStream(jar.getInputStream(entry)))) { type = read(in); }
                Type previous = loaded.putIfAbsent(type.name(), type);
                if (previous != null && !previous.equals(type)) throw new IOException("Conflicting class: " + type.name());
            }
        } catch (IOException error) { throw new IllegalArgumentException("Cannot read classpath " + name + ": " + error.getMessage(), error); }
        types = Map.copyOf(loaded);
    }
    public Type get(String name) { return types.get(name); }
    private static Type read(DataInputStream in) throws IOException {
        if (in.readInt() != 0xcafebabe) throw new IOException("Invalid class file");
        in.readUnsignedShort(); in.readUnsignedShort(); Object[] pool = new Object[in.readUnsignedShort()];
        for (int i = 1; i < pool.length; i++) switch (in.readUnsignedByte()) {
            case 1 -> pool[i] = in.readUTF();
            case 7 -> pool[i] = in.readUnsignedShort();
            case 3, 4, 9, 10, 11, 12, 17, 18 -> in.skipNBytes(4);
            case 5, 6 -> { in.skipNBytes(8); i++; }
            case 8, 16, 19, 20 -> in.skipNBytes(2);
            case 15 -> in.skipNBytes(3);
            default -> throw new IOException("Unknown constant pool tag");
        }
        int flags = in.readUnsignedShort(); String name = type(pool, in.readUnsignedShort());
        int parent = in.readUnsignedShort(); List<String> interfaces = new ArrayList<>();
        for (int count = in.readUnsignedShort(); count > 0; count--) interfaces.add(type(pool, in.readUnsignedShort()));
        Map<String, Integer> members = new HashMap<>();
        for (int kind = 0; kind < 2; kind++) for (int count = in.readUnsignedShort(); count > 0; count--) {
            int access = in.readUnsignedShort(); String member = (String)pool[in.readUnsignedShort()]; String descriptor = (String)pool[in.readUnsignedShort()];
            members.put(member + (kind == 0 ? ":" : "") + descriptor, access); attributes(in);
        }
        attributes(in);
        return new Type(name, flags, parent == 0 ? null : type(pool, parent), List.copyOf(interfaces), Map.copyOf(members));
    }
    private static String type(Object[] pool, int index) { return "L" + pool[(Integer)pool[index]] + ";"; }
    private static void attributes(DataInputStream in) throws IOException {
        for (int count = in.readUnsignedShort(); count > 0; count--) { in.readUnsignedShort(); in.skipNBytes(Integer.toUnsignedLong(in.readInt())); }
    }
}
