package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.reference.*;

/** Resolves exact descriptors through the input and explicitly supplied library hierarchy. */
public final class MemberResolver {
    public record Member(String owner, int flags, int ownerFlags) {}
    private final DexContext dex;
    private final LibraryTypes libraries;
    public MemberResolver(DexContext dex, LibraryTypes libraries) { this.dex = dex; this.libraries = libraries; }
    public Integer typeFlags(String type) {
        ClassDef cls = dex.classes().get(type); if (cls != null) return cls.getAccessFlags();
        var library = libraries.get(type); return library == null ? null : library.flags();
    }
    /** Verifier-style reference assignability using only supplied metadata. */
    public boolean assignable(String actual, String expected) {
        return assignable(actual, expected, new HashSet<>());
    }
    private boolean assignable(String actual, String expected, Set<String> seen) {
        if (actual == null) return false;
        if (actual.equals(expected)) return true;
        boolean ref = expected.startsWith("L") || expected.startsWith("[");
        if (actual.equals("null")) return ref;
        if (!ref || !(actual.startsWith("L") || actual.startsWith("["))) return false;
        if (expected.equals("Ljava/lang/Object;")) return true;
        if (actual.startsWith("[")) {
            if (expected.equals("Ljava/lang/Cloneable;") || expected.equals("Ljava/io/Serializable;")) return true;
            return expected.startsWith("[") && assignable(actual.substring(1), expected.substring(1), seen);
        }
        if (!seen.add(actual)) return false;
        ClassDef cls = dex.classes().get(actual); var library = libraries.get(actual);
        String parent = cls != null ? cls.getSuperclass() : library != null ? library.parent() : null;
        List<String> interfaces = cls != null ? cls.getInterfaces() : library != null ? library.interfaces() : List.of();
        if (assignable(parent, expected, seen)) return true;
        for (String type : interfaces) if (assignable(type, expected, seen)) return true;
        return false;
    }
    public Member resolve(Reference reference) {
        String owner, key;
        if (reference instanceof MethodReference method) {
            owner = method.getDefiningClass(); key = method.getName() + "(" + String.join("", method.getParameterTypes()) + ")" + method.getReturnType();
        } else if (reference instanceof FieldReference field) { owner = field.getDefiningClass(); key = field.getName() + ":" + field.getType(); }
        else return null;
        return resolve(owner, key, new HashSet<>());
    }
    private Member resolve(String owner, String key, Set<String> seen) {
        if (owner == null || !seen.add(owner)) return null;
        String parent; List<String> interfaces;
        ClassDef cls = dex.classes().get(owner);
        if (cls != null) {
            Method method = dex.methods().get(owner + "->" + key);
            Field field = dex.fields().get(owner + "->" + key);
            if (method != null) return new Member(owner, method.getAccessFlags(), cls.getAccessFlags());
            if (field != null) return new Member(owner, field.getAccessFlags(), cls.getAccessFlags());
            parent = cls.getSuperclass(); interfaces = cls.getInterfaces();
        } else {
            var library = libraries.get(owner); if (library == null) return null;
            Integer flags = library.members().get(key);
            if (flags != null) return new Member(owner, flags, library.flags());
            parent = library.parent(); interfaces = library.interfaces();
        }
        Member inherited = resolve(parent, key, seen); if (inherited != null) return inherited;
        for (String type : interfaces) { inherited = resolve(type, key, seen); if (inherited != null) return inherited; }
        return null;
    }
}
