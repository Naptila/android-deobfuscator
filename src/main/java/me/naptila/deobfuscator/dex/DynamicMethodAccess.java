package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.iface.reference.MethodReference;

/** Unresolved dynamic method access blocks definition removal, including in closed-world mode. */
public final class DynamicMethodAccess {
    private DynamicMethodAccess() {}
    public static List<String> hazards(DexContext dex, MethodReferences references) {
        Set<String> hazards = new TreeSet<>();
        for (var m : dex.methods().values()) if (AccessFlags.NATIVE.isSet(m.getAccessFlags())) hazards.add("native:" + Signatures.of(m));
        for (var use : references.uses()) if (dynamic(use.method())) hazards.add(use.source() + " -> " + Signatures.of(use.method()));
        return List.copyOf(hazards);
    }
    private static boolean dynamic(MethodReference m) {
        String owner = m.getDefiningClass(), name = m.getName();
        return (owner.equals("Ljava/lang/Class;") && (name.startsWith("getDeclaredMethod") || name.startsWith("getMethod")
                || name.startsWith("getDeclaredConstructor") || name.startsWith("getConstructor") || name.equals("getEnclosingMethod") || name.equals("forName")))
                || owner.equals("Ljava/lang/reflect/Method;") || owner.equals("Ljava/lang/reflect/Constructor;")
                || owner.startsWith("Ljava/lang/invoke/MethodHandle")
                || owner.startsWith("Ldalvik/system/")
                || (owner.equals("Ljava/lang/ClassLoader;") && (name.contains("Class") || name.equals("<init>")))
                || ((owner.equals("Ljava/lang/System;") || owner.equals("Ljava/lang/Runtime;")) && name.startsWith("load"));
    }
}
