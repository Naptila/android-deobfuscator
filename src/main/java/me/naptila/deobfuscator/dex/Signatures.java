package me.naptila.deobfuscator.dex;

import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.FieldReference;

public final class Signatures {
    private Signatures() {}
    public static String of(FieldReference field) {
        return field.getDefiningClass() + "->" + field.getName() + ":" + field.getType();
    }
    public static String of(MethodReference method) {
        StringBuilder s = new StringBuilder(method.getDefiningClass()).append("->").append(method.getName()).append('(');
        method.getParameterTypes().forEach(s::append);
        return s.append(')').append(method.getReturnType()).toString();
    }
}
