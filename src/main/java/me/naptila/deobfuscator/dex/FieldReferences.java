package me.naptila.deobfuscator.dex;

import java.util.*;
import java.util.function.Consumer;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;
import org.jf.dexlib2.iface.value.*;

/** Field uses in instructions, handles, call sites and nested encoded metadata. */
public final class FieldReferences {
    private FieldReferences() {}
    public static List<FieldReference> collect(DexContext dex, Set<String> ignoredMethodBodies) {
        List<FieldReference> fields = new ArrayList<>(); Consumer<FieldReference> use = fields::add;
        for (ClassDef cls : dex.classes().values()) {
            annotations(cls.getAnnotations(), use);
            for (Field field : cls.getFields()) {
                annotations(field.getAnnotations(), use); value(field.getInitialValue(), use);
            }
            for (Method method : cls.getMethods()) {
                annotations(method.getAnnotations(), use);
                for (MethodParameter parameter : method.getParameters()) annotations(parameter.getAnnotations(), use);
                if (method.getImplementation() == null || ignoredMethodBodies.contains(Signatures.of(method))) continue;
                for (var instruction : method.getImplementation().getInstructions()) {
                    if (instruction instanceof ReferenceInstruction r) reference(r.getReference(), use);
                    if (instruction instanceof DualReferenceInstruction r) reference(r.getReference2(), use);
                }
            }
        }
        return List.copyOf(fields);
    }
    /** Include inherited symbolic owners; unresolved owners conservatively retain matching fields. */
    public static boolean mayResolveTo(DexContext dex, FieldReference use, FieldReference field) {
        if (!use.getName().equals(field.getName()) || !use.getType().equals(field.getType())) return false;
        String owner = use.getDefiningClass(); Set<String> seen = new HashSet<>();
        while (owner != null && seen.add(owner)) {
            if (owner.equals(field.getDefiningClass())) return true;
            if (owner.equals("Ljava/lang/Object;")) return false;
            ClassDef cls = dex.classes().get(owner); if (cls == null) return true;
            // A declaration in the referenced class shadows an inherited field.
            for (Field declared : cls.getFields())
                if (declared.getName().equals(use.getName()) && declared.getType().equals(use.getType())) return false;
            owner = cls.getSuperclass();
        }
        return owner != null; // Malformed inheritance cycle: do not claim absence of a reference.
    }
    private static void annotations(Iterable<? extends Annotation> annotations, Consumer<FieldReference> use) {
        for (Annotation annotation : annotations) for (AnnotationElement element : annotation.getElements()) value(element.getValue(), use);
    }
    private static void reference(Reference reference, Consumer<FieldReference> use) {
        if (reference instanceof FieldReference f) use.accept(f);
        else if (reference instanceof MethodHandleReference h) reference(h.getMemberReference(), use);
        else if (reference instanceof CallSiteReference c) {
            reference(c.getMethodHandle(), use);
            for (EncodedValue argument : c.getExtraArguments()) value(argument, use);
        }
    }
    private static void value(EncodedValue value, Consumer<FieldReference> use) {
        if (value instanceof FieldEncodedValue f) reference(f.getValue(), use);
        else if (value instanceof EnumEncodedValue e) reference(e.getValue(), use);
        else if (value instanceof MethodHandleEncodedValue h) reference(h.getValue(), use);
        else if (value instanceof ArrayEncodedValue a) for (EncodedValue element : a.getValue()) value(element, use);
        else if (value instanceof AnnotationEncodedValue a)
            for (AnnotationElement element : a.getElements()) value(element.getValue(), use);
    }
}
