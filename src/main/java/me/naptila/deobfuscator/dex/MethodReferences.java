package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;
import org.jf.dexlib2.iface.value.*;

/** Reference graph including encoded metadata, method handles and invoke-custom bootstrap arguments. */
public final class MethodReferences {
    public record Use(String source, MethodReference method, String kind, boolean directCall) {}
    private final List<Use> uses = new ArrayList<>();
    private final Set<String> strings = new TreeSet<>();
    public List<Use> uses() { return List.copyOf(uses); }
    public Set<String> strings() { return Collections.unmodifiableSet(strings); }
    public MethodReferences(DexContext dex) {
        for (ClassDef cls : dex.classes().values()) {
            annotations(cls.getType(), cls.getAnnotations());
            for (Field f : cls.getFields()) { annotations(Signatures.of(f), f.getAnnotations()); value(Signatures.of(f), f.getInitialValue()); }
            for (Method m : cls.getMethods()) {
                String source = Signatures.of(m); annotations(source, m.getAnnotations());
                for (MethodParameter p : m.getParameters()) annotations(source, p.getAnnotations());
                if (m.getImplementation() == null) continue;
                for (Instruction i : m.getImplementation().getInstructions()) {
                    if (i instanceof ReferenceInstruction r) reference(source, r.getReference(), "instruction:" + i.getOpcode().name, i.getOpcode().name.startsWith("invoke-"));
                    if (i instanceof DualReferenceInstruction r) reference(source, r.getReference2(), "secondary-reference", false);
                }
            }
        }
    }
    private void annotations(String source, Iterable<? extends Annotation> annotations) {
        for (Annotation a : annotations) for (AnnotationElement e : a.getElements()) value(source, e.getValue());
    }
    private void reference(String source, Reference ref, String kind, boolean direct) {
        if (ref instanceof MethodReference m) uses.add(new Use(source, m, kind, direct));
        else if (ref instanceof StringReference s) strings.add(s.getString());
        else if (ref instanceof MethodHandleReference h) reference(source, h.getMemberReference(), "method-handle", false);
        else if (ref instanceof CallSiteReference c) {
            strings.add(c.getMethodName()); reference(source, c.getMethodHandle(), "bootstrap", false);
            for (EncodedValue v : c.getExtraArguments()) value(source, v);
        }
    }
    private void value(String source, EncodedValue v) {
        if (v instanceof MethodEncodedValue m) reference(source, m.getValue(), "encoded-method", false);
        else if (v instanceof MethodHandleEncodedValue h) reference(source, h.getValue(), "encoded-handle", false);
        else if (v instanceof StringEncodedValue s) strings.add(s.getValue());
        else if (v instanceof ArrayEncodedValue a) for (EncodedValue e : a.getValue()) value(source, e);
        else if (v instanceof AnnotationEncodedValue a) for (AnnotationElement e : a.getElements()) value(source, e.getValue());
    }
    /** Inherited symbolic owners and unresolved ancestry are conservatively included. */
    public static boolean mayResolveTo(DexContext dex, MethodReference use, MethodReference candidate) {
        if (!use.getName().equals(candidate.getName()) || !use.getReturnType().equals(candidate.getReturnType())
                || !parameterTypes(use).equals(parameterTypes(candidate))) return false;
        return hierarchy(dex, use.getDefiningClass(), candidate, new HashSet<>());
    }
    private static List<String> parameterTypes(MethodReference method) {
        // ImmutableMethod exposes MethodParameter CharSequences; instruction references
        // expose Strings. List.equals is not a descriptor comparison across these forms.
        return method.getParameterTypes().stream().map(CharSequence::toString).toList();
    }
    private static boolean hierarchy(DexContext dex, String owner, MethodReference candidate, Set<String> path) {
        if (owner == null || owner.equals("Ljava/lang/Object;")) return false;
        if (owner.equals(candidate.getDefiningClass())) return true;
        if (!path.add(owner)) return true;
        ClassDef cls = dex.classes().get(owner); if (cls == null) return true;
        String key = owner + "->" + candidate.getName() + "(" + String.join("", candidate.getParameterTypes()) + ")" + candidate.getReturnType();
        if (dex.methods().containsKey(key)) return false;
        if (hierarchy(dex, cls.getSuperclass(), candidate, new HashSet<>(path))) return true;
        for (String itf : cls.getInterfaces()) if (hierarchy(dex, itf, candidate, new HashSet<>(path))) return true;
        return false;
    }
}
