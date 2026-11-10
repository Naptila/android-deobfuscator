package me.naptila.deobfuscator.transformers.np.reflection;

import java.util.*;

import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;
import org.jf.dexlib2.iface.value.*;
import org.jf.dexlib2.immutable.*;

/** Whole-input proof for private string fields; unknown observers fail closed. */
final class PrivateStringFields {
    record Result(DexFile dex, int edits, List<String> notes) {}
    record Site(Method method, int at) {}
    private final DexContext dex;
    private final Set<String> dormant;
    private final Map<String, CodeGraph> graphs = new HashMap<>();
    private final Map<String, ReflectionTypes> types = new HashMap<>();
    private final Map<String, List<Site>> calls = new HashMap<>();
    private final Set<String> metadataMethods = new HashSet<>(), metadataFields = new HashSet<>();
    private final List<String> hazards = new ArrayList<>();
    PrivateStringFields(DexContext dex, Set<String> dormant) {
        this.dex = dex; this.dormant = dormant;
        for (var use : new MethodReferences(dex).uses()) if (!use.directCall()) metadataMethods.add(Signatures.of(use.method()));
        for (ClassDef cls : dex.classes().values()) {
            annotations(cls.getAnnotations());
            for (Field f : cls.getFields()) { annotations(f.getAnnotations()); value(f.getInitialValue()); }
            for (Method m : cls.getMethods()) {
                annotations(m.getAnnotations()); for (var p : m.getParameters()) annotations(p.getAnnotations());
                if (AccessFlags.NATIVE.isSet(m.getAccessFlags())) hazards.add("native:" + Signatures.of(m));
                if (m.getImplementation() == null || dormant.contains(Signatures.of(m))) continue;
                CodeGraph g = graph(m);
                for (int i = 0; i < g.size(); i++) {
                    Instruction insn = g.at(i);
                    if (insn instanceof ReferenceInstruction r) {
                        if (r.getReference() instanceof MethodReference target) {
                            String owner = target.getDefiningClass(), name = target.getName();
                            if (owner.startsWith("Ljava/lang/reflect/") || owner.startsWith("Ljava/lang/invoke/")
                                    || owner.startsWith("Ldalvik/system/") || owner.contains("/Unsafe;")
                                    || owner.equals("Ljava/lang/ClassLoader;")
                                    || owner.equals("Ljava/lang/Class;") && (name.startsWith("getDeclared") || name.startsWith("getField") || name.startsWith("getMethod") || name.equals("forName"))
                                    || (owner.equals("Ljava/lang/System;") || owner.equals("Ljava/lang/Runtime;")) && name.startsWith("load")) hazards.add(Signatures.of(m) + " -> " + Signatures.of(target));
                            if (insn.getOpcode().name.startsWith("invoke-")) calls.computeIfAbsent(Signatures.of(target), k -> new ArrayList<>()).add(new Site(m, i));
                        } else if (!(r.getReference() instanceof FieldReference)) reference(r.getReference());
                    }
                    if (insn instanceof DualReferenceInstruction r) reference(r.getReference2());
                    if (insn.getOpcode().name.startsWith("invoke-custom") || insn.getOpcode().name.startsWith("invoke-polymorphic")) hazards.add("dynamic invocation:" + Signatures.of(m));
                }
            }
        }
    }
    Set<String> provenFields() {
        Set<String> proven = new TreeSet<>(); if (!hazards.isEmpty()) return proven;
        for (Field field : dex.fields().values()) {
            if (!AccessFlags.PRIVATE.isSet(field.getAccessFlags()) || !field.getType().equals(ReflectionModel.STRING) || metadataFields.contains(Signatures.of(field))) continue;
            if (readsOnlyContent(field)) proven.add(Signatures.of(field));
        }
        return proven;
    }
    private boolean readsOnlyContent(Field field) {
        String signature = Signatures.of(field); boolean read = false;
        for (Method m : dex.methods().values()) {
            if (m.getImplementation() == null || dormant.contains(Signatures.of(m))) continue;
            CodeGraph g = graph(m);
            for (int i = 0; i < g.size(); i++) if (g.at(i) instanceof ReferenceInstruction r && r.getReference() instanceof FieldReference f
                    && f.getName().equals(field.getName()) && f.getType().equals(field.getType())) {
                // An inherited or unresolved symbolic field owner is not silently ignored.
                if (!Signatures.of(f).equals(signature)) return false;
                Opcode op = g.at(i).getOpcode();
                if (op == Opcode.IPUT_OBJECT || op == Opcode.SPUT_OBJECT) continue;
                if (op != Opcode.IGET_OBJECT && op != Opcode.SGET_OBJECT) return false;
                read = true;
                if (StringContentUses.onlyContent(g, types(m), i)) continue;
                if (!getter(m, field) || !getterCallersOnlyContent(m)) return false;
            }
        }
        return read;
    }
    private boolean getterCallersOnlyContent(Method getter) {
        String sig = Signatures.of(getter); if (metadataMethods.contains(sig)) return false;
        // Reject alternate symbolic owners rather than missing an inherited call.
        for (var use : new MethodReferences(dex).uses()) if (!Signatures.of(use.method()).equals(sig)
                && !dormant.contains(use.source()) && MethodReferences.mayResolveTo(dex, use.method(), getter)) return false;
        for (Site site : calls.getOrDefault(sig, List.of())) {
            CodeGraph g = graph(site.method()); int at = site.at();
            Opcode op = g.at(at).getOpcode(); if (op != Opcode.INVOKE_STATIC && op != Opcode.INVOKE_STATIC_RANGE) return false;
            if (at + 1 < g.size() && g.at(at + 1).getOpcode() == Opcode.MOVE_RESULT_OBJECT
                    && !StringContentUses.onlyContent(g, types(site.method()), at + 1)) return false;
        }
        return true;
    }
    private boolean getter(Method m, Field field) {
        if (!AccessFlags.STATIC.isSet(m.getAccessFlags()) || !AccessFlags.SYNTHETIC.isSet(m.getAccessFlags())
                || AccessFlags.PUBLIC.isSet(m.getAccessFlags()) || AccessFlags.PROTECTED.isSet(m.getAccessFlags())
                || !m.getReturnType().equals(ReflectionModel.STRING) || !m.getImplementation().getTryBlocks().isEmpty()) return false;
        boolean isStatic = AccessFlags.STATIC.isSet(field.getAccessFlags());
        if (!m.getParameterTypes().equals(isStatic ? List.of() : List.of(field.getDefiningClass()))) return false;
        CodeGraph g = graph(m); int[] facts = new int[g.registers()]; if (!isStatic) facts[g.registers() - 1] = 1;
        int reads = 0;
        for (int i = 0; i < g.size(); i++) {
            Instruction insn = g.at(i); Opcode op = insn.getOpcode();
            if (op == Opcode.NOP) continue;
            if (op.name.startsWith("move-object") && insn instanceof TwoRegisterInstruction move) facts[move.getRegisterA()] = facts[move.getRegisterB()];
            else if (op == (isStatic ? Opcode.SGET_OBJECT : Opcode.IGET_OBJECT) && insn instanceof ReferenceInstruction ref
                    && ref.getReference() instanceof FieldReference f && Signatures.of(f).equals(Signatures.of(field))
                    && (isStatic || facts[((TwoRegisterInstruction)insn).getRegisterB()] == 1)) {
                facts[((OneRegisterInstruction)insn).getRegisterA()] = 2; reads++;
            } else if (op == Opcode.RETURN_OBJECT && i == g.size() - 1) return reads == 1 && facts[((OneRegisterInstruction)insn).getRegisterA()] == 2;
            else return false;
        }
        return false;
    }
    private CodeGraph graph(Method m) { return graphs.computeIfAbsent(Signatures.of(m), k -> new CodeGraph(m.getImplementation())); }
    private ReflectionTypes types(Method m) { return types.computeIfAbsent(Signatures.of(m), k -> new ReflectionTypes(m, graph(m))); }
    private void annotations(Iterable<? extends Annotation> list) { for (var a : list) for (var e : a.getElements()) value(e.getValue()); }
    private void value(EncodedValue v) {
        if (v instanceof FieldEncodedValue f) metadataFields.add(Signatures.of(f.getValue()));
        else if (v instanceof MethodHandleEncodedValue h) reference(h.getValue());
        else if (v instanceof ArrayEncodedValue a) for (var e : a.getValue()) value(e);
        else if (v instanceof AnnotationEncodedValue a) for (var e : a.getElements()) value(e.getValue());
    }
    private void reference(Reference r) {
        if (r instanceof FieldReference f) metadataFields.add(Signatures.of(f));
        else if (r instanceof MethodHandleReference h) reference(h.getMemberReference());
        else if (r instanceof CallSiteReference c) { reference(c.getMethodHandle()); for (var e : c.getExtraArguments()) value(e); }
    }
    static Result clean(DexFile linked, DexContext original, ReflectionModel model, Map<String, Boolean> helpers) {
        DexContext dex = new DexContext(linked); Set<String> dormant = ReflectionReachability.dormant(original, dex, model);
        PrivateStringFields analysis = new PrivateStringFields(dex, dormant); Set<String> fields = analysis.provenFields();
        List<String> notes = new ArrayList<>(); notes.add("Dormant NP runtime methods excluded from private field observation: " + dormant.size());
        if (!analysis.hazards.isEmpty()) { notes.add("Private string fields retained due to dynamic access: " + analysis.hazards); return new Result(linked, 0, notes); }
        if (fields.isEmpty()) { notes.add("No private string fields proven content-only"); return new Result(linked, 0, notes); }
        int edits = 0; List<ClassDef> classes = new ArrayList<>(); Set<String> changed = new TreeSet<>();
        for (ClassDef cls : linked.getClasses()) {
            List<Method> methods = new ArrayList<>();
            for (Method m : cls.getMethods()) {
                if (m.getImplementation() == null || dormant.contains(Signatures.of(m))) { methods.add(m); continue; }
                MethodContext context = new MethodContext(dex, m); int count = ReflectionTransformer.cleanStrings(context, helpers, fields);
                if (count > 0) { ReflectionTransformer.cleanScaffolding(context); methods.add(context.finish()); edits += count; changed.add(Signatures.of(m)); }
                else methods.add(m);
            }
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        notes.add("Private string fields proven content-only: " + fields); notes.add("Private field literal replacements: " + edits); notes.add("Private field literal callers: " + changed);
        return new Result(new ImmutableDexFile(linked.getOpcodes(), classes), edits, notes);
    }
}
