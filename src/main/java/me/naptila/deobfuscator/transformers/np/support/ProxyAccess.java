package me.naptila.deobfuscator.transformers.np.support;

import me.naptila.deobfuscator.dex.*;
import java.util.*;

import me.naptila.deobfuscator.dex.*;
import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;

/** Fail closed on unresolved members. Platform reflection reads bootstrap metadata only. */
/** Shared DEX access and class-initialization checks used before replacing or removing helper operations. */
public final class ProxyAccess {
    private ProxyAccess() {}
    public static boolean visible(int flags, String owner, String caller) {
        return owner.equals(caller) || AccessFlags.PUBLIC.isSet(flags)
                || (!AccessFlags.PRIVATE.isSet(flags) && packageName(owner).equals(packageName(caller)));
    }
    public static String packageName(String type) { return type.substring(0, Math.max(0, type.lastIndexOf('/'))); }
    public static boolean type(DexContext dex, String type, String caller) {
        while (type.startsWith("[")) type = type.substring(1);
        if (type.length() == 1) return true;
        ClassDef cls = dex.classes().get(type);
        if (cls != null) return visible(cls.getAccessFlags(), type, caller);
        Class<?> platform = platform(type);
        return platform != null && java.lang.reflect.Modifier.isPublic(platform.getModifiers());
    }
    public static boolean type(DexContext dex, MemberResolver resolver, String type, String caller) {
        while (type.startsWith("[")) type = type.substring(1);
        if (type.length() == 1) return true;
        Integer flags = resolver.typeFlags(type);
        return flags == null ? type(dex, type, caller) : visible(flags, type, caller);
    }
    public static boolean member(DexContext dex, MemberResolver resolver, Reference ref, String caller, boolean write) {
        String owner = ref instanceof MethodReference m ? m.getDefiningClass() : ((FieldReference)ref).getDefiningClass();
        var resolved = resolver.resolve(ref);
        if (resolved == null) return member(dex, ref, caller, write);
        return type(dex, resolver, owner, caller) && visible(resolved.flags(), resolved.owner(), caller)
                && (!write || !AccessFlags.FINAL.isSet(resolved.flags()));
    }
    public static boolean member(DexContext dex, Reference ref, String caller, boolean write) {
        String owner = ref instanceof MethodReference m ? m.getDefiningClass() : ((FieldReference)ref).getDefiningClass();
        if (!type(dex, owner, caller)) return false;
        if (ref instanceof MethodReference m) {
            Method method = dex.methods().get(Signatures.of(m));
            if (method != null) return visible(method.getAccessFlags(), owner, caller);
            Class<?> platform = platform(owner);
            if (platform == null) return false;
            // No class loading from the input DEX, no invocation, and no class initialization.
            for (java.lang.reflect.Method methodInfo : platform.getMethods()) {
                if (methodInfo.getName().equals(m.getName()) && descriptor(methodInfo.getReturnType()).equals(m.getReturnType())
                        && java.util.Arrays.stream(methodInfo.getParameterTypes()).map(ProxyAccess::descriptor).toList().equals(m.getParameterTypes()))
                    return true;
            }
        } else {
            FieldReference f = (FieldReference)ref;
            Field field = dex.fields().get(Signatures.of(f));
            if (field != null) return visible(field.getAccessFlags(), owner, caller) && (!write || !AccessFlags.FINAL.isSet(field.getAccessFlags()));
            Class<?> platform = platform(owner);
            if (platform == null) return false;
            try {
                var member = platform.getField(f.getName());
                return descriptor(member.getType()).equals(f.getType()) && (!write || !java.lang.reflect.Modifier.isFinal(member.getModifiers()));
            } catch (NoSuchFieldException ignored) { return false; }
        }
        return false;
    }
    private static String descriptor(Class<?> cls) { return cls.descriptorString(); }
    private static Class<?> platform(String type) {
        if (!type.startsWith("Ljava/") && !type.startsWith("Ljavax/")) return null;
        try { return Class.forName(type.substring(1, type.length() - 1).replace('/', '.'), false, null); }
        catch (ClassNotFoundException | LinkageError error) { return null; }
    }
    public static boolean initializationSafe(DexContext dex, String owner, String caller) {
        if (owner.equals(caller)) return true;
        ClassDef cls = dex.classes().get(owner);
        if (cls == null || !"Ljava/lang/Object;".equals(cls.getSuperclass()) || !cls.getInterfaces().isEmpty()) return false;
        for (Method method : cls.getMethods()) if (method.getName().equals("<clinit>")) return false;
        return true;
    }

    /** Successful static operations establish initialization; handlers keep the pre-throw facts. */
    public static Map<String, BitSet> initializedBefore(MethodContext context, CodeGraph graph, Set<String> requested) {
        return completedBefore(context, graph, requested, false, null, Map.of());
    }

    /** Track exact calls, including initialization of dependencies reached inside the callee. */
    public static Map<String, BitSet> successfulCallsBefore(MethodContext context, CodeGraph graph, Set<String> requested, BitSet provenCalls) {
        return completedBefore(context, graph, requested, true, provenCalls, Map.of());
    }

    /** A decoded forwarding call can prove completion of its verified leaf decryptors. */
    public static Map<String, BitSet> successfulCallsBefore(MethodContext context, CodeGraph graph, Set<String> requested,
                                                           Map<Integer, Set<String>> completedCalls) {
        return completedBefore(context, graph, requested, true, null, completedCalls);
    }

    private static Map<String, BitSet> completedBefore(MethodContext context, CodeGraph graph, Set<String> requested, boolean calls,
                                                      BitSet provenCalls, Map<Integer, Set<String>> completedCalls) {
        Map<String, Integer> owners = new HashMap<>();
        for (int i = 0; i < graph.size(); i++) if (graph.at(i) instanceof ReferenceInstruction ref) {
            Reference member = ref.getReference();
            String owner = member instanceof MethodReference m ? calls ? Signatures.of(m) : m.getDefiningClass()
                    : !calls && member instanceof FieldReference f ? f.getDefiningClass() : null;
            if (owner != null && requested.contains(owner)) owners.computeIfAbsent(owner, key -> owners.size());
        }
        for (Set<String> completed : completedCalls.values()) for (String signature : completed)
            if (requested.contains(signature)) owners.computeIfAbsent(signature, key -> owners.size());
        if (owners.isEmpty() || graph.size() == 0) return Map.of();
        BitSet[] triggers = new BitSet[graph.size()];
        for (int i = 0; i < graph.size(); i++) {
            Instruction instruction = graph.at(i); Opcode op = instruction.getOpcode();
            if (!(instruction instanceof ReferenceInstruction ref)) continue;
            String owner = null;
            if ((op == Opcode.INVOKE_STATIC || op == Opcode.INVOKE_STATIC_RANGE) && ref.getReference() instanceof MethodReference method) {
                var definition = context.dex().methods().get(Signatures.of(method));
                if (definition != null && AccessFlags.STATIC.isSet(definition.getAccessFlags()))
                    owner = calls ? Signatures.of(definition) : definition.getDefiningClass();
            } else if (!calls && (op.name.startsWith("sget") || op.name.startsWith("sput")) && ref.getReference() instanceof FieldReference field) {
                var definition = context.dex().fields().get(Signatures.of(field));
                if (definition != null && AccessFlags.STATIC.isSet(definition.getAccessFlags())) owner = definition.getDefiningClass();
            }
            Integer trigger = owners.get(owner);
            if (trigger != null && (!calls || provenCalls != null && provenCalls.get(i))) {
                triggers[i] = new BitSet(); triggers[i].set(trigger);
            }
            if (calls && (op == Opcode.INVOKE_STATIC || op == Opcode.INVOKE_STATIC_RANGE))
                for (String signature : completedCalls.getOrDefault(i, Set.of())) {
                    var definition = context.dex().methods().get(signature);
                    Integer target = owners.get(signature);
                    if (target == null || definition == null || !AccessFlags.STATIC.isSet(definition.getAccessFlags())) continue;
                    if (triggers[i] == null) triggers[i] = new BitSet();
                    triggers[i].set(target);
                }
        }
        BitSet[] before = new BitSet[graph.size()]; before[0] = new BitSet();
        Integer caller = calls ? null : owners.get(context.original().getDefiningClass());
        if (caller != null) before[0].set(caller);
        ArrayDeque<Integer> work = new ArrayDeque<>(); work.add(0);
        BitSet queued = new BitSet(); queued.set(0);
        long budget = Math.max(10000L, (long)graph.size() * 256);
        while (!work.isEmpty()) {
            if (--budget == 0) return Map.of();
            int at = work.removeFirst(); queued.clear(at);
            BitSet out = (BitSet)before[at].clone();
            if (triggers[at] != null) out.or(triggers[at]);
            for (int next : graph.successors(at)) mergeInitialization(before, next, out, work, queued);
            for (int next : graph.handlers(at)) mergeInitialization(before, next, before[at], work, queued);
        }
        Map<String, BitSet> result = new HashMap<>();
        for (var owner : owners.entrySet()) {
            BitSet sites = new BitSet();
            for (int i = 0; i < graph.size(); i++) if (before[i] != null && before[i].get(owner.getValue())) sites.set(i);
            result.put(owner.getKey(), sites);
        }
        return result;
    }

    private static void mergeInitialization(BitSet[] before, int target, BitSet state, ArrayDeque<Integer> work, BitSet queued) {
        BitSet merged = (BitSet)state.clone();
        if (before[target] != null) merged.and(before[target]);
        if (!merged.equals(before[target])) {
            before[target] = merged;
            if (!queued.get(target)) { work.add(target); queued.set(target); }
        }
    }
}
