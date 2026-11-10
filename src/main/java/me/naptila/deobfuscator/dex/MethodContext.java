package me.naptila.deobfuscator.dex;

import org.jf.dexlib2.builder.MutableMethodImplementation;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.immutable.ImmutableMethod;

public final class MethodContext {
    private final Method original;
    private final String name;
    private CodeGraph originalGraph;
    private MutableMethodImplementation code;
    private final DexContext dex;
    private final java.util.List<TransformationEvidence.Replacement> replacements = new java.util.ArrayList<>();
    private final java.util.Map<String, Integer> invocations = new java.util.HashMap<>();
    // Instruction identity follows insertions/deletions; snapshot indices do not.
    // These are call-site proofs, never a whitelist for every call to a method.
    private final java.util.Set<org.jf.dexlib2.iface.instruction.Instruction> decodedStringCalls =
            java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());

    public void recordDecodedStringCall(org.jf.dexlib2.iface.instruction.Instruction instruction) {
        decodedStringCalls.add(instruction);
    }
    public boolean decodedStringCall(org.jf.dexlib2.iface.instruction.Instruction instruction) {
        return decodedStringCalls.contains(instruction);
    }

    public int nextInvocation(String producer) { return invocations.merge(producer, 1, Integer::sum); }
    public void recordReplacement(String producer, String target, int invocation, int index, int address) {
        replacements.add(new TransformationEvidence.Replacement(producer, target, name(), invocation, index, address));
    }
    java.util.List<TransformationEvidence.Replacement> replacements() { return java.util.List.copyOf(replacements); }

    public MethodContext(Method method) {
        this(null, method);
    }
    public MethodContext(DexContext dex, Method method) {
        if (method.getImplementation() == null) throw new IllegalArgumentException("Method has no code");
        original = method;
        name = Signatures.of(method);
        this.dex = dex;
        code = new MutableMethodImplementation(method.getImplementation());
    }
    public String name() { return name; }
    public Method original() { return original; }
    /** Immutable original graph, shared by rules and unaffected by transaction edits. */
    public CodeGraph originalGraph() {
        if (originalGraph == null) originalGraph = new CodeGraph(original.getImplementation());
        return originalGraph;
    }
    /** Original input, not partially rewritten methods. Standalone contexts have no DEX. */
    public DexContext dex() {
        if (dex == null) throw new IllegalStateException("Standalone MethodContext has no DEX context");
        return dex;
    }
    public MutableMethodImplementation code() { return code; }
    /** Reserve scratch after the old register file, copying new incoming parameters to their old locations. */
    public void appendScratchRegisters(int count) {
        if (count < 1) throw new IllegalArgumentException("Scratch count must be positive");
        java.util.List<String> types = new java.util.ArrayList<>();
        if (!org.jf.dexlib2.AccessFlags.STATIC.isSet(original.getAccessFlags())) types.add(original.getDefiningClass());
        original.getParameterTypes().forEach(t -> types.add(t.toString()));
        int words = types.stream().mapToInt(t -> t.equals("J") || t.equals("D") ? 2 : 1).sum();
        int oldCount = code.getRegisterCount(), newCount = oldCount + count + words;
        if (newCount > 65535) throw new IllegalArgumentException("DEX register limit exceeded");
        code = new MutableMethodImplementation(new org.jf.dexlib2.immutable.ImmutableMethodImplementation(
                newCount, code.getInstructions(), code.getTryBlocks(), code.getDebugItems()));
        decodedStringCalls.clear();
        int oldParameter = oldCount - words, newParameter = oldCount + count, index = 0;
        for (String type : types) {
            boolean wide = type.equals("J") || type.equals("D");
            org.jf.dexlib2.Opcode op = wide ? org.jf.dexlib2.Opcode.MOVE_WIDE_16
                    : type.startsWith("L") || type.startsWith("[") ? org.jf.dexlib2.Opcode.MOVE_OBJECT_16 : org.jf.dexlib2.Opcode.MOVE_16;
            code.addInstruction(index++, new org.jf.dexlib2.builder.instruction.BuilderInstruction32x(op, oldParameter, newParameter));
            oldParameter += wide ? 2 : 1; newParameter += wide ? 2 : 1;
        }
    }
    /** Replace metadata and instructions together after label-based relocation. */
    public void replaceCode(org.jf.dexlib2.iface.MethodImplementation replacement) {
        if (replacement.getRegisterCount() != code.getRegisterCount()) throw new IllegalArgumentException("Register count changed");
        code = new MutableMethodImplementation(replacement);
        // Rebuilding clones instructions. Discard proofs rather than assigning
        // an old offset to a different operation; the next string pass reproves it.
        decodedStringCalls.clear();
    }
    /** Fresh snapshot after each pass: no stale instruction addresses or analysis caches. */
    public CodeGraph graph() { BranchRelaxation.run(code); return new CodeGraph(code); }
    public Method finish() {
        BranchRelaxation.run(code);
        return new ImmutableMethod(original.getDefiningClass(), original.getName(), original.getParameters(),
                original.getReturnType(), original.getAccessFlags(), original.getAnnotations(),
                original.getHiddenApiRestrictions(), code);
    }
}
