package me.naptila.deobfuscator.transformers.np.reflection;

import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.ConstantEvaluator;
import me.naptila.deobfuscator.dex.RegisterLiveness;
import me.naptila.deobfuscator.dex.Signatures;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;

/** May-alias traversal: every use of one string result must consume its value without retaining its identity. */
final class StringContentUses {
    static boolean onlyContent(CodeGraph g, ReflectionTypes types, int result) { return onlyContent(g, types, result, Set.of()); }
    static boolean onlyContent(CodeGraph g, ReflectionTypes types, int result, Set<String> contentFields) {
        BitSet initial = new BitSet(); initial.set(((OneRegisterInstruction)g.at(result)).getRegisterA());
        BitSet[] before = new BitSet[g.size()]; ArrayDeque<Integer> work = new ArrayDeque<>(); BitSet queued = new BitSet();
        for (int next : g.successors(result)) enqueue(next, initial, before, work, queued);
        int budget = Math.max(10000, g.size() * 256);
        while (!work.isEmpty()) {
            if (--budget == 0) return false;
            int at = work.removeFirst(); queued.clear(at); BitSet state = before[at], out = (BitSet)state.clone();
            Instruction i = g.at(at); Opcode op = i.getOpcode();
            BitSet reads = RegisterLiveness.reads(i); reads.and(state);
            out.andNot(RegisterLiveness.writes(i));
            if (op.name.startsWith("move-object") && i instanceof TwoRegisterInstruction move) {
                if (state.get(move.getRegisterB())) out.set(move.getRegisterA());
            } else if (op == Opcode.CHECK_CAST) {
                int reg = ((OneRegisterInstruction)i).getRegisterA(); if (state.get(reg)) out.set(reg);
            } else if (!reads.isEmpty()) {
                if ((op == Opcode.IPUT_OBJECT || op == Opcode.SPUT_OBJECT) && i instanceof ReferenceInstruction r
                        && r.getReference() instanceof FieldReference field && contentFields.contains(Signatures.of(field))
                        && state.get(((OneRegisterInstruction)i).getRegisterA())
                        && (op == Opcode.SPUT_OBJECT || !state.get(((TwoRegisterInstruction)i).getRegisterB()))) { /* proven private content sink */ }
                else if (op == Opcode.IF_EQZ || op == Opcode.IF_NEZ) { /* nullness is unchanged */ }
                else if (!(i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference method
                        && op.name.startsWith("invoke-") && consumesContent(i, method, state, types, at))) return false;
            }
            // Exceptional successors see the old register values, not a successful destination write.
            for (int next : g.handlers(at)) enqueue(next, state, before, work, queued);
            for (int next : g.successors(at)) enqueue(next, out, before, work, queued);
        }
        return true;
    }
    private static void enqueue(int at, BitSet state, BitSet[] before, ArrayDeque<Integer> work, BitSet queued) {
        if (state.isEmpty()) return;
        boolean changed;
        if (before[at] == null) { before[at] = (BitSet)state.clone(); changed = true; }
        else { BitSet old = (BitSet)before[at].clone(); before[at].or(state); changed = !old.equals(before[at]); }
        if (changed && !queued.get(at)) { queued.set(at); work.add(at); }
    }
    private static boolean consumesContent(Instruction i, MethodReference m, BitSet aliases, ReflectionTypes types, int at) {
        int[] args = ConstantEvaluator.arguments(i); String owner = m.getDefiningClass(), name = m.getName();
        List<String> params = m.getParameterTypes().stream().map(Object::toString).toList(); String ret = m.getReturnType();
        boolean isStatic = i.getOpcode() == Opcode.INVOKE_STATIC || i.getOpcode() == Opcode.INVOKE_STATIC_RANGE;
        if (owner.equals("Landroid/util/Log;") && isStatic && ret.equals("I")
                && Set.of("v", "d", "i", "w", "e").contains(name)
                && (params.equals(List.of(ReflectionModel.STRING, ReflectionModel.STRING)) || params.equals(List.of(ReflectionModel.STRING, ReflectionModel.STRING, "Ljava/lang/Throwable;")))) {
            return args.length == params.size() && (args.length < 3 || !aliases.get(args[2]));
        }
        if (isStatic || (i.getOpcode() != Opcode.INVOKE_VIRTUAL && i.getOpcode() != Opcode.INVOKE_VIRTUAL_RANGE && i.getOpcode() != Opcode.INVOKE_DIRECT && i.getOpcode() != Opcode.INVOKE_DIRECT_RANGE)) return false;
        if ((owner.equals("Ljava/lang/StringBuilder;") || owner.equals("Ljava/lang/StringBuffer;")) && args.length == 2 && !aliases.get(args[0])
                && (name.equals("append") && ret.equals(owner) && (params.equals(List.of(ReflectionModel.STRING)) || params.equals(List.of(ReflectionModel.OBJECT)))
                || name.equals("<init>") && ret.equals("V") && params.equals(List.of(ReflectionModel.STRING)))) return true;
        if (!owner.equals(ReflectionModel.STRING) || args.length == 0) return false;
        var receiver = types.get(at, args[0]);
        if (receiver == null || !receiver.type().equals(ReflectionModel.STRING)) return false;
        String signature = name + "(" + String.join("", params) + ")" + ret;
        // All return primitives. Identity-returning operations (substring, trim, toString, intern) stay out.
        return Set.of("length()I", "isEmpty()Z", "charAt(I)C", "hashCode()I", "equals(Ljava/lang/Object;)Z",
                "equalsIgnoreCase(Ljava/lang/String;)Z", "compareTo(Ljava/lang/String;)I", "compareToIgnoreCase(Ljava/lang/String;)I",
                "startsWith(Ljava/lang/String;)Z", "startsWith(Ljava/lang/String;I)Z", "endsWith(Ljava/lang/String;)Z",
                "indexOf(I)I", "indexOf(II)I", "indexOf(Ljava/lang/String;)I", "indexOf(Ljava/lang/String;I)I",
                "lastIndexOf(I)I", "lastIndexOf(II)I", "lastIndexOf(Ljava/lang/String;)I", "lastIndexOf(Ljava/lang/String;I)I").contains(signature);
    }
}
