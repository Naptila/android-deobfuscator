package me.naptila.deobfuscator.dex;

import java.util.BitSet;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.instruction.TwoRegisterInstruction;
import org.jf.dexlib2.iface.reference.MethodReference;

/** Remove repeated or reverse copies when every incoming path proves the registers equal. */
public final class RedundantMoves {
    private RedundantMoves() {}
    public static int run(MethodContext context) {
        CodeGraph graph = context.graph(); BitSet remove = new BitSet();
        List<List<Integer>> previous = new ArrayList<>();
        for (int i = 0; i < graph.size(); i++) previous.add(new ArrayList<>());
        BitSet entries = new BitSet(); if (graph.size() > 0) entries.set(0);
        for (int i = 0; i < graph.size(); i++) {
            for (int next : graph.successors(i)) previous.get(next).add(i);
            for (CodeGraph.Handler handler : graph.protection(i)) entries.set(handler.target());
        }
        for (int i = 0; i < graph.size(); i++) {
            int kind = kind(graph.at(i).getOpcode());
            if (kind == 0) continue;
            var b = (TwoRegisterInstruction)graph.at(i);
            int target = b.getRegisterA(), source = b.getRegisterB();
            if (target == source) { remove.set(i); continue; }
            int width = kind == 3 ? 2 : 1;
            if (width == 2 && Math.abs(target - source) < 2) continue;
            BitSet pair = new BitSet(); pair.set(target, target + width); pair.set(source, source + width);
            if (!entries.get(i) && !previous.get(i).isEmpty()
                    && equalBefore(graph, previous, entries, i, i, kind, target, source, pair, new HashSet<>(), new int[]{64})) remove.set(i);
        }
        ExceptionEdits.remove(context, remove); return remove.cardinality();
    }
    private static boolean equalBefore(CodeGraph graph, List<List<Integer>> previous, BitSet entries, int at, int origin,
            int kind, int target, int source, BitSet pair, Set<Integer> active, int[] budget) {
        if (entries.get(at) || previous.get(at).isEmpty() || budget[0]-- <= 0 || !active.add(at)) return false;
        for (int n : previous.get(at)) {
            if (n == origin) return false;
            var instruction = graph.at(n);
            if (kind == kind(instruction.getOpcode())) {
                var copy = (TwoRegisterInstruction)instruction;
                if (copy.getRegisterA() == target && copy.getRegisterB() == source
                        || copy.getRegisterA() == source && copy.getRegisterB() == target) continue;
            }
            if (RegisterLiveness.writes(instruction).intersects(pair)
                    || instruction.getOpcode() == Opcode.CHECK_CAST && RegisterLiveness.reads(instruction).intersects(pair)
                    // Constructors initialize every receiver alias. Keep the explicit
                    // post-constructor bindings produced by instruction normalization.
                    || kind == 2 && instruction instanceof ReferenceInstruction ref
                        && ref.getReference() instanceof MethodReference method && method.getName().equals("<init>")
                    || !equalBefore(graph, previous, entries, n, origin, kind, target, source, pair, active, budget)) return false;
        }
        active.remove(at); return true;
    }
    private static int kind(Opcode op) {
        return switch(op) {
            case MOVE, MOVE_FROM16, MOVE_16 -> 1;
            case MOVE_OBJECT, MOVE_OBJECT_FROM16, MOVE_OBJECT_16 -> 2;
            case MOVE_WIDE, MOVE_WIDE_FROM16, MOVE_WIDE_16 -> 3;
            default -> 0;
        };
    }
}
