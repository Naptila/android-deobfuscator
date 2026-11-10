package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.instruction.*;

/** Must-known 64-bit values for constants, copies, signed int widening and XOR. */
public final class WideConstantAnalysis {
    private final List<Map<Integer, Long>> before;
    private final CodeGraph graph;
    private final ConstantAnalysis integers;
    public WideConstantAnalysis(CodeGraph graph, ConstantAnalysis integers) {
        this.graph = graph; this.integers = integers;
        before = new ArrayList<>(Collections.nCopies(graph.size(), null));
        if (graph.size() == 0) return;
        before.set(0, new HashMap<>());
        ArrayDeque<Integer> work = new ArrayDeque<>(); work.add(0);
        BitSet queued = new BitSet(); queued.set(0);
        long budget = Math.max(10000L, (long)graph.size() * 256);
        while (!work.isEmpty()) {
            if (--budget == 0) throw new IllegalStateException("Wide constant analysis work limit exceeded");
            int i = work.removeFirst(); queued.clear(i);
            Map<Integer, Long> out = new HashMap<>(before.get(i));
            Long value = valueAt(i);
            invalidate(out, RegisterLiveness.writes(graph.at(i)));
            if (value != null) out.put(((OneRegisterInstruction)graph.at(i)).getRegisterA(), value);
            for (int target : graph.successors(i)) propagate(target, out, work, queued);
            // A throw cannot establish a new value; preserve only unaffected pairs.
            Map<Integer, Long> exceptional = new HashMap<>(before.get(i));
            invalidate(exceptional, RegisterLiveness.writes(graph.at(i)));
            for (int target : graph.handlers(i)) propagate(target, exceptional, work, queued);
        }
    }
    public Long valueAt(int index) {
        Map<Integer, Long> state = before.get(index); if (state == null) return null;
        Instruction i = graph.at(index); Opcode op = i.getOpcode();
        return switch(op) {
            case CONST_WIDE, CONST_WIDE_16, CONST_WIDE_32, CONST_WIDE_HIGH16 -> ((WideLiteralInstruction)i).getWideLiteral();
            case MOVE_WIDE, MOVE_WIDE_FROM16, MOVE_WIDE_16 -> state.get(((TwoRegisterInstruction)i).getRegisterB());
            case INT_TO_LONG -> {
                Constants facts = integers.before(index);
                Object value = facts == null ? null : facts.get(((TwoRegisterInstruction)i).getRegisterB());
                yield value instanceof Integer n ? n.longValue() : null;
            }
            case XOR_LONG, XOR_LONG_2ADDR -> {
                var r = (TwoRegisterInstruction)i;
                Long left = state.get(op == Opcode.XOR_LONG ? r.getRegisterB() : r.getRegisterA());
                Long right = state.get(op == Opcode.XOR_LONG ? ((ThreeRegisterInstruction)i).getRegisterC() : r.getRegisterB());
                yield left == null || right == null ? null : left ^ right;
            }
            default -> null;
        };
    }
    private static void invalidate(Map<Integer, Long> state, BitSet words) {
        state.keySet().removeIf(r -> words.get(r) || words.get(r + 1));
    }
    private void propagate(int target, Map<Integer, Long> out, ArrayDeque<Integer> work, BitSet queued) {
        Map<Integer, Long> old = before.get(target); boolean changed;
        if (old == null) { before.set(target, new HashMap<>(out)); changed = true; }
        else changed = old.entrySet().removeIf(e -> !Objects.equals(e.getValue(), out.get(e.getKey())));
        if (changed && !queued.get(target)) { work.add(target); queued.set(target); }
    }
}
