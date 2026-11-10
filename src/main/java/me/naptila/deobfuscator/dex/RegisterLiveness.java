package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.instruction.*;

/** Backward register-word liveness; wide values occupy two words, invoke lists include both. */
public final class RegisterLiveness {
    private final BitSet[] after;
    private final BitSet[] before;
    public RegisterLiveness(CodeGraph graph) {
        int size = graph.size();
        before = new BitSet[size];
        BitSet[] reads = new BitSet[size], writes = new BitSet[size];
        after = new BitSet[size];
        List<List<Integer>> predecessors = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            before[i] = new BitSet(); after[i] = new BitSet();
            reads[i] = reads(graph.at(i)); writes[i] = writes(graph.at(i));
            predecessors.add(new ArrayList<>());
        }
        for (int i = 0; i < size; i++) {
            for (int next : graph.successors(i)) predecessors.get(next).add(i);
            for (int next : graph.handlers(i)) predecessors.get(next).add(i);
        }
        ArrayDeque<Integer> work = new ArrayDeque<>();
        boolean[] queued = new boolean[size];
        for (int i = size - 1; i >= 0; i--) { work.add(i); queued[i] = true; }
        while (!work.isEmpty()) {
            int i = work.removeFirst(); queued[i] = false;
            BitSet normal = new BitSet(), exceptional = new BitSet();
            for (int next : graph.successors(i)) normal.or(before[next]);
            for (int next : graph.handlers(i)) exceptional.or(before[next]);
            after[i] = (BitSet) normal.clone(); after[i].or(exceptional);
            normal.andNot(writes[i]);
            // A throwing instruction need not have written its destination at the handler.
            normal.or(exceptional); normal.or(reads[i]);
            if (!normal.equals(before[i])) {
                before[i] = normal;
                for (int previous : predecessors.get(i)) if (!queued[previous]) {
                    queued[previous] = true; work.add(previous);
                }
            }
        }
    }
    public boolean deadAfter(int index, Instruction instruction) {
        BitSet defined = writes(instruction);
        return !defined.isEmpty() && !after[index].intersects(defined);
    }
    public boolean liveBefore(int index, int register) { return before[index].get(register); }
    public boolean liveAfter(int index, int register) { return after[index].get(register); }
    public static BitSet writes(Instruction i) {
        BitSet result = new BitSet();
        if (i.getOpcode().setsRegister() && i instanceof OneRegisterInstruction one) {
            result.set(one.getRegisterA());
            if (i.getOpcode().setsWideRegister()) result.set(one.getRegisterA() + 1);
        }
        return result;
    }
    public static BitSet reads(Instruction i) {
        BitSet result = new BitSet();
        Opcode op = i.getOpcode(); String name = op.name;
        if (i instanceof VariableRegisterInstruction) {
            for (int register : ConstantEvaluator.arguments(i)) result.set(register);
            return result;
        }
        int[] regs = i instanceof ThreeRegisterInstruction t ? new int[]{t.getRegisterA(), t.getRegisterB(), t.getRegisterC()}
                : i instanceof TwoRegisterInstruction t ? new int[]{t.getRegisterA(), t.getRegisterB()}
                : i instanceof OneRegisterInstruction t ? new int[]{t.getRegisterA()} : new int[0];
        int start = op.setsRegister() && !name.endsWith("/2addr") && op != Opcode.CHECK_CAST ? 1 : 0;
        for (int n = start; n < regs.length; n++) {
            result.set(regs[n]);
            boolean wide;
            if (name.contains("-to-")) wide = name.startsWith("long-to-") || name.startsWith("double-to-");
            else if (name.startsWith("aget") || name.startsWith("iget")) wide = false;
            else if (name.startsWith("aput") || name.startsWith("iput")) wide = name.endsWith("-wide") && n == 0;
            else if (name.startsWith("shl-long") || name.startsWith("shr-long") || name.startsWith("ushr-long"))
                wide = n == (name.endsWith("/2addr") ? 0 : 1);
            else wide = name.contains("wide") || name.endsWith("-long") || name.contains("-long/")
                        || name.endsWith("-double") || name.contains("-double/");
            if (wide) result.set(regs[n] + 1);
        }
        return result;
    }
}
