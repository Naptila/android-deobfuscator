package me.naptila.deobfuscator.transformers.np.instructions;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.BuilderInstruction;
import org.jf.dexlib2.builder.instruction.BuilderInstruction32x;
import org.jf.dexlib2.builder.instruction.BuilderInstruction23x;
import org.jf.dexlib2.iface.instruction.*;

/** Cancel integer offsets or negations around one sum without moving reads or effects. */
final class AdditiveOffsets {
    private AdditiveOffsets() {}

    static boolean rewriteOne(MethodContext context) {
        int arithmetic = 0;
        boolean literal = false;
        for (Instruction instruction : context.code().getInstructions()) {
            String name = instruction.getOpcode().name;
            if (name.startsWith("add-int") || name.startsWith("sub-int") || name.startsWith("rsub-int")
                    || instruction.getOpcode() == Opcode.NEG_INT) arithmetic++;
            literal |= instruction instanceof NarrowLiteralInstruction || instruction.getOpcode() == Opcode.NEG_INT;
        }
        if (arithmetic < 2 || !literal) return false;
        CodeGraph graph = context.graph();
        ConstantAnalysis facts = new ConstantAnalysis(graph, ConstantEvaluator::step, false, true);
        RegisterLiveness live = new RegisterLiveness(graph);
        int[] incoming = incoming(graph);
        for (int start = 0; start < graph.size(); start++) {
            Offset first = offset(graph.at(start), facts.before(start));
            if (first == null || first.scale() == 1 && first.value() == 0) continue;
            // Original values equal scale * rewritten value + offset. Copies can
            // carry the same relation; no observer may read a changed value.
            BitSet affected = new BitSet(); affected.set(first.destination());
            int carrier = first.destination();
            int scale = first.scale(), value = first.value(), combine = -1;
            BuilderInstruction combined = null;
            boolean added = false;
            Set<Integer> visited = new HashSet<>(); visited.add(start);
            int previous = start;
            for (int budget = 0; budget < 64; budget++) {
                if (graph.successors(previous).size() != 1) break;
                int end = graph.successors(previous).get(0);
                if (incoming[end] != 1 || graph.isPayload(end) || !visited.add(end)) break;
                previous = end;
                Instruction instruction = graph.at(end);
                if (CodeGraph.isGoto(instruction.getOpcode())) continue;
                // A handler could observe an intermediate offset value. Do not change it.
                if (instruction.getOpcode().canThrow() && !graph.handlers(end).isEmpty()) break;
                Offset last = offset(instruction, facts.before(end));
                if (added && last != null && last.source() == carrier
                        && last.scale() * scale == 1 && last.scale() * value + last.value() == 0) {
                    if (!unobserved(affected, last.destination(), live, end)) break;
                    List<Edits.Edit> edits = new ArrayList<>();
                    BitSet remove = new BitSet();
                    replaceOffset(start, first, edits, remove);
                    replaceOffset(end, last, edits, remove);
                    if (combined != null) edits.add(new Edits.Edit(combine, false, List.of(combined)));
                    apply(context, edits, remove);
                    return true;
                }
                BitSet reads = RegisterLiveness.reads(instruction);
                if (reads.intersects(affected)) {
                    if ((instruction.getOpcode() == Opcode.MOVE || instruction.getOpcode() == Opcode.MOVE_FROM16
                            || instruction.getOpcode() == Opcode.MOVE_16) && instruction instanceof TwoRegisterInstruction move
                            && move.getRegisterB() == carrier) {
                        carrier = move.getRegisterA(); affected.set(carrier); continue;
                    }
                    int[] add = addition(instruction);
                    // Exactly one tainted input: x+x has twice the offset and is not this pattern.
                    if (added || add == null || affected.get(add[1]) == affected.get(add[2])) break;
                    if (add[1] != carrier && add[2] != carrier) break;
                    boolean subtract = instruction.getOpcode() == Opcode.SUB_INT || instruction.getOpcode() == Opcode.SUB_INT_2ADDR;
                    boolean right = add[2] == carrier;
                    if (scale == -1 || subtract && right) {
                        int other = right ? add[1] : add[2];
                        combined = new BuilderInstruction23x(scale == -1
                                ? subtract ? Opcode.ADD_INT : Opcode.SUB_INT : Opcode.SUB_INT, add[0], carrier, other);
                        combine = end;
                    }
                    if (subtract && right) { scale = -scale; value = -value; }
                    carrier = add[0]; affected.set(carrier); added = true;
                    // A preceding expression rewrite may already have absorbed the
                    // outer negation: y - (-x) closes the relation at this sum.
                    if (scale == 1 && value == 0 && unobserved(affected, carrier, live, end)) {
                        List<Edits.Edit> edits = new ArrayList<>(); BitSet remove = new BitSet();
                        replaceOffset(start, first, edits, remove);
                        if (combined != null) edits.add(new Edits.Edit(combine, false, List.of(combined)));
                        apply(context, edits, remove);
                        return true;
                    }
                } else if (RegisterLiveness.writes(instruction).intersects(affected)) {
                    BitSet writes = RegisterLiveness.writes(instruction);
                    if (writes.get(carrier)) break;
                    affected.andNot(writes);
                }
                if (!instruction.getOpcode().canContinue() || CodeGraph.isIf(instruction.getOpcode())
                        || CodeGraph.isSwitch(instruction.getOpcode())) break;
            }
        }
        return false;
    }

    private static boolean unobserved(BitSet affected, int destination, RegisterLiveness live, int end) {
        BitSet remaining = (BitSet) affected.clone(); remaining.clear(destination);
        for (int r = remaining.nextSetBit(0); r >= 0; r = remaining.nextSetBit(r + 1))
            if (live.liveAfter(end, r)) return false;
        return true;
    }

    private static void apply(MethodContext context, List<Edits.Edit> edits, BitSet remove) {
        List<BuilderInstruction> removed = new ArrayList<>();
        for (int r = remove.nextSetBit(0); r >= 0; r = remove.nextSetBit(r + 1))
            removed.add(context.code().getInstructions().get(r));
        Edits.apply(context.code(), edits);
        // Branch relaxation during replacement can insert instructions elsewhere.
        remove.clear();
        for (BuilderInstruction old : removed) remove.set(old.getLocation().getIndex());
        ExceptionEdits.remove(context, remove);
    }

    static int[] incoming(CodeGraph graph) {
        int[] counts = new int[graph.size()];
        if (graph.size() != 0) counts[0]++;
        for (int i = 0; i < graph.size(); i++) {
            for (int next : graph.successors(i)) counts[next]++;
            for (var handler : graph.protection(i)) counts[handler.target()]++;
        }
        return counts;
    }

    private static void replaceOffset(int index, Offset offset, List<Edits.Edit> edits, BitSet remove) {
        if (offset.destination() == offset.source()) remove.set(index);
        else edits.add(new Edits.Edit(index, false, List.of(
                new BuilderInstruction32x(Opcode.MOVE_16, offset.destination(), offset.source()))));
    }

    private static Offset offset(Instruction instruction, Constants facts) {
        Opcode op = instruction.getOpcode();
        if (op == Opcode.NEG_INT) {
            TwoRegisterInstruction r = (TwoRegisterInstruction) instruction;
            return new Offset(r.getRegisterA(), r.getRegisterB(), -1, 0);
        }
        if (op == Opcode.ADD_INT_LIT8 || op == Opcode.ADD_INT_LIT16 || op == Opcode.RSUB_INT || op == Opcode.RSUB_INT_LIT8) {
            TwoRegisterInstruction r = (TwoRegisterInstruction) instruction;
            return new Offset(r.getRegisterA(), r.getRegisterB(), op == Opcode.ADD_INT_LIT8 || op == Opcode.ADD_INT_LIT16 ? 1 : -1,
                    ((NarrowLiteralInstruction) instruction).getNarrowLiteral());
        }
        int[] args = addition(instruction);
        if (args == null || facts == null) return null;
        Object left = facts.get(args[1]), right = facts.get(args[2]);
        if (left instanceof Integer && right instanceof Integer) return null;
        boolean subtract = op == Opcode.SUB_INT || op == Opcode.SUB_INT_2ADDR;
        if (right instanceof Integer n) return new Offset(args[0], args[1], 1, subtract ? -n : n);
        if (left instanceof Integer n) return new Offset(args[0], args[2], subtract ? -1 : 1, n);
        return null;
    }

    private static int[] addition(Instruction instruction) {
        if (instruction.getOpcode() == Opcode.ADD_INT || instruction.getOpcode() == Opcode.SUB_INT) {
            ThreeRegisterInstruction r = (ThreeRegisterInstruction) instruction;
            return new int[]{r.getRegisterA(), r.getRegisterB(), r.getRegisterC()};
        }
        if (instruction.getOpcode() == Opcode.ADD_INT_2ADDR || instruction.getOpcode() == Opcode.SUB_INT_2ADDR) {
            TwoRegisterInstruction r = (TwoRegisterInstruction) instruction;
            return new int[]{r.getRegisterA(), r.getRegisterA(), r.getRegisterB()};
        }
        return null;
    }

    private record Offset(int destination, int source, int scale, int value) {}
}
