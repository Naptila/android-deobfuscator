package me.naptila.deobfuscator.dex;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.MutableMethodImplementation;
import org.jf.dexlib2.builder.Label;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.immutable.ImmutableMethodImplementation;

/** Lay out basic blocks in reverse postorder without changing their operations or edges. */
public final class BlockLayout {
    private BlockLayout() {}

    public static int run(MethodContext context) {
        // Debug scopes stay untouched; exception coverage is relocated by labels below.
        if (context.code().getDebugItems().iterator().hasNext()) return 0;
        CodeGraph graph = context.graph(); int size = graph.size();
        if (size == 0 || size > 4096 || graph.leaders().size() > 512) return 0;
        for (int i = 0; i < size; i++)
            if (graph.isPayload(i) || CodeGraph.isSwitch(graph.at(i).getOpcode()) || graph.at(i).getOpcode() == Opcode.FILL_ARRAY_DATA) return 0;

        List<Integer> starts = new ArrayList<>(graph.leaders());
        int blocks = starts.size(); int[] owner = new int[size], ends = new int[blocks];
        for (int b = 0; b < blocks; b++) {
            ends[b] = (b + 1 < blocks ? starts.get(b + 1) : size) - 1;
            for (int i = starts.get(b); i <= ends[b]; i++) owner[i] = b;
        }
        BitSet seen = new BitSet();
        List<Integer> order = reversePostorder(graph, ends, owner, 0, seen);
        var handlers = new TreeSet<Integer>();
        for (int i = 0; i < size; i++) for (CodeGraph.Handler handler : graph.protection(i)) handlers.add(owner[handler.target()]);
        for (int handler : handlers) if (!seen.get(handler)) order.addAll(reversePostorder(graph, ends, owner, handler, seen));
        // A reachable fall-off is malformed input, not a new fallthrough to place.
        if (seen.get(owner[size - 1]) && graph.at(size - 1).getOpcode().canContinue()) return 0;
        for (int b = 0; b < blocks; b++) if (!seen.get(b)) order.add(b);
        boolean changed = false;
        for (int b = 0; b < blocks; b++) changed |= order.get(b) != b;
        if (!changed) return 0;

        int[] slots = new int[size]; BitSet extra = new BitSet(), inverse = new BitSet(); int count = 0;
        for (int k = 0; k < blocks; k++) {
            int block = order.get(k), end = ends[block];
            int next = k + 1 < blocks ? starts.get(order.get(k + 1)) : -1;
            for (int i = starts.get(block); i <= end; i++) slots[i] = count++;
            if (graph.at(end).getOpcode().canContinue() && end + 1 < size && next != end + 1) {
                if (CodeGraph.isIf(graph.at(end).getOpcode()) && graph.successors(end).get(0) == next) inverse.set(end);
                else { extra.set(end); count++; }
            }
        }
        var code = new MutableMethodImplementation(graph.registers());
        for (int i = 0; i < count; i++) code.addInstruction(new BuilderInstruction10x(Opcode.NOP));
        for (int block : order) for (int i = starts.get(block); i <= ends[block]; i++) {
            Instruction instruction = graph.at(i); Opcode op = instruction.getOpcode();
            if (CodeGraph.isGoto(op)) {
                code.replaceInstruction(slots[i], new BuilderInstruction30t(Opcode.GOTO_32,
                        code.newLabelForIndex(slots[graph.successors(i).get(0)])));
            } else if (CodeGraph.isIf(op)) {
                boolean flip = inverse.get(i); if (flip) op = invert(op);
                Label target = code.newLabelForIndex(slots[flip ? i + 1 : graph.successors(i).get(0)]);
                code.replaceInstruction(slots[i], instruction instanceof TwoRegisterInstruction r
                        ? new BuilderInstruction22t(op, r.getRegisterA(), r.getRegisterB(), target)
                        : new BuilderInstruction21t(op, ((OneRegisterInstruction)instruction).getRegisterA(), target));
            } else code.replaceInstruction(slots[i], Edits.copy(instruction, graph.registers()));
            if (extra.get(i)) code.replaceInstruction(slots[i] + 1,
                    new BuilderInstruction30t(Opcode.GOTO_32, code.newLabelForIndex(slots[i + 1])));
        }
        List<List<CodeGraph.Handler>> protections = new ArrayList<>(Collections.nCopies(count, List.of()));
        for (int i = 0; i < size; i++) {
            protections.set(slots[i], graph.protection(i));
            if (extra.get(i)) protections.set(slots[i] + 1, graph.protection(i));
        }
        int start = 0;
        for (int i = 1; i <= count; i++) if (i == count || !protections.get(start).equals(protections.get(i))) {
            for (CodeGraph.Handler handler : protections.get(start)) {
                Label from = code.newLabelForIndex(start), end = code.newLabelForIndex(i);
                Label target = code.newLabelForIndex(slots[handler.target()]);
                if (handler.type() == null) code.addCatch(from, end, target);
                else code.addCatch(handler.type(), from, end, target);
            }
            start = i;
        }
        var implementation = new ImmutableMethodImplementation(graph.registers(), code.getInstructions(), code.getTryBlocks(), List.of());
        CodeGraph candidate = new CodeGraph(implementation);
        // Check every old instruction, including non-throwing ones: both typed
        // handler order and the relocated handler entry must be identical.
        for (int i = 0; i < size; i++) {
            List<CodeGraph.Handler> expected = new ArrayList<>();
            for (CodeGraph.Handler handler : graph.protection(i)) expected.add(new CodeGraph.Handler(handler.type(), slots[handler.target()]));
            if (!expected.equals(candidate.protection(slots[i]))) return 0;
        }
        context.replaceCode(implementation);
        BranchThreading.run(context);
        UnreachableInstructions.remove(context);
        DeadAssignments.removeNonThrowing(context);
        return 1;
    }

    private static List<Integer> reversePostorder(CodeGraph graph, int[] ends, int[] owner, int start, BitSet seen) {
        List<Integer> order = new ArrayList<>(); int[] nextEdge = new int[ends.length];
        ArrayDeque<Integer> work = new ArrayDeque<>(); work.push(start); seen.set(start);
        while (!work.isEmpty()) {
            int block = work.peek(); List<Integer> successors = graph.successors(ends[block]);
            if (nextEdge[block] == successors.size()) { order.add(block); work.pop(); }
            else {
                int next = owner[successors.get(nextEdge[block]++)];
                if (!seen.get(next)) { seen.set(next); work.push(next); }
            }
        }
        Collections.reverse(order); return order;
    }

    private static Opcode invert(Opcode op) {
        return switch (op) {
            case IF_EQ -> Opcode.IF_NE; case IF_NE -> Opcode.IF_EQ;
            case IF_LT -> Opcode.IF_GE; case IF_GE -> Opcode.IF_LT;
            case IF_GT -> Opcode.IF_LE; case IF_LE -> Opcode.IF_GT;
            case IF_EQZ -> Opcode.IF_NEZ; case IF_NEZ -> Opcode.IF_EQZ;
            case IF_LTZ -> Opcode.IF_GEZ; case IF_GEZ -> Opcode.IF_LTZ;
            case IF_GTZ -> Opcode.IF_LEZ; case IF_LEZ -> Opcode.IF_GTZ;
            default -> throw new IllegalArgumentException("Not a conditional branch: " + op);
        };
    }
}
