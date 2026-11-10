package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.instruction.*;

/** Bypass goto-only blocks. Cycles are deliberately left alone. */
public final class BranchThreading {
    private BranchThreading() {}
    public static int run(MethodContext context) {
        CodeGraph graph = context.graph();
        var code = context.code();
        List<Edits.Edit> edits = new ArrayList<>();
        int[] incoming = new int[graph.size()];
        if (graph.size() != 0) incoming[0]++;
        for (int i = 0; i < graph.size(); i++) {
            for (int next : graph.successors(i)) incoming[next]++;
            for (CodeGraph.Handler handler : graph.protection(i)) incoming[handler.target()]++;
        }
        for (int i = 0; i < graph.size(); i++) {
            Instruction instruction = graph.at(i);
            Opcode op = instruction.getOpcode();
            if (CodeGraph.isGoto(op) || CodeGraph.isIf(op)) {
                int old = graph.index(graph.address(i) + ((OffsetInstruction) instruction).getCodeOffset());
                int target = target(graph, old);
                // Dispatch recovery can leave a condition alone at the end of
                // the method. Bring a uniquely entered forward test back to its
                // goto, retaining both destinations and all register values.
                // The old test then becomes unreachable; shared tests and
                // exception entries are deliberately left in place.
                if (CodeGraph.isGoto(op) && old == target && target > i + 1
                        && CodeGraph.isIf(graph.at(target).getOpcode()) && incoming[target] == 1
                        && graph.protection(i).equals(graph.protection(target))) {
                    Instruction condition = graph.at(target);
                    Label taken = code.newLabelForIndex(graph.successors(target).get(0));
                    BuilderInstruction branch = condition instanceof TwoRegisterInstruction r
                            ? new BuilderInstruction22t(condition.getOpcode(), r.getRegisterA(), r.getRegisterB(), taken)
                            : new BuilderInstruction21t(condition.getOpcode(), ((OneRegisterInstruction) condition).getRegisterA(), taken);
                    edits.add(new Edits.Edit(i, false, List.of(branch,
                            new BuilderInstruction30t(Opcode.GOTO_32, code.newLabelForIndex(target + 1)))));
                    continue;
                }
                // A shared return needs no register adaptation and no exception relocation.
                if (CodeGraph.isGoto(op) && isReturn(graph.at(target).getOpcode())
                        && graph.protection(i).isEmpty() && graph.protection(target).isEmpty()) {
                    edits.add(new Edits.Edit(i, false, List.of(Edits.copy(graph.at(target), graph.registers()))));
                    continue;
                }
                if (old == target) continue;
                Label label = code.newLabelForIndex(target);
                BuilderInstruction replacement;
                if (CodeGraph.isGoto(op)) replacement = new BuilderInstruction30t(Opcode.GOTO_32, label);
                else if (instruction instanceof TwoRegisterInstruction r)
                    replacement = new BuilderInstruction22t(op, r.getRegisterA(), r.getRegisterB(), label);
                else replacement = new BuilderInstruction21t(op, ((OneRegisterInstruction) instruction).getRegisterA(), label);
                edits.add(new Edits.Edit(i, false, List.of(replacement)));
            } else if (CodeGraph.isSwitch(op)) {
                List<SwitchLabelElement> entries = new ArrayList<>();
                boolean changed = false;
                for (SwitchElement element : graph.payload(i).getSwitchElements()) {
                    int old = graph.index(graph.address(i) + element.getOffset());
                    int target = target(graph, old);
                    changed |= old != target;
                    entries.add(new SwitchLabelElement(element.getKey(), code.newLabelForIndex(target)));
                }
                if (changed) {
                    BuilderInstruction payload = op == Opcode.SPARSE_SWITCH
                            ? new BuilderSparseSwitchPayload(entries)
                            : new BuilderPackedSwitchPayload(entries.get(0).key, entries.stream().map(e -> e.target).toList());
                    edits.add(new Edits.Edit(graph.payloadIndex(i), false, List.of(payload)));
                }
            }
        }
        Edits.apply(code, edits);
        // Specialization leaves goto-to-next edges which keep artificial blocks
        // alive in decompilers. Deleting one does not change either successor state.
        graph = context.graph();
        BitSet redundant = new BitSet();
        for (int i = 0; i < graph.size(); i++)
            if (CodeGraph.isGoto(graph.at(i).getOpcode()) && graph.successors(i).get(0) == i + 1
                    && target(graph, i) != i) redundant.set(i);
        ExceptionEdits.remove(context, redundant);
        return edits.size() + redundant.cardinality();
    }
    private static int target(CodeGraph graph, int start) {
        Set<Integer> seen = new HashSet<>();
        int current = start;
        while (CodeGraph.isGoto(graph.at(current).getOpcode())
                || graph.at(current).getOpcode() == Opcode.NOP && current + 1 < graph.size() && !graph.isPayload(current + 1)) {
            if (!seen.add(current)) return start;
            current = graph.successors(current).get(0);
        }
        return current;
    }
    private static boolean isReturn(Opcode op) {
        return op == Opcode.RETURN || op == Opcode.RETURN_OBJECT || op == Opcode.RETURN_WIDE || op == Opcode.RETURN_VOID;
    }
}
