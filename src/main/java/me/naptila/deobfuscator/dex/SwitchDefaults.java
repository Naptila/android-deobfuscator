package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.instruction.*;

/** Hoist a shared default integer assignment when every incoming path preserves it. */
public final class SwitchDefaults {
    private SwitchDefaults() {}
    public static int run(MethodContext context) {
        if (!context.code().getTryBlocks().isEmpty()) return 0;
        CodeGraph graph = context.graph();
        RegisterLiveness live = new RegisterLiveness(graph);
        List<List<Integer>> predecessors = new ArrayList<>();
        for (int i = 0; i < graph.size(); i++) predecessors.add(new ArrayList<>());
        for (int i = 0; i < graph.size(); i++) for (int next : graph.successors(i)) predecessors.get(next).add(i);
        for (int i = 0; i < graph.size(); i++) {
            if (!CodeGraph.isSwitch(graph.at(i).getOpcode())) continue;
            int target = i + 1;
            Set<Integer> visited = new HashSet<>();
            while (target < graph.size() && CodeGraph.isGoto(graph.at(target).getOpcode()) && visited.add(target))
                target = graph.successors(target).get(0);
            Opcode op = graph.at(target).getOpcode();
            if (op != Opcode.CONST_4 && op != Opcode.CONST_16 && op != Opcode.CONST && op != Opcode.CONST_HIGH16) continue;
            int register = ((OneRegisterInstruction) graph.at(target)).getRegisterA();
            if (live.liveBefore(i, register) || !preserved(graph, predecessors, i, target, register)) continue;
            int value = ((NarrowLiteralInstruction) graph.at(target)).getNarrowLiteral();
            var code = context.code();
            var branch = new BuilderInstruction31t(graph.at(i).getOpcode(), ((OneRegisterInstruction) graph.at(i)).getRegisterA(),
                    code.newLabelForIndex(graph.payloadIndex(i)));
            Edits.apply(code, List.of(
                    new Edits.Edit(target, false, List.of(new BuilderInstruction10x(Opcode.NOP))),
                    new Edits.Edit(i, false, List.of(Edits.constant(register, value), branch))));
            return 1; // Rebuild facts before considering another switch.
        }
        return 0;
    }
    private static boolean preserved(CodeGraph graph, List<List<Integer>> predecessors, int header, int target, int register) {
        Set<Integer> seen = new HashSet<>();
        ArrayDeque<Integer> work = new ArrayDeque<>(predecessors.get(target));
        boolean reachesHeader = false;
        while (!work.isEmpty()) {
            int i = work.removeFirst();
            if (i == header) { reachesHeader = true; continue; }
            if (!seen.add(i)) continue;
            // Also establishes that the switch dominates the shared default assignment.
            if (i == 0 || predecessors.get(i).isEmpty() || RegisterLiveness.writes(graph.at(i)).get(register)) return false;
            work.addAll(predecessors.get(i));
        }
        return reachesHeader;
    }
}
