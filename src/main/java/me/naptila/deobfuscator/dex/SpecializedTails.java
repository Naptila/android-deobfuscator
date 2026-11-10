package me.naptila.deobfuscator.dex;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.Label;
import org.jf.dexlib2.builder.instruction.BuilderInstruction21t;
import org.jf.dexlib2.builder.instruction.BuilderInstruction22t;
import org.jf.dexlib2.iface.instruction.*;

/** Give an edge its own terminal trace when local constants resolve every later branch. */
public final class SpecializedTails {
    private SpecializedTails() {}

    public static int run(MethodContext context) {
        if (!context.code().getTryBlocks().isEmpty() || context.code().getDebugItems().iterator().hasNext()) return 0;
        CodeGraph graph = context.graph(); int size = graph.size();
        if (size == 0 || size > 1024) return 0;
        BitSet reachable = new BitSet(); ArrayDeque<Integer> work = new ArrayDeque<>(); work.add(0);
        int[] incoming = new int[size];
        while (!work.isEmpty()) {
            int at = work.removeFirst(); if (reachable.get(at)) continue;
            reachable.set(at);
            for (int next : graph.successors(at)) { incoming[next]++; work.add(next); }
        }
        if (graph.at(size - 1).getOpcode().canContinue() && reachable.get(size - 1)) return 0;
        for (int source = 0; source + 1 < size; source++) {
            if (!reachable.get(source) || !CodeGraph.isIf(graph.at(source).getOpcode())) continue;
            int target = graph.successors(source).get(0), at = target, conditions = 0;
            boolean shared = false, terminal = false;
            Constants state = new Constants(); Set<Integer> visited = new HashSet<>();
            List<Instruction> body = new ArrayList<>();
            for (int budget = 0; budget < 128 && at < size && visited.add(at); budget++) {
                Instruction instruction = graph.at(at); Opcode op = instruction.getOpcode();
                if (graph.isPayload(at) || CodeGraph.isSwitch(op) || op == Opcode.FILL_ARRAY_DATA || op == Opcode.MOVE_EXCEPTION
                        || op == Opcode.MONITOR_ENTER || op == Opcode.MONITOR_EXIT) break;
                shared |= incoming[at] > 1;
                if (CodeGraph.isGoto(op)) { at = graph.successors(at).get(0); continue; }
                if (CodeGraph.isIf(op)) {
                    Boolean decision = ConstantBranches.decision(instruction, state);
                    if (decision == null) break;
                    conditions++; at = decision ? graph.successors(at).get(0) : at + 1; continue;
                }
                if (instruction instanceof OffsetInstruction) break;
                // Unknown calls keep their operations and invalidate their results.
                // They cannot write the caller's local registers used as constants.
                ConstantEvaluator.step(instruction, state); body.add(instruction);
                if (op.name.startsWith("return") || op == Opcode.THROW) { terminal = true; break; }
                at++;
            }
            if (!terminal || !shared || conditions == 0 || visited.contains(source) || visited.contains(source + 1)
                    || body.isEmpty() || result(graph.at(target).getOpcode())
                    || size + body.size() > 1024 || size + body.size() > context.originalGraph().size() + 128) continue;
            var code = context.code(); int start = code.getInstructions().size();
            for (Instruction instruction : body) code.addInstruction(Edits.copy(instruction, graph.registers()));
            Instruction condition = graph.at(source); Label destination = code.newLabelForIndex(start);
            code.replaceInstruction(source, condition instanceof TwoRegisterInstruction two
                    ? new BuilderInstruction22t(condition.getOpcode(), two.getRegisterA(), two.getRegisterB(), destination)
                    : new BuilderInstruction21t(condition.getOpcode(), ((OneRegisterInstruction)condition).getRegisterA(), destination));
            return 1;
        }
        return 0;
    }
    private static boolean result(Opcode op) {
        return op == Opcode.MOVE_RESULT || op == Opcode.MOVE_RESULT_OBJECT || op == Opcode.MOVE_RESULT_WIDE;
    }
}
