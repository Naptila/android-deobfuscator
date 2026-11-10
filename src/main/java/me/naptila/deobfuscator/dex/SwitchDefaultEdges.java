package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.BuilderInstruction;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.instruction.*;

/** Split a shared default discriminator before a second switch, preserving live input values. */
public final class SwitchDefaultEdges {
    private SwitchDefaultEdges() {}
    public static int run(MethodContext context) {
        if (!context.code().getTryBlocks().isEmpty()) return 0;
        CodeGraph graph = context.graph();
        Set<Integer> defaults = new HashSet<>();
        for (int i = 0; i < graph.size(); i++) {
            if (!CodeGraph.isSwitch(graph.at(i).getOpcode())) continue;
            int target = i + 1;
            Set<Integer> seen = new HashSet<>();
            while (target < graph.size() && CodeGraph.isGoto(graph.at(target).getOpcode()) && seen.add(target))
                target = graph.successors(target).get(0);
            if (target + 1 >= graph.size() || graph.isPayload(target + 1)) continue;
            Opcode op = graph.at(target).getOpcode();
            if (op != Opcode.CONST && op != Opcode.CONST_4 && op != Opcode.CONST_16 && op != Opcode.CONST_HIGH16) continue;
            int join = target + 1;
            seen.clear();
            while (CodeGraph.isGoto(graph.at(join).getOpcode()) && seen.add(join)) join = graph.successors(join).get(0);
            if (CodeGraph.isSwitch(graph.at(join).getOpcode())
                    && ((OneRegisterInstruction)graph.at(join)).getRegisterA() == ((OneRegisterInstruction)graph.at(target)).getRegisterA())
                defaults.add(target);
        }
        List<Edits.Edit> edits = new ArrayList<>();
        for (int i = 0; i + 1 < graph.size(); i++) {
            Instruction instruction = graph.at(i);
            if (!CodeGraph.isIf(instruction.getOpcode())) continue;
            int target = skipGotos(graph, graph.index(graph.address(i) + ((OffsetInstruction)instruction).getCodeOffset()));
            // A relay can hide the shared default. If both arms already reach it,
            // copying the assignment only creates another identical default edge.
            if (!defaults.contains(target) || target == skipGotos(graph, i + 1)) continue;
            // Preserve the old condition and both successor states: only the taken
            // edge executes a copy of the default const, then rejoins after it.
            var fallthrough = context.code().newLabelForIndex(i + 1);
            Opcode inverse = invert(instruction.getOpcode());
            BuilderInstruction branch = instruction instanceof TwoRegisterInstruction r
                    ? new BuilderInstruction22t(inverse, r.getRegisterA(), r.getRegisterB(), fallthrough)
                    : new BuilderInstruction21t(inverse, ((OneRegisterInstruction)instruction).getRegisterA(), fallthrough);
            edits.add(new Edits.Edit(i, false, List.of(branch,
                    Edits.copy(graph.at(target), graph.registers()), Edits.jump(context.code(), target + 1))));
        }
        Edits.apply(context.code(), edits);
        return edits.size();
    }
    private static int skipGotos(CodeGraph graph, int target) {
        Set<Integer> seen = new HashSet<>();
        while (CodeGraph.isGoto(graph.at(target).getOpcode()) && seen.add(target))
            target = graph.successors(target).get(0);
        return target;
    }
    private static Opcode invert(Opcode opcode) {
        return switch (opcode) {
            case IF_EQ -> Opcode.IF_NE; case IF_NE -> Opcode.IF_EQ;
            case IF_LT -> Opcode.IF_GE; case IF_GE -> Opcode.IF_LT;
            case IF_GT -> Opcode.IF_LE; case IF_LE -> Opcode.IF_GT;
            case IF_EQZ -> Opcode.IF_NEZ; case IF_NEZ -> Opcode.IF_EQZ;
            case IF_LTZ -> Opcode.IF_GEZ; case IF_GEZ -> Opcode.IF_LTZ;
            case IF_GTZ -> Opcode.IF_LEZ; case IF_LEZ -> Opcode.IF_GTZ;
            default -> throw new IllegalArgumentException("Not a conditional branch: " + opcode);
        };
    }
}
