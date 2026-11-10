package me.naptila.deobfuscator.dex;

import java.util.List;
import org.jf.dexlib2.iface.instruction.*;

public final class ConstantBranches {
    private ConstantBranches() {}
    public static Boolean decision(Instruction instruction, Constants state) {
        if (!CodeGraph.isIf(instruction.getOpcode())) return null;
        Object left = state.get(((OneRegisterInstruction) instruction).getRegisterA());
        Object right = instruction instanceof TwoRegisterInstruction two ? state.get(two.getRegisterB()) : 0;
        if (!(left instanceof Integer a) || !(right instanceof Integer b)) return null;
        return switch (instruction.getOpcode()) {
            case IF_EQ, IF_EQZ -> a.intValue() == b.intValue();
            case IF_NE, IF_NEZ -> a.intValue() != b.intValue();
            case IF_LT, IF_LTZ -> a < b;
            case IF_LE, IF_LEZ -> a <= b;
            case IF_GT, IF_GTZ -> a > b;
            case IF_GE, IF_GEZ -> a >= b;
            default -> null;
        };
    }
    public static List<Integer> successors(CodeGraph graph, int i, Constants state) {
        Boolean decision = decision(graph.at(i), state);
        if (decision != null) return List.of(decision ? graph.successors(i).get(0) : i + 1);
        if (CodeGraph.isSwitch(graph.at(i).getOpcode())) {
            Object value = state.get(((OneRegisterInstruction) graph.at(i)).getRegisterA());
            if (value instanceof Integer key) return List.of(graph.switchTarget(i, key));
        }
        return graph.successors(i);
    }
}
