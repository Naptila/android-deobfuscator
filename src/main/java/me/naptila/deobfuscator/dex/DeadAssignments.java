package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.instruction.Instruction;

/** Reusable liveness cleanup; protected throwing instructions and all unknown calls stay. */
public final class DeadAssignments {
    private DeadAssignments() {}
    private static final Set<Opcode> PURE = EnumSet.noneOf(Opcode.class);
    static { for (Opcode opcode : Opcode.values()) if (pureOpcode(opcode)) PURE.add(opcode); }
    public static int remove(MethodContext context) {
        return remove(context, false);
    }
    /** Post-layout cleanup must keep potentially throwing definitions even when their values are dead. */
    public static int removeNonThrowing(MethodContext context) {
        return remove(context, true);
    }
    private static int remove(MethodContext context, boolean nonThrowing) {
        int count = 0;
        while (true) {
            CodeGraph graph = context.graph(); RegisterLiveness live = new RegisterLiveness(graph);
            BitSet remove = new BitSet();
            for (int i = 0; i < graph.size(); i++) {
                Instruction instruction = graph.at(i);
                if (instruction.getOpcode().canThrow() && (nonThrowing || !graph.protection(i).isEmpty())) continue;
                if (isPure(instruction) && live.deadAfter(i, instruction)) remove.set(i);
            }
            if (remove.isEmpty()) return count;
            ExceptionEdits.remove(context, remove); count += remove.cardinality();
        }
    }
    public static boolean isPure(Instruction i) {
        return PURE.contains(i.getOpcode());
    }
    private static boolean pureOpcode(Opcode opcode) {
        return switch (opcode) {
            case CONST_4, CONST_16, CONST, CONST_HIGH16, CONST_WIDE_16, CONST_WIDE_32, CONST_WIDE, CONST_WIDE_HIGH16,
                 CONST_STRING, CONST_STRING_JUMBO,
                 MOVE, MOVE_FROM16, MOVE_16, MOVE_OBJECT, MOVE_OBJECT_FROM16, MOVE_OBJECT_16,
                 MOVE_WIDE, MOVE_WIDE_FROM16, MOVE_WIDE_16,
                 MOVE_RESULT, MOVE_RESULT_OBJECT, MOVE_RESULT_WIDE -> true;
            default -> {
                String name = opcode.name;
                // Explicit pure numeric families, including conversions; division/remainder stay.
                yield !opcode.canThrow() && opcode.setsRegister()
                        && (name.matches("(?:add|sub|rsub|mul|and|or|xor|shl|shr|ushr|neg|not)-(?:int|long|float|double)(?:/.*)?")
                        || name.matches("(?:int|long|float|double)-to-(?:int|long|float|double|byte|char|short)")
                        || name.matches("cmp(?:l|g)?-(?:long|float|double)"));
            }
        };
    }
}
