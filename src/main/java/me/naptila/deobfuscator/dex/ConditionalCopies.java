package me.naptila.deobfuscator.dex;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.BuilderInstruction;
import org.jf.dexlib2.builder.Label;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.debug.EndLocal;
import org.jf.dexlib2.iface.debug.RestartLocal;
import org.jf.dexlib2.iface.debug.StartLocal;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.MethodReference;

/** Delay an assignment until the only conditional successor that needs its destination. */
public final class ConditionalCopies {
    private static final int PATH_LIMIT = 64;
    private ConditionalCopies() {}

    public static int run(MethodContext context) {
        return run(context, false);
    }

    /** Integer literals have no source register and cannot throw during evaluation. */
    public static int runLiterals(MethodContext context) {
        return run(context, true);
    }

    private static int run(MethodContext context, boolean literals) {
        // Changing assignment timing would change the value of a visible debug local.
        for (var item : context.code().getDebugItems())
            if (item instanceof StartLocal || item instanceof EndLocal || item instanceof RestartLocal) return 0;
        int copies = 0;
        while (copies < 64 && sinkOne(context, literals)) copies++;
        return copies;
    }

    private static boolean sinkOne(MethodContext context, boolean literals) {
        CodeGraph graph = context.graph();
        if (graph.size() > 4096) return false;
        boolean candidate = false, condition = false;
        for (int i = 0; i < graph.size(); i++) {
            candidate |= assignment(graph.at(i).getOpcode(), literals);
            condition |= CodeGraph.isIf(graph.at(i).getOpcode());
        }
        if (!candidate || !condition) return false;
        int[] incoming = new int[graph.size()];
        incoming[0]++;
        for (int i = 0; i < graph.size(); i++) {
            for (int next : graph.successors(i)) incoming[next]++;
            for (CodeGraph.Handler handler : graph.protection(i)) incoming[handler.target()]++;
        }
        RegisterLiveness live = new RegisterLiveness(graph);
        for (int source = 0; source < graph.size(); source++) {
            Instruction instruction = graph.at(source);
            if (!assignment(instruction.getOpcode(), literals)) continue;
            int destination = ((OneRegisterInstruction)instruction).getRegisterA();
            int value = literals ? -1 : ((TwoRegisterInstruction)instruction).getRegisterB();
            if (destination == value) continue;
            Set<Integer> seen = new HashSet<>(); seen.add(source);
            int at = source + 1;
            for (int budget = 0; budget < PATH_LIMIT && at < graph.size() && seen.add(at) && incoming[at] == 1; budget++) {
                Instruction next = graph.at(at); Opcode op = next.getOpcode();
                BitSet writes = RegisterLiveness.writes(next);
                if (writes.get(destination) || value >= 0 && writes.get(value) || RegisterLiveness.reads(next).get(destination)
                        || !graph.handlers(at).isEmpty() || graph.isPayload(at)) break;
                // Constructors change the verifier state of all receiver aliases.
                if (next instanceof ReferenceInstruction reference && reference.getReference() instanceof MethodReference method
                        && method.getName().equals("<init>")) break;
                if (CodeGraph.isIf(op)) {
                    int taken = graph.successors(at).get(0), fallthrough = at + 1;
                    boolean onTaken = live.liveBefore(taken, destination);
                    if (onTaken == live.liveBefore(fallthrough, destination)) break;
                    moveToEdge(context, graph, source, at, onTaken);
                    return true;
                }
                if (CodeGraph.isSwitch(op) || op == Opcode.FILL_ARRAY_DATA || op == Opcode.MONITOR_ENTER || op == Opcode.MONITOR_EXIT
                        || graph.successors(at).size() != 1) break;
                at = graph.successors(at).get(0);
            }
        }
        return false;
    }

    private static void moveToEdge(MethodContext context, CodeGraph graph, int source, int branch, boolean taken) {
        var code = context.code(); Instruction condition = graph.at(branch);
        int destination = graph.successors(branch).get(0);
        Opcode op = taken ? invert(condition.getOpcode()) : condition.getOpcode();
        Label skip = code.newLabelForIndex(taken ? branch + 1 : destination);
        BuilderInstruction test = condition instanceof TwoRegisterInstruction two
                ? new BuilderInstruction22t(op, two.getRegisterA(), two.getRegisterB(), skip)
                : new BuilderInstruction21t(op, ((OneRegisterInstruction)condition).getRegisterA(), skip);
        List<BuilderInstruction> route = new ArrayList<>();
        route.add(test); route.add(Edits.copy(graph.at(source), graph.registers()));
        if (taken) route.add(Edits.jump(code, destination));
        // All old labels, debug items and try boundaries stay on their original instructions.
        Edits.apply(code, List.of(new Edits.Edit(branch, false, route),
                new Edits.Edit(source, false, List.of(new BuilderInstruction10x(Opcode.NOP)))));
    }

    private static boolean assignment(Opcode op, boolean literals) {
        if (literals) return op == Opcode.CONST_4 || op == Opcode.CONST_16 || op == Opcode.CONST || op == Opcode.CONST_HIGH16;
        return op == Opcode.MOVE || op == Opcode.MOVE_FROM16 || op == Opcode.MOVE_16
                || op == Opcode.MOVE_OBJECT || op == Opcode.MOVE_OBJECT_FROM16 || op == Opcode.MOVE_OBJECT_16;
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
