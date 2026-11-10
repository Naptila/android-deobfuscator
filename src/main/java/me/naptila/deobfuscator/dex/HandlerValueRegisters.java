package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.instruction.*;

/** Separate short unprotected scalar definitions from locals still used by exception handlers. */
public final class HandlerValueRegisters {
    private HandlerValueRegisters() {}
    public static int run(MethodContext context) {
        if (context.code().getTryBlocks().isEmpty()) return 0;
        CodeGraph g = context.graph(); RegisterLiveness live = new RegisterLiveness(g); BitSet handlerLive = new BitSet();
        for (var block : context.code().getTryBlocks()) {
            int target = g.index(block.exceptionHandler.getHandlerCodeAddress());
            for (int r = 0; r < g.registers(); r++) if (live.liveBefore(target, r)) handlerLive.set(r);
        }
        for (int start = 0; start < g.size(); start++) {
            Instruction def = g.at(start); Opcode op = def.getOpcode();
            if (!(def instanceof OneRegisterInstruction one) || !op.setsRegister() || op.setsWideRegister()
                    || !g.protection(start).isEmpty() || definition(def, one.getRegisterA()) == null) continue;
            int old = one.getRegisterA(); if (!handlerLive.get(old) || RegisterLiveness.reads(def).get(old)) continue;
            List<Integer> uses = new ArrayList<>(); int end = -1;
            for (int i = start + 1; i < Math.min(g.size(), start + 64); i++) {
                if (g.leaders().contains(i) || !g.protection(i).isEmpty() || RegisterLiveness.writes(g.at(i)).get(old)) break;
                if (RegisterLiveness.reads(g.at(i)).get(old)) {
                    // Staging moves are the only consumers we rename; no range-call contiguity assumptions.
                    if (!(g.at(i) instanceof TwoRegisterInstruction move) || !g.at(i).getOpcode().name.startsWith("move")
                            || g.at(i).getOpcode().name.startsWith("move-wide") || move.getRegisterB() != old) break;
                    uses.add(i);
                }
                if (!live.liveAfter(i, old)) { if (!uses.isEmpty()) end = i; break; }
                if (!g.successors(i).equals(List.of(i + 1))) break;
            }
            if (end < 0) continue;
            int scratch = -1;
            for (int r = 0; r < Math.min(256, g.registers()); r++) {
                if (r == old || handlerLive.get(r)) continue;
                boolean available = true;
                for (int i = start; i <= end; i++) if (live.liveBefore(i, r) || live.liveAfter(i, r) || RegisterLiveness.writes(g.at(i)).get(r)) { available = false; break; }
                if (available) { scratch = r; break; }
            }
            if (scratch < 0) continue;
            context.code().replaceInstruction(start, definition(def, scratch));
            for (int at : uses) {
                var move = (TwoRegisterInstruction)g.at(at);
                Opcode code = g.at(at).getOpcode().name.startsWith("move-object") ? Opcode.MOVE_OBJECT_16 : Opcode.MOVE_16;
                context.code().replaceInstruction(at, new BuilderInstruction32x(code, move.getRegisterA(), scratch));
            }
            return 1;
        }
        return 0;
    }
    private static BuilderInstruction definition(Instruction i, int dest) {
        Opcode op = i.getOpcode();
        if (op.name.startsWith("sget") && op != Opcode.SGET_WIDE && op.format == Format.Format21c) return new BuilderInstruction21c(op, dest, ((ReferenceInstruction)i).getReference());
        if (op == Opcode.MOVE_RESULT || op == Opcode.MOVE_RESULT_OBJECT) return new BuilderInstruction11x(op, dest);
        if (op.name.startsWith("aget") && op != Opcode.AGET_WIDE) {
            var r = (ThreeRegisterInstruction)i; return new BuilderInstruction23x(op, dest, r.getRegisterB(), r.getRegisterC());
        }
        if (op.name.startsWith("const") && !op.name.startsWith("const-wide") && i instanceof NarrowLiteralInstruction n) return Edits.constant(dest, n.getNarrowLiteral());
        return null;
    }
}
