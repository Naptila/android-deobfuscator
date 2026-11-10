package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.instruction.formats.Instruction35c;

/** Keep a straight-line string temporary separate from registers live in exception handlers. */
public final class HandlerLiteralRegisters {
    private HandlerLiteralRegisters() {}
    public static int run(MethodContext context) {
        if (context.code().getTryBlocks().isEmpty()) return 0;
        CodeGraph graph = context.graph(); RegisterLiveness live = new RegisterLiveness(graph);
        BitSet handlerLive = new BitSet();
        for (var block : context.code().getTryBlocks()) {
            int target = graph.index(block.exceptionHandler.getHandlerCodeAddress());
            for (int r = 0; r < graph.registers(); r++) if (live.liveBefore(target, r)) handlerLive.set(r);
        }
        for (int start = 0; start < graph.size(); start++) {
            Opcode op = graph.at(start).getOpcode();
            if (op != Opcode.CONST_STRING && op != Opcode.CONST_STRING_JUMBO) continue;
            int old = ((OneRegisterInstruction)graph.at(start)).getRegisterA();
            if (!handlerLive.get(old) || !graph.protection(start).isEmpty()) continue;
            List<Integer> uses = new ArrayList<>(); int end = -1;
            for (int i = start + 1; i < Math.min(graph.size(), start + 64); i++) {
                if (graph.leaders().contains(i) || !graph.protection(i).isEmpty()
                        || RegisterLiveness.writes(graph.at(i)).get(old)) break;
                if (RegisterLiveness.reads(graph.at(i)).get(old)) {
                    // Other formats need their own register remapping and encoding proof.
                    if (!(graph.at(i) instanceof Instruction35c) || !graph.at(i).getOpcode().name.startsWith("invoke-")) break;
                    uses.add(i);
                }
                if (!live.liveAfter(i, old)) { if (!uses.isEmpty()) end = i; break; }
                if (!graph.successors(i).equals(List.of(i + 1))) break;
            }
            if (end < 0) continue;
            int scratch = -1;
            for (int r = 0; r < Math.min(16, graph.registers()); r++) {
                if (r == old || handlerLive.get(r)) continue;
                boolean available = true;
                for (int i = start; i <= end; i++)
                    if (live.liveBefore(i, r) || live.liveAfter(i, r) || RegisterLiveness.writes(graph.at(i)).get(r)) {
                        available = false; break;
                    }
                if (available) { scratch = r; break; }
            }
            if (scratch < 0) continue;
            var code = context.code();
            code.replaceInstruction(start, new BuilderInstruction31c(Opcode.CONST_STRING_JUMBO, scratch,
                    ((ReferenceInstruction)graph.at(start)).getReference()));
            for (int index : uses) {
                Instruction35c call = (Instruction35c)graph.at(index);
                int[] args = Arrays.copyOf(ConstantEvaluator.arguments(call), 5);
                for (int k = 0; k < call.getRegisterCount(); k++) if (args[k] == old) args[k] = scratch;
                code.replaceInstruction(index, new BuilderInstruction35c(call.getOpcode(), call.getRegisterCount(),
                        args[0], args[1], args[2], args[3], args[4], call.getReference()));
            }
            return 1; // Liveness must be rebuilt before selecting another temporary.
        }
        return 0;
    }
}
