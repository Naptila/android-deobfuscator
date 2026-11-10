package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.immutable.ImmutableMethodImplementation;

/** Reconnect a split move-exception/goto entry to its exclusively owned handler body. */
public final class HandlerEntries {
    private HandlerEntries() {}
    public static int run(MethodContext context) {
        CodeGraph graph = context.graph();
        Set<Integer> handlers = new HashSet<>();
        for (var block : context.code().getTryBlocks())
            handlers.add(graph.index(block.exceptionHandler.getHandlerCodeAddress()));
        List<Set<Integer>> predecessors = new ArrayList<>();
        for (int i = 0; i < graph.size(); i++) predecessors.add(new HashSet<>());
        for (int i = 0; i < graph.size(); i++) for (int next : graph.successors(i)) predecessors.get(next).add(i);
        for (int entry : handlers) {
            if (entry == 0 || entry + 1 >= graph.size() || graph.at(entry).getOpcode() != Opcode.MOVE_EXCEPTION
                    || !CodeGraph.isGoto(graph.at(entry + 1).getOpcode()) || !predecessors.get(entry).isEmpty()
                    || !predecessors.get(entry + 1).equals(Set.of(entry)) || handlers.contains(entry + 1)) continue;
            int body = graph.successors(entry + 1).get(0);
            if (body == 0 || body == entry || body == entry + 1 || handlers.contains(body) || graph.isPayload(body)
                    || !predecessors.get(body).equals(Set.of(entry + 1))
                    || !graph.protection(entry).isEmpty() || !graph.protection(body).isEmpty()) continue;
            var code = context.code();
            List<BuilderTryBlock> blocks = new ArrayList<>(code.getTryBlocks());
            Set<BuilderTryBlock> redirect = Collections.newSetFromMap(new IdentityHashMap<>());
            for (BuilderTryBlock block : blocks)
                if (graph.index(block.exceptionHandler.getHandlerCodeAddress()) == entry) redirect.add(block);
            code.addInstruction(body, Edits.copy(graph.at(entry), graph.registers()));
            Label destination = code.newLabelForIndex(body);
            List<BuilderTryBlock> replacement = new ArrayList<>();
            for (BuilderTryBlock block : blocks)
                replacement.add(redirect.contains(block)
                        ? new BuilderTryBlock(block.start, block.end, block.exceptionHandler.getExceptionType(), destination) : block);
            context.replaceCode(new ImmutableMethodImplementation(code.getRegisterCount(), code.getInstructions(), replacement, code.getDebugItems()));
            return 1; // The old stub is now unreachable; rebuild all indices before another entry.
        }
        return 0;
    }
}
