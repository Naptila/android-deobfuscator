package me.naptila.deobfuscator.transformers.np.controlflow;

import java.util.*;

import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.CodeGraph;
import me.naptila.deobfuscator.dex.DexPass;
import me.naptila.deobfuscator.dex.MethodContext;
import me.naptila.deobfuscator.dex.RegisterLiveness;
import me.naptila.deobfuscator.transformers.np.NpTransformer;

import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.iface.instruction.*;

/** Specialize proven dispatcher edges, preserving traversed operations by cloning their prefix. */
public final class DispatcherTransformer extends NpTransformer {
    public String id() { return "np.dispatcher"; }
    public PassResult run(MethodContext context) {
        CodeGraph graph = context.graph();
        // Earlier features can remove every helper reference before the dispatcher
        // is restored. Keep the original method's NP evidence for later rounds.
        if (!applies(context, graph) && !applies(context, context.originalGraph())) return PassResult.unchanged();
        Set<Integer> dispatchers = new HashSet<>();
        for (int i = 0; i + 1 < graph.size(); i++)
            if (CodeGraph.isSwitch(graph.at(i).getOpcode()) && loopingDefault(graph, i)) dispatchers.add(i);
        if (dispatchers.isEmpty()) return PassResult.unchanged();
        return new DispatcherRecovery(model, false, false).run(context, dispatchers);
    }

    private static boolean loopingDefault(CodeGraph graph, int dispatcher) {
        int selector = ((OneRegisterInstruction) graph.at(dispatcher)).getRegisterA();
        BitSet aliases = new BitSet();
        aliases.set(selector);
        Set<Integer> visited = new HashSet<>();
        int cursor = dispatcher + 1;
        for (int budget = 0; budget < ComparisonDispatchers.PATH_LIMIT; budget++) {
            if (cursor == dispatcher) return aliases.get(selector);
            if (cursor >= graph.size() || graph.isPayload(cursor) || !visited.add(cursor)) return false;
            var op = graph.at(cursor).getOpcode();
            if (CodeGraph.isGoto(op)) {
                cursor = graph.successors(cursor).get(0);
                continue;
            }
            // NP restores live aliases on the default backedge and in the header.
            // Recovery preserves header writes on each specialized incoming edge.
            boolean copy = switch (op) {
                case MOVE, MOVE_FROM16, MOVE_16, MOVE_OBJECT, MOVE_OBJECT_FROM16, MOVE_OBJECT_16,
                     MOVE_WIDE, MOVE_WIDE_FROM16, MOVE_WIDE_16 -> true;
                default -> false;
            };
            if (op.canThrow() || op != Opcode.NOP && !op.name.startsWith("const") && !copy) return false;
            boolean low = false, high = false;
            if (copy) {
                var move = (TwoRegisterInstruction) graph.at(cursor);
                low = aliases.get(move.getRegisterB());
                high = op.setsWideRegister() && aliases.get(move.getRegisterB() + 1);
            }
            aliases.andNot(RegisterLiveness.writes(graph.at(cursor)));
            if (copy) {
                int target = ((TwoRegisterInstruction) graph.at(cursor)).getRegisterA();
                aliases.set(target, low);
                if (op.setsWideRegister()) aliases.set(target + 1, high);
            }
            cursor++;
        }
        return false;
    }

    public static final class Provider extends NpTransformer.Provider {
        public String id() { return "np.dispatcher"; }
        public String displayName() { return "Control-flow unflattening"; }
        public String description() { return "Restore switch dispatcher paths while preserving exception order and application operations."; }
        public DexPass create(TransformerOptions options) {
            options.requireOnly();
            return new DispatcherTransformer();
        }
    }
}
