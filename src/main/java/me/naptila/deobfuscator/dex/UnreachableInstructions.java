package me.naptila.deobfuscator.dex;

import java.util.ArrayDeque;
import java.util.BitSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.jf.dexlib2.Opcode;

/** Reachability includes every possible handler, without predicting exception types. */
public final class UnreachableInstructions {
    private UnreachableInstructions() {}
    public static int remove(MethodContext context) {
        CodeGraph graph = context.graph(); if (graph.size() == 0) return 0;
        Set<Integer> live = new HashSet<>(); ArrayDeque<Integer> work = new ArrayDeque<>(); work.add(0);
        while (!work.isEmpty()) {
            int at = work.removeFirst(); if (!live.add(at)) continue;
            work.addAll(graph.successors(at)); work.addAll(graph.handlers(at));
        }
        for (int at : List.copyOf(live)) {
            Opcode op = graph.at(at).getOpcode();
            if (CodeGraph.isSwitch(op) || op == Opcode.FILL_ARRAY_DATA) live.add(graph.payloadIndex(at));
        }
        BitSet remove = new BitSet();
        for (int i = 0; i < graph.size(); i++) if (!live.contains(i) && graph.at(i).getOpcode() != Opcode.NOP) remove.set(i);
        ExceptionEdits.remove(context, remove); return remove.cardinality();
    }
}
