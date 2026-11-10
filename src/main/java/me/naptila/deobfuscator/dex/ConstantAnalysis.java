package me.naptila.deobfuscator.dex;

import java.util.*;
import java.util.function.BiConsumer;
import org.jf.dexlib2.iface.instruction.Instruction;

/** Forward must-constant analysis; optionally merge unaffected locals from throwing sites. */
public final class ConstantAnalysis {
    private final Constants[] before;
    public ConstantAnalysis(CodeGraph graph) {
        this(graph, ConstantEvaluator::step, false);
    }
    public ConstantAnalysis(CodeGraph graph, BiConsumer<Instruction, Constants> evaluator, boolean pruneBranches) {
        this(graph, evaluator, pruneBranches, false);
    }
    public ConstantAnalysis(CodeGraph graph, BiConsumer<Instruction, Constants> evaluator, boolean pruneBranches, boolean preserveExceptionLocals) {
        before = new Constants[graph.size()];
        if (graph.size() == 0) return;
        ArrayDeque<Integer> work = new ArrayDeque<>();
        boolean[] queued = new boolean[graph.size()];
        before[0] = new Constants(); work.add(0); queued[0] = true;
        long remaining = Math.max(10000L, (long) graph.size() * 256);
        while (!work.isEmpty()) {
            if (--remaining == 0) throw new IllegalStateException("Constant analysis work limit exceeded");
            int i = work.removeFirst(); queued[i] = false;
            Constants out = before[i].copy(); evaluator.accept(graph.at(i), out);
            for (int target : pruneBranches ? ConstantBranches.successors(graph, i, before[i]) : graph.successors(i))
                propagate(target, out, work, queued);
            if (graph.handlers(i).isEmpty()) continue;
            Constants exceptional = new Constants();
            if (preserveExceptionLocals) {
                exceptional = before[i].copy(); exceptional.result(null);
                // Only unaffected locals are propagated. Never use the normal result of a
                // throwing instruction, nor rely on its destination retaining the old value.
                BitSet writes = RegisterLiveness.writes(graph.at(i));
                for (int r = writes.nextSetBit(0); r >= 0; r = writes.nextSetBit(r + 1)) exceptional.put(r, null);
            }
            for (int target : graph.handlers(i)) propagate(target, exceptional, work, queued);
        }
    }
    private void propagate(int target, Constants value, ArrayDeque<Integer> work, boolean[] queued) {
        boolean changed;
        if (before[target] == null) { before[target] = value.copy(); changed = true; }
        else changed = before[target].merge(value);
        if (changed && !queued[target]) { work.add(target); queued[target] = true; }
    }
    public Constants before(int index) { return before[index] == null ? null : before[index].copy(); }
}
