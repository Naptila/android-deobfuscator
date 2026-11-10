package me.naptila.deobfuscator.core;

import java.util.*;

/** Format-independent pass scheduling. Contexts own format-specific analyses and edits. */
public final class Pipeline<C> {
    public record Step(int round, String pass, PassResult result) {}
    public record Result(List<Step> steps, boolean converged) {
        public Result { steps = List.copyOf(steps); }
        public int edits() { return steps.stream().mapToInt(s -> s.result().edits()).sum(); }
    }
    private final List<Pass<C>> passes;
    private final int maxRounds;

    public Pipeline(List<? extends Pass<C>> passes, int maxRounds) {
        if (maxRounds < 1) throw new IllegalArgumentException("maxRounds must be positive");
        Set<String> ids = new HashSet<>();
        for (Pass<C> pass : passes) {
            if (!ids.add(pass.id())) throw new IllegalArgumentException("Duplicate pass: " + pass.id());
        }
        this.passes = List.copyOf(passes);
        this.maxRounds = maxRounds;
    }
    public Result run(C context) {
        return run(context, (pass, round) -> {});
    }
    public Result run(C context, java.util.function.BiConsumer<String, Integer> observer) {
        List<Step> steps = new ArrayList<>();
        for (int round = 1; round <= maxRounds; round++) {
            int edits = 0;
            for (Pass<C> pass : passes) {
                observer.accept(pass.id(), round);
                PassResult result = pass.run(context);
                steps.add(new Step(round, pass.id(), result));
                edits += result.edits();
            }
            if (edits == 0) return new Result(steps, true);
        }
        return new Result(steps, false);
    }
}
