package me.naptila.deobfuscator.config;

import java.nio.file.Path;
import java.util.List;

public record RunConfiguration(Path input, Path output, Path report, boolean dryRun, int maxRounds,
                               List<TransformerSpec> transformers) {
    public RunConfiguration {
        if (maxRounds < 1) throw new IllegalArgumentException("maxRounds must be positive");
        transformers = List.copyOf(transformers);
    }
    public static RunConfiguration defaults() {
        return new RunConfiguration(null, null, null, false, 20, List.of(
                new TransformerSpec("np.method-hiding"), new TransformerSpec("np.numbers"), new TransformerSpec("np.instructions"), new TransformerSpec("np.strings"), new TransformerSpec("strings.decrypt"),
                new TransformerSpec("np.opaque-predicates"), new TransformerSpec("np.dispatcher"),
                new TransformerSpec("np.flower")));
    }
}
