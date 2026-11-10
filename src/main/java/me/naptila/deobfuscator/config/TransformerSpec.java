package me.naptila.deobfuscator.config;

import java.util.Objects;

public record TransformerSpec(String id, TransformerOptions options) {
    public TransformerSpec {
        if (id == null || id.isBlank()) throw new IllegalArgumentException("Transformer id is required");
        Objects.requireNonNull(options, "options");
    }
    public TransformerSpec(String id) { this(id, TransformerOptions.empty()); }
}
