package me.naptila.deobfuscator.transform;

import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.dex.DexPass;
import java.util.List;

/** ServiceLoader extension point. Create a fresh transformer for each run. */
public interface TransformerProvider {
    String id();
    default String displayName() { return id(); }
    String description();
    DexPass create(TransformerOptions options);
    /** Internal cleanup scheduled once after the selected features. Explicit legacy rules take precedence. */
    default List<TransformerSpec> cleanup(TransformerOptions options) { return List.of(); }
    default boolean internal() { return false; }
}
