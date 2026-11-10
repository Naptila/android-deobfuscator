package me.naptila.deobfuscator.dex;

import me.naptila.deobfuscator.core.Pass;

/** Method transformer; configuration and plugin discovery use TransformerProvider. */
public interface DexPass extends Pass<MethodContext> {
    /** Called once per input before any method is changed. Never execute target code here. */
    default void prepare(DexContext context) {}
}
