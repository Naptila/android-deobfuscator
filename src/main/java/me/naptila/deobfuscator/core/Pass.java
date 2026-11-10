package me.naptila.deobfuscator.core;

/** A deterministic transformation. Return zero edits when already at a fixed point. */
public interface Pass<C> {
    String id();
    PassResult run(C context);
}
