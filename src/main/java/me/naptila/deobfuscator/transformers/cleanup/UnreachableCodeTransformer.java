package me.naptila.deobfuscator.transformers.cleanup;

import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.DexPass;
import me.naptila.deobfuscator.dex.MethodContext;
import me.naptila.deobfuscator.dex.UnreachableInstructions;
import me.naptila.deobfuscator.transform.TransformerProvider;

/** Reachability includes all possible exception handlers, without predicting exception types. */
public final class UnreachableCodeTransformer implements DexPass {
    @Override public String id() { return "dex.unreachable"; }
    @Override public PassResult run(MethodContext context) {
        return PassResult.changed(UnreachableInstructions.remove(context));
    }

    public static final class Provider implements TransformerProvider {
        public String id() { return "dex.unreachable"; }
        public String description() { return "Remove unreachable instructions with exception edges and try-table relocation"; }
        public DexPass create(TransformerOptions options) {
            options.requireOnly();
            return new UnreachableCodeTransformer();
        }
    }
}
