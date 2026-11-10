package me.naptila.deobfuscator.dex;

import java.util.Objects;
import me.naptila.deobfuscator.core.PassResult;
import org.jf.dexlib2.iface.DexFile;

/** Optional hook after method transactions; phase order first, configuration order within a phase. */
public interface DexFinalizer {
    enum Phase { LINK, TRANSFORM, REMOVE_DEFINITIONS, COLLECT_TABLES }
    default Phase phase() { return Phase.TRANSFORM; }
    /** Linkers must run even when an unrelated method transaction was rolled back. */
    default boolean requiresCompleteMethods() { return true; }
    record Result(DexFile dex, PassResult result) {
        public Result { Objects.requireNonNull(dex); Objects.requireNonNull(result); }
    }
    Result finish(DexContext original, DexFile rewritten);
}
