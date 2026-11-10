package me.naptila.deobfuscator.app;

import java.util.List;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.dex.DexEngine;
import me.naptila.deobfuscator.dex.EngineProgress;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import org.jf.dexlib2.iface.DexFile;

/** Embeddable API; no command-line parsing or filesystem access. */
public final class Deobfuscator {
    private final TransformerRegistry registry;
    public Deobfuscator(TransformerRegistry registry) { this.registry = registry; }
    public DexEngine.Result transform(DexFile input, List<TransformerSpec> transformers, int maxRounds) {
        return new DexEngine(registry.create(transformers), maxRounds).transform(input);
    }
    public DexEngine.Result transform(DexFile input, List<TransformerSpec> transformers, int maxRounds,
                                      java.util.function.Consumer<EngineProgress> progress) {
        return new DexEngine(registry.create(transformers), maxRounds).transform(input, progress);
    }
}
