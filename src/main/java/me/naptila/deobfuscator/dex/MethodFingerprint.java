package me.naptila.deobfuscator.dex;

import java.io.IOException;
import java.security.*;
import java.util.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.writer.io.MemoryDataStore;
import org.jf.dexlib2.writer.pool.DexPool;

/** Deterministic fingerprint including code, flags, annotations, handlers and debug metadata. */
public final class MethodFingerprint {
    private MethodFingerprint() {}
    public static String of(DexContext dex, Method method) {
        var cls = new ImmutableClassDef(method.getDefiningClass(), 1, "Ljava/lang/Object;", List.of(), null,
                Set.of(), List.of(), List.of(method));
        var data = new MemoryDataStore();
        try {
            DexPool.writeTo(data, new ImmutableDexFile(dex.original().getOpcodes(), List.of(cls)));
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data.getData()));
        } catch (IOException | NoSuchAlgorithmException error) { throw new IllegalStateException("Cannot fingerprint " + Signatures.of(method), error); }
    }
}
