package me.naptila.deobfuscator.app;

import java.util.*;
import me.naptila.deobfuscator.dex.DexEngine;

/** One program analysis, optionally spanning several DEX files inside an APK. */
public record FileRunResult(boolean apk, List<String> dexEntries, Map<String, String> classOwners,
                            List<String> removedSignatureEntries, DexEngine.Result result) {
    public FileRunResult {
        dexEntries = List.copyOf(dexEntries);
        classOwners = Map.copyOf(classOwners);
        removedSignatureEntries = List.copyOf(removedSignatureEntries);
    }
}
