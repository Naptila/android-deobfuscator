package me.naptila.deobfuscator.dex;

/** A lightweight live snapshot; observers must not mutate analysis state. */
public record EngineProgress(Phase phase, String transformer, String method, int round,
                             int completedMethods, int totalMethods) {
    public enum Phase { PREPARING, METHODS, FINALIZING }
}
