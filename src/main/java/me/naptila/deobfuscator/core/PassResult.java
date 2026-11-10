package me.naptila.deobfuscator.core;

import java.util.List;

public record PassResult(int edits, List<String> notes) {
    private static final PassResult UNCHANGED = new PassResult(0, List.of());
    public PassResult {
        if (edits < 0) throw new IllegalArgumentException("Negative edit count");
        notes = List.copyOf(notes);
    }
    public static PassResult unchanged() { return UNCHANGED; }
    public static PassResult changed(int edits) { return edits == 0 ? UNCHANGED : new PassResult(edits, List.of()); }
    public static PassResult skipped(String reason) { return new PassResult(0, List.of(reason)); }
}
