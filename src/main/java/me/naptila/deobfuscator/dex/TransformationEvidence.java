package me.naptila.deobfuscator.dex;

import java.util.*;
import org.jf.dexlib2.iface.Method;

/** Run-local provenance. Replacements become visible only when their method transaction commits. */
public final class TransformationEvidence {
    public record Candidate(String method, String producer, String rule, String originalSha256, List<String> facts) {
        public Candidate { facts = List.copyOf(facts); }
    }
    /** Index/address identify the instruction snapshot in the indicated pass invocation, not the original DEX. */
    public record Replacement(String producer, String target, String caller, int invocation, int instructionIndex, int codeAddress) {}
    public record Decision(String method, String action, String outputSha256, List<String> reasons, List<String> references) {
        public Decision { reasons = List.copyOf(reasons); references = List.copyOf(references); }
    }
    public record Snapshot(List<Candidate> candidates, List<Replacement> replacements, List<Decision> decisions, List<String> incompleteMethods) {
        public Snapshot { candidates = List.copyOf(candidates); replacements = List.copyOf(replacements); decisions = List.copyOf(decisions); incompleteMethods = List.copyOf(incompleteMethods); }
        public static Snapshot empty() { return new Snapshot(List.of(), List.of(), List.of(), List.of()); }
    }
    private final Map<String, Candidate> candidates = new TreeMap<>();
    private final List<Replacement> replacements = new ArrayList<>();
    private final Map<String, String> accepted = new TreeMap<>();
    private final Map<String, Decision> decisions = new TreeMap<>();
    private final Set<String> incomplete = new TreeSet<>();
    public void register(DexContext dex, Method method, String producer, String rule, List<String> facts) {
        String signature = Signatures.of(method);
        if (dex.methods().get(signature) != method && !Objects.equals(dex.methods().get(signature), method))
            throw new IllegalArgumentException("Candidate is not from the original input: " + signature);
        var candidate = new Candidate(signature, producer, rule, MethodFingerprint.of(dex, method), facts);
        Candidate previous = candidates.putIfAbsent(signature, candidate);
        if (previous != null && !previous.equals(candidate)) throw new IllegalArgumentException("Conflicting candidate evidence: " + signature);
    }
    void commit(DexContext dex, Method output, List<Replacement> pending) {
        String signature = Signatures.of(output);
        for (Replacement replacement : pending) {
            Candidate candidate = candidates.get(replacement.target());
            if (!signature.equals(replacement.caller()) || candidate == null || !candidate.producer().equals(replacement.producer()))
                throw new IllegalArgumentException("Replacement has no matching provenance");
        }
        if (candidates.containsKey(signature)) accepted.put(signature, MethodFingerprint.of(dex, output));
        replacements.addAll(pending);
    }
    void incomplete(String method) { incomplete.add(method); }
    public String acceptedFingerprint(String signature) { return accepted.get(signature); }
    public void decide(Decision decision) { decisions.put(decision.method(), decision); }
    public Snapshot snapshot() { return new Snapshot(new ArrayList<>(candidates.values()), replacements, new ArrayList<>(decisions.values()), new ArrayList<>(incomplete)); }
}
