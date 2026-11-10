package me.naptila.deobfuscator.dex;

import java.util.*;

/** Missing register = unknown. Values are int bit patterns, strings, or validated field identities. */
public final class Constants {
    /** Symbolic identity of a validated static field, not its contents or a runtime object. */
    public record FieldValue(String signature) {}
    private final Map<Integer, Object> registers = new HashMap<>();
    private Object result;

    public Object get(int register) { return registers.get(register); }
    public Object result() { return result; }
    public void result(Object value) { result = value; }
    public void put(int register, Object value) {
        if (value == null) registers.remove(register);
        else if (value instanceof Integer || value instanceof String || value instanceof FieldValue) registers.put(register, value);
        else throw new IllegalArgumentException("Unsupported constant");
    }
    public Constants copy() {
        Constants copy = new Constants(); copy.registers.putAll(registers); copy.result = result; return copy;
    }
    public boolean merge(Constants other) {
        int before = registers.size();
        registers.entrySet().removeIf(e -> !Objects.equals(e.getValue(), other.get(e.getKey())));
        boolean changed = before != registers.size();
        if (result != null && !Objects.equals(result, other.result)) { result = null; changed = true; }
        return changed;
    }
}
