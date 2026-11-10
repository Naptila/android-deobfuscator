package me.naptila.deobfuscator.config;

import java.util.*;

/** Immutable, data-only options. Each provider owns its option schema. */
public record TransformerOptions(Map<String, Object> values) {
    public TransformerOptions {
        values = freezeMap(values);
    }
    public static TransformerOptions empty() { return new TransformerOptions(Map.of()); }
    public void requireOnly(String... keys) {
        Set<String> unknown = new TreeSet<>(values.keySet());
        unknown.removeAll(Arrays.asList(keys));
        if (!unknown.isEmpty()) throw new IllegalArgumentException("Unknown transformer options: " + unknown);
    }
    public boolean bool(String key) {
        Object value = values.getOrDefault(key, false);
        if (!(value instanceof Boolean enabled)) throw new IllegalArgumentException(key + " must be a boolean");
        return enabled;
    }
    public List<String> strings(String key) {
        Object value = values.get(key);
        if (value == null) return List.of();
        if (!(value instanceof List<?> list) || list.stream().anyMatch(v -> !(v instanceof String)))
            throw new IllegalArgumentException(key + " must be a list of strings");
        return list.stream().map(String.class::cast).toList();
    }
    public TransformerOptions with(String key, Object value) {
        Map<String, Object> copy = new LinkedHashMap<>(values);
        copy.put(key, value);
        return new TransformerOptions(copy);
    }
    private static Map<String, Object> freezeMap(Map<?, ?> source) {
        Map<String, Object> result = new LinkedHashMap<>();
        source.forEach((key, value) -> {
            if (!(key instanceof String name)) throw new IllegalArgumentException("Option keys must be strings");
            result.put(name, freeze(value));
        });
        return Collections.unmodifiableMap(result);
    }
    private static Object freeze(Object value) {
        if (value instanceof Map<?, ?> map) return freezeMap(map);
        if (value instanceof List<?> list) return list.stream().map(TransformerOptions::freeze).toList();
        if (value instanceof String || value instanceof Boolean || value instanceof Number) return value;
        throw new IllegalArgumentException("Option values must be strings, numbers, booleans, lists or maps");
    }
}
