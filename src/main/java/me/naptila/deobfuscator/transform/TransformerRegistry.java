package me.naptila.deobfuscator.transform;

import java.util.*;
import me.naptila.deobfuscator.config.*;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.dex.DexPass;

/** Discovery and construction only; no dependencies on concrete rules. */
public final class TransformerRegistry {
    private final Map<String, TransformerProvider> providers;

    public TransformerRegistry(Collection<? extends TransformerProvider> providers) {
        Map<String, TransformerProvider> registered = new LinkedHashMap<>();
        for (TransformerProvider provider : providers) {
            if (provider.id() == null || provider.id().isBlank()) throw new IllegalArgumentException("Empty transformer id");
            if (registered.putIfAbsent(provider.id(), provider) != null)
                throw new IllegalArgumentException("Duplicate transformer: " + provider.id());
        }
        this.providers = Collections.unmodifiableMap(registered);
    }
    public static TransformerRegistry discover() {
        List<TransformerProvider> providers = new ArrayList<>();
        ServiceLoader.load(TransformerProvider.class).forEach(providers::add);
        return new TransformerRegistry(providers);
    }
    public Collection<TransformerProvider> providers() { return providers.values(); }
    public Optional<TransformerProvider> provider(String id) { return Optional.ofNullable(providers.get(id)); }

    public List<TransformerSpec> scheduled(List<TransformerSpec> specs) {
        Set<String> explicit = new HashSet<>();
        for (TransformerSpec spec : specs) {
            if (!explicit.add(spec.id())) throw new IllegalArgumentException("Duplicate transformer: " + spec.id());
            if (!providers.containsKey(spec.id())) throw new IllegalArgumentException("Unknown transformer: " + spec.id());
        }
        Map<String, TransformerOptions> cleanup = new LinkedHashMap<>();
        for (TransformerSpec spec : specs) for (TransformerSpec step : providers.get(spec.id()).cleanup(spec.options())) {
            if (explicit.contains(step.id())) continue;
            if (!providers.containsKey(step.id())) throw new IllegalArgumentException("Unknown cleanup transformer: " + step.id());
            Map<String, Object> options = new LinkedHashMap<>(cleanup.getOrDefault(step.id(), TransformerOptions.empty()).values());
            step.options().values().forEach((key, value) -> {
                Object previous = options.putIfAbsent(key, value);
                if (previous != null && !previous.equals(value))
                    throw new IllegalArgumentException("Conflicting cleanup option: " + step.id() + "." + key);
            });
            cleanup.put(step.id(), new TransformerOptions(options));
        }
        List<TransformerSpec> scheduled = new ArrayList<>(specs);
        cleanup.forEach((id, options) -> scheduled.add(new TransformerSpec(id, options)));
        return List.copyOf(scheduled);
    }
    public List<DexPass> create(List<TransformerSpec> specs) {
        List<DexPass> passes = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (TransformerSpec spec : scheduled(specs)) {
            if (!ids.add(spec.id())) throw new IllegalArgumentException("Duplicate transformer: " + spec.id());
            TransformerProvider provider = providers.get(spec.id());
            if (provider == null) throw new IllegalArgumentException("Unknown transformer: " + spec.id());
            DexPass pass;
            try { pass = Objects.requireNonNull(provider.create(spec.options()), "provider returned null"); }
            catch (RuntimeException error) { throw new IllegalArgumentException(spec.id() + ": " + error.getMessage(), error); }
            if (!pass.id().equals(spec.id())) throw new IllegalArgumentException("Provider/transformer id mismatch: " + spec.id());
            passes.add(pass);
        }
        return List.copyOf(passes);
    }
}
