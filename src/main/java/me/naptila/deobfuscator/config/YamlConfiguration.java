package me.naptila.deobfuscator.config;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/** Strict data-only YAML; paths are relative to the configuration file. */
public final class YamlConfiguration {
    private YamlConfiguration() {}

    /** Portable exports use absolute file paths; transformer options retain their exact values. */
    public static String write(RunConfiguration config) {
        Map<String, Object> root = new LinkedHashMap<>();
        if (config.input() != null) root.put("input", config.input().toAbsolutePath().normalize().toString());
        if (config.output() != null) root.put("output", config.output().toAbsolutePath().normalize().toString());
        if (config.report() != null) root.put("report", config.report().toAbsolutePath().normalize().toString());
        root.put("dryRun", config.dryRun());
        root.put("maxRounds", config.maxRounds());
        List<Object> specs = new ArrayList<>();
        for (TransformerSpec spec : config.transformers()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("id", spec.id());
            entry.put("options", spec.options().values());
            specs.add(entry);
        }
        root.put("transformers", specs);
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        return new Yaml(options).dump(root);
    }

    public static RunConfiguration read(Path file) throws IOException {
        LoaderOptions options = new LoaderOptions();
        options.setAllowDuplicateKeys(false);
        options.setMaxAliasesForCollections(0);
        options.setCodePointLimit(1_000_000);
        Map<String, Object> root;
        try (Reader reader = Files.newBufferedReader(file)) {
            root = map(new Yaml(new SafeConstructor(options)).load(reader), "configuration");
        }
        only(root, "input", "output", "report", "dryRun", "maxRounds", "transformers");
        RunConfiguration defaults = RunConfiguration.defaults();
        List<TransformerSpec> specs = defaults.transformers();
        if (root.containsKey("transformers")) {
            if (!(root.get("transformers") instanceof List<?> list))
                throw new IllegalArgumentException("transformers must be an ordered list");
            specs = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof String id) specs.add(new TransformerSpec(id));
                else {
                    Map<String, Object> spec = map(item, "transformer");
                    only(spec, "id", "options");
                    specs.add(new TransformerSpec(string(spec.get("id"), "transformer.id"),
                            new TransformerOptions(spec.containsKey("options")
                                    ? map(spec.get("options"), "transformer.options") : Map.of())));
                }
            }
        }
        Object rounds = root.getOrDefault("maxRounds", defaults.maxRounds());
        if (!(rounds instanceof Integer count)) throw new IllegalArgumentException("maxRounds must be an integer");
        Object dryRun = root.getOrDefault("dryRun", false);
        if (!(dryRun instanceof Boolean dry)) throw new IllegalArgumentException("dryRun must be a boolean");
        Path base = file.toAbsolutePath().normalize().getParent();
        return new RunConfiguration(path(root, "input", base), path(root, "output", base), path(root, "report", base),
                dry, count, specs);
    }

    private static Path path(Map<String, Object> values, String key, Path base) {
        return values.containsKey(key) ? base.resolve(string(values.get(key), key)).normalize() : null;
    }
    private static String string(Object value, String name) {
        if (!(value instanceof String text) || text.isBlank()) throw new IllegalArgumentException(name + " must be a nonempty string");
        return text;
    }
    private static Map<String, Object> map(Object value, String name) {
        if (!(value instanceof Map<?, ?> map)) throw new IllegalArgumentException(name + " must be a mapping");
        Map<String, Object> result = new LinkedHashMap<>();
        map.forEach((key, v) -> result.put(string(key, name + " key"), v));
        return result;
    }
    private static void only(Map<String, Object> map, String... keys) {
        Set<String> unknown = new TreeSet<>(map.keySet());
        unknown.removeAll(Arrays.asList(keys));
        if (!unknown.isEmpty()) throw new IllegalArgumentException("Unknown configuration keys: " + unknown);
    }
}
