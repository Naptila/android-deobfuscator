package me.naptila.deobfuscator.cli;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import me.naptila.deobfuscator.config.*;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.config.YamlConfiguration;

/** CLI overrides YAML; legacy flags translate to transformer configuration. */
final class CliArguments {
    private final Map<String, String> values = new HashMap<>();
    private final List<String> xorMethods = new ArrayList<>();
    private boolean dryRun, list, help;

    static CliArguments parse(String[] args) {
        CliArguments result = new CliArguments();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--help", "-h" -> result.help = true;
                case "--dry-run" -> result.dryRun = true;
                case "--list-passes", "--list-transformers" -> result.list = true;
                case "--xor-method" -> {
                    if (++i == args.length) throw new IllegalArgumentException("Missing --xor-method value");
                    result.xorMethods.add(args[i]);
                }
                case "--config", "--input", "--output", "--report", "--passes", "--transformers", "--max-rounds" -> {
                    String key = args[i].equals("--passes") ? "--transformers" : args[i];
                    if (++i == args.length) throw new IllegalArgumentException("Missing " + key + " value");
                    if (result.values.put(key, args[i]) != null) throw new IllegalArgumentException("Duplicate option " + key);
                }
                default -> throw new IllegalArgumentException("Unknown argument: " + args[i]);
            }
        }
        return result;
    }
    boolean help() { return help; }
    boolean list() { return list; }

    RunConfiguration configuration() throws IOException {
        RunConfiguration base = values.containsKey("--config")
                ? YamlConfiguration.read(Path.of(values.get("--config"))) : RunConfiguration.defaults();
        List<TransformerSpec> specs = base.transformers();
        if (values.containsKey("--transformers")) {
            specs = Arrays.stream(values.get("--transformers").split(",", -1))
                    .map(String::trim).map(TransformerSpec::new).toList();
        }
        if (!xorMethods.isEmpty()) {
            boolean found = false;
            List<TransformerSpec> updated = new ArrayList<>();
            for (TransformerSpec spec : specs) {
                if (spec.id().equals("strings.decrypt")) {
                    List<String> methods = new ArrayList<>(spec.options().strings("xorMethods"));
                    methods.addAll(xorMethods);
                    spec = new TransformerSpec(spec.id(), spec.options().with("xorMethods", methods));
                    found = true;
                }
                updated.add(spec);
            }
            if (!found) throw new IllegalArgumentException("--xor-method requires strings.decrypt in the transformer list");
            specs = updated;
        }
        int rounds = values.containsKey("--max-rounds") ? Integer.parseInt(values.get("--max-rounds")) : base.maxRounds();
        return new RunConfiguration(path("--input", base.input()), path("--output", base.output()),
                path("--report", base.report()), dryRun || base.dryRun(), rounds, specs);
    }
    private Path path(String key, Path fallback) {
        if (!values.containsKey(key)) return fallback;
        if (values.get(key).isBlank()) throw new IllegalArgumentException(key + " must not be blank");
        return Path.of(values.get(key)).toAbsolutePath().normalize();
    }
}
