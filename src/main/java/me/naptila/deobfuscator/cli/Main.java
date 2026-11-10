package me.naptila.deobfuscator.cli;

import java.io.PrintStream;
import java.util.ServiceConfigurationError;
import me.naptila.deobfuscator.app.*;
import me.naptila.deobfuscator.app.DeobfuscationRunner;
import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.app.FileRunResult;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.dex.DexEngine;
import me.naptila.deobfuscator.transform.TransformerRegistry;

public final class Main {
    private Main() {}
    public static void main(String[] args) {
        int status = run(args, System.out, System.err);
        if (status != 0) System.exit(status);
    }
    public static int run(String[] args, PrintStream out, PrintStream err) {
        try {
            CliArguments arguments = CliArguments.parse(args);
            if (arguments.help()) { help(out); return 0; }
            TransformerRegistry registry = TransformerRegistry.discover();
            if (arguments.list()) {
                registry.providers().stream().filter(provider -> !provider.internal())
                        .forEach(provider -> out.println(provider.id() + "  " + provider.description()));
                return 0;
            }
            RunConfiguration config = arguments.configuration();
            FileRunResult files = new DeobfuscationRunner(new Deobfuscator(registry)).runInput(config);
            DexEngine.Result result = files.result();
            long incomplete = result.methods().stream().filter(m -> !m.converged() && !m.rolledBack()).count();
            out.printf("%s: %d methods changed, %d methods rolled back, %d hit round limit.%n",
                    config.dryRun() ? "Dry run" : "Wrote " + config.output(), result.changedMethods(), result.failedMethods(), incomplete);
            if (config.report() != null) out.println("Report: " + config.report());
            if (result.dexEdits() != 0) out.println("DEX-level cleanup edits: " + result.dexEdits());
            if (files.apk()) {
                out.println("APK DEX entries (analyzed together): " + String.join(", ", files.dexEntries()));
                if (!config.dryRun()) out.println("Output APK is UNSIGNED. Re-sign before installation; the original signature is not retained.");
            }
            return result.failedMethods() > 0 || incomplete > 0 ? 2 : 0;
        } catch (Exception | ServiceConfigurationError error) {
            err.println("Error: " + error.getMessage());
            return 1;
        }
    }
    private static void help(PrintStream out) {
        out.println("""
                Usage: deobfuscator --config config.yml [overrides]
                   or: deobfuscator --input input.dex --output output.dex [options]
                   or: deobfuscator --input input.apk --output output.unsigned.apk [options]
                  --config FILE         Ordered transformer configuration (YAML)
                  --dry-run             Transform in memory without writing DEX/APK
                  --report FILE         Write per-method/transformer JSON report
                  --list-transformers   List registered transformers and descriptions
                  --transformers id,id  Replace transformer list in execution order
                  --max-rounds N        Method fixed-point limit (default: 20)
                  --xor-method SIG      Append a UTF-16 XOR model to strings.decrypt
                  --list-passes         Alias for --list-transformers
                  --passes id,id        Alias for --transformers
                CLI paths are relative to the working directory; YAML paths to the YAML file.
                Existing output files are never overwritten. Input may be DEX or APK (including multidex).
                APK output is unsigned; re-sign before installation. Resources are preserved.
                Exit codes: 0 success, 1 input/output/config error, 2 partial result (see report).
                """);
    }
}
