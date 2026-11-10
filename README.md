# Android Deobfuscator

English | [简体中文](README.zh-CN.md)

A command-line deobfuscation tool for Android APKs and DEX files. It reads, analyzes, and rewrites DEX directly, with joint analysis of all DEX files in an APK. Features are independently selectable, with cleanup scheduled automatically. Supported obfuscation patterns include NP Manager.

## Build and run

Requires JDK 17 or newer. Use the included Gradle Wrapper:

```bash
./gradlew test installDist
build/install/deobfuscator/bin/deobfuscator --list-transformers
build/install/deobfuscator/bin/deobfuscator \
  --input sample.apk --output sample.cleaned.apk --report report.json
```

On Windows, use `gradlew.bat` and the generated `.bat` launcher. Input can be a standalone DEX or an APK. Output and report paths must be new files. APK output preserves each class's original DEX placement and resource contents, and must be signed again before installation.

`./gradlew distZip` builds a distribution containing CLI launchers, dependencies, configuration examples, and documentation. Extract it and run `bin/deobfuscator`, or `bin/deobfuscator.bat` on Windows.

## Transformers and default pipeline

| Transformer | Purpose |
| --- | --- |
| `np.method-hiding` | Restore verified guarded proxies, literals, and member operations |
| `np.numbers` | Recover proven integer constants and 64-bit XOR constants |
| `np.instructions` | Simplify expanded int/long arithmetic and bitwise operations, normalize constructor object aliases, and optionally restore expanded float/double addition and subtraction |
| `np.strings` | Recognize short-array XOR decryptors and recover known strings |
| `strings.decrypt` | Decode configured UTF-16 XOR and StringFog Base64/byte-XOR/UTF-8 patterns |
| `np.opaque-predicates` | Evaluate verified hash/GuardInt helpers and simplify conditions |
| `np.dispatcher` | Recover flattened switch dispatcher paths and shared integer state updates |
| `np.flower` | Recover XOR/hash dispatchers used by junk-code obfuscation, including switches and comparison chains |

The table lists the default execution order. Shared cleanup runs after the selected features in each method. Processing repeats until unchanged, with a default limit of 20 rounds per method. Cross-method finalization runs in this order: linking, general rewrites, proxy removal, and string-table collection. Flattening, junk-code obfuscation, and opaque predicates remain separate features.

Configure cleanup options on the owning feature: `np.strings` accepts `removeProtectedStringCalls`, and `np.method-hiding` accepts `assumeClosedWorld` and `keepMethods`. Shared cleanup is scheduled once, while reports retain individual steps. Legacy configurations using `np.cleanup`, `np.method-hiding.cleanup`, `dex.constant-switch`, and `dex.unreachable` remain supported. Explicit cleanup configurations take precedence and are not scheduled twice.

The optional `np.reflection` feature restores NP reflection-cache dispatchers. It requires Android/JAR member metadata and explicit runtime assumptions, so it is excluded from the default pipeline. In NP Manager, junk-code obfuscation and control-flow flattening are mutually exclusive input options, as are reflection obfuscation and method hiding. Their recognition rules can coexist in the deobfuscator configuration.

Helpers are recognized by their method bodies rather than random names. Validated samples cover NP 3.1.54 templates, newer combined flattening templates with shared integer state updates, and some D8-transformed comparison chains. Unknown templates are preserved with skip diagnostics. Resource ID decryption is not implemented. Readable output does not imply complete recovery of the original source code.

## Configuration

Copy and adapt the [configuration example](config.example.yml):

```bash
build/install/deobfuscator/bin/deobfuscator --config config.example.yml
```

Top-level YAML paths are relative to the configuration file; CLI paths are relative to the working directory. Absolute paths are recommended for `classpath`. `--transformers id,id` replaces the entire transformer list. `--dry-run` performs transformations in memory and can write a report, without writing an output APK or DEX. An empty list, `transformers: []`, disables all rules. The existing `--passes`, `--list-passes`, and `--xor-method` shortcuts remain available.

Unknown options, duplicate transformer IDs, and incorrect types are rejected. See the [configuration reference](docs/configuration.md) for option defaults and the requirements for floating-point recovery, protected-call removal, closed-world assumptions, and immutable-array assumptions.

If a method transformation fails, that method is rolled back. Reports record rollbacks, non-convergence, skipped transformations, and finalization decisions. Exit code `0` means the run completed, `1` indicates a configuration or processing error, and `2` indicates a method rollback or round limit. Exit codes do not indicate whether all obfuscation was removed.

## Development

NP implementations are organized into `analysis`, `controlflow`, `strings`, `numbers`, `instructions`, `methodhiding`, `reflection`, and `support`. Proxy and reflection cleanup belong to their respective features; string-table collection belongs to `strings`. Internal `NpCleanup` handles shared cleanup at the end of each round. Dispatcher recovery shares `DispatcherRecovery`, and option type validation is centralized in `TransformerOptions`.

Transformers are registered through the `TransformerProvider` SPI. To add a rule, declare a nested Provider in the transformer file, add its SPI entry, and add tests. The CLI and engine do not depend on concrete transformers. General string algorithms can extend `StringDecoder`. The old `ServiceLoader<DexPass>` registration mechanism has been removed; plugins must provide a Provider.

See the [extension guide](docs/extending.md) for package responsibilities, analysis caches, method transactions, finalization phases, and integration examples.

## Validation

```bash
./gradlew clean test installDist distZip
```

Regression fixtures in `src/test/resources` cover NP strings, numbers, instruction substitution, flattening, junk-code obfuscation, comparison chains, method hiding, reflection, and combined obfuscation. Tests check exception paths, business effects, wide registers, field/array escape, DEX write/read round trips, idempotence, CLI configuration, dry runs, and input/output protection.

Local analysis records and APKs belong in `tmp/` and are excluded from source commits and distributions.
