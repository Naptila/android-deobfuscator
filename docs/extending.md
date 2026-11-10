# Development and extensions

English | [简体中文](extending.zh-CN.md)

The project uses a single Gradle module. Method transformations implement `DexPass`; registration and construction use a `TransformerProvider` declared in the same file. Concrete algorithms stay out of the CLI.

## Package responsibilities

| Package | Responsibility |
| --- | --- |
| `core` | Generic passes, fixed-point scheduling, and results; no DEX dependency |
| `dex` | Original-input indexes, analysis caches, method transactions, CFGs, data flow, instruction editing, and general cleanup |
| `transform` | Provider SPI, discovery, automatic cleanup scheduling and deduplication, and independent instance creation |
| `config` | YAML, top-level configuration, and typed transformer options |
| `app` | In-memory API and file processing workflows |
| `io` / `report` | DEX/APK I/O and JSON reports |
| `cli` | Arguments, help, and exit status |
| `strings` | Offline string algorithms and the `StringDecoder` extension interface |
| `transformers.strings` / `transformers.cleanup` | General string transformers and shared cleanup transformers |

NP implementations are organized by responsibility under `transformers.np`:

| Subpackage | Contents |
| --- | --- |
| Root package | `NpTransformer` prepares shared models and checks eligibility; internal `NpCleanup` performs shared cleanup at the end of each round |
| `analysis` | `NpAnalysis`, `NpModel`, helper shapes, integer expressions, short-table initialization and escape analysis; initializer shapes live in `NpArrays.Initializer` |
| `controlflow` | Flattening and junk-code recognition, comparison chains, and guard evaluation; shared path recovery through `DispatcherRecovery` |
| `strings` | Call-site decryption, `NpStringCalls` argument/bounds/removability proofs, and `StringTables` collection |
| `numbers` | Integer constants and wide XOR restoration |
| `instructions` | Int/long expansions, offset cancellation, and optional floating-point recovery |
| `methodhiding` | Guarded proxies, array getters, proxy inlining, and definition cleanup |
| `reflection` | Cache mappings, type proofs, member-call generation, string identity, and field analysis |
| `support` | Access and initialization checks, and proxy instruction re-encoding |

NP transformers share `NpAnalysis` over the original input, exposing facts through read-only views. Helpers can be normalized in bounded temporary methods before their shapes are verified again. Temporary rewrites commit neither output nor cleanup evidence. Array-getter recognition reuses method-hiding body proofs, separately from string-table immutability proofs.

## Execution lifecycle

1. `TransformerRegistry` preserves feature order, appends the providers' merged `cleanup(options)` steps, and creates independent transformer instances for each run. Each cleanup ID is scheduled once; explicit legacy cleanup takes precedence.
2. `DexContext` freezes indexes of original classes, methods, fields, and references.
3. Each transformer's `prepare(DexContext)` runs once per input, building shared or private facts.
4. Each method gets a `MethodContext`; configured transformers repeat until unchanged or the round limit is reached.
5. Instruction targets are validated before committing the method. Runtime exceptions roll back all rewrites to that method. Non-converged methods may output completed rewrites, but do not commit successful restoration evidence.
6. `DexFinalizer` processes output snapshots by phase: linking, general rewrites, proxy removal, and string-table collection.

Preparation failure aborts the run. Finalization requires all methods to succeed and converge by default. Mandatory adapter linking can opt out of that prerequisite, so unrelated method rollbacks do not prevent required linking. Finalization failure prevents output publication.

`DexContext` always describes the original input, avoiding traversal-order-dependent facts and stale caches after rollback. `MethodContext.original()` is the original method definition. `originalGraph()` lazily caches its immutable CFG for reuse across transformers and rounds. `code()` holds transactional code. After edits, rebuild `graph()` and data-flow analyses; do not retain current-code instruction indexes across mutations. Register growth and transactional code replacement do not change the original definition or its CFG.

Each feature declares its factory as a `public static final class Provider` inside the transformer file. Small helpers with one call site belong as named methods in the owning implementation. Shared path recovery, access proofs, and data flow remain centralized. Reflection cleanup and method-hiding definition cleanup belong to their respective features.

## Adding a transformer

Add a transformer in the appropriate feature package:

```java
package me.naptila.deobfuscator.transformers.example;

import core.me.naptila.deobfuscator.PassResult;
import dex.me.naptila.deobfuscator.DexPass;
import dex.me.naptila.deobfuscator.MethodContext;

public final class ExampleTransformer implements DexPass {
    public String id() { return "example.cleanup"; }
    public PassResult run(MethodContext context) {
        // Recognize the pattern, prove conditions, and apply Edits / ExceptionEdits.
        return PassResult.unchanged();
    }
}
```

Add a nested Provider in the same transformer class, declaring accepted options and creating a fresh instance. The following snippet belongs inside the class:

```java
public static final class Provider implements TransformerProvider {
    public String id() { return "example.cleanup"; }
    public String description() { return "Example cleanup rule"; }
    public DexPass create(TransformerOptions options) {
        options.requireOnly();
        return new ExampleTransformer();
    }
}
```

Append `me.naptila.deobfuscator.transformers.example.ExampleTransformer$Provider` to `src/main/resources/META-INF/services/me.naptila.deobfuscator.transform.TransformerProvider`, add `example.cleanup` to the YAML, and add fixtures and necessary counterexample tests. Nested providers must be public static with a public no-argument constructor, and provider/transformer IDs must match. SPI discovery order does not determine execution order, and discovery does not automatically enable a plugin.

NP feature providers extend `NpTransformer.Provider`, which schedules constant-branch, unreachable-code, and NP residual cleanup by default. Override `cleanup(options)` for feature-specific finalization or option forwarding. Compatibility providers use `internal()` to hide explicit cleanup entries from the normal feature list while keeping their IDs available in legacy YAML. A direct low-level `new DexEngine(...)` runs only the supplied passes. Use `Deobfuscator` / `TransformerRegistry` for full feature scheduling and automatic cleanup.

Validate options with `requireOnly(...)`, `bool(key)`, and `strings(key)`. The boolean reader defaults to false, and string lists default to empty; providers handle domain-specific validation such as exact signatures and can explicitly define different defaults. Update `RunConfiguration.defaults()` and configuration examples when adding a mature rule to the default pipeline.

External JARs use the same Provider SPI. The former `META-INF/services/me.naptila.deobfuscator.dex.DexPass` entry has been removed; old plugins need Provider wrappers. General string algorithms can implement `StringDecoder` and integrate through `StringDecryptTransformer` construction or its `StringDecoder` SPI. Return plaintext only for supported signatures with fully known arguments.

## Rewrite constraints

- Extract constants statically from input without executing target APK helpers. Knowing a return value and proving a call removable are separate conditions.
- Method hiding recognizes layered integer-guard wrappers through at most eight local fixed-point rounds, consuming only verified proxy bodies. Unknown business calls, writes, casts, and unverified reads are rejected. Wrapper returns select paths, while original calls remain; no removable facts are added to the shared model. Simplified bodies of multi-argument proxies remain bounded, with per-instruction register and call-encoding checks.
- Check normal and exceptional successor liveness before deleting or overwriting register values. Wide values occupy two words; overwriting either invalidates the old value.
- When removing unused hashes of known strings, initialization proofs intersect incoming paths. Add facts only after static member operations complete normally; exceptional edges carry the pre-operation state. Do not infer first-entry initialization from loop backedges, `const-class`, or caller initialization dependencies.
- Method hiding and hash cleanup share path proofs through `ProxyAccess.initializedBefore`, filtering facts to the classes each needs. Incomplete computation retains calls. Proxy expansion must preserve the first operation that establishes initialization.
- Moving throwing instructions requires identical ordered handler lists. Use `ExceptionEdits` to relocate try ranges, preserving catch/finally, business effects, and call order.
- Dispatcher specialization preserves necessary traversed prefixes and rejects unknown states and loops. Comparison chains and switches share recovery machinery; recognition conditions remain in their owning transformers.
- `Edits` and `BranchRelaxation` handle instruction generation and long branches. Use `appendScratchRegisters` for additional scratch space, while still checking 4/8-bit register encoding limits.
- `TransformationEvidence` commits restoration records only for successful method transactions. Proxy removal checks original fingerprints, final references, external entries, and complete-input conditions rather than guessing origin from names or simplified shapes.
- String rules, method cleanup, and DEX finalization respectively handle decryption, unused-call removal, and short-table collection, sharing argument and array proofs.
- Verify int/long simplification with 32/64-bit modular semantics. Float/double algebraic recovery is separate, disabled by default, and not described as bitwise equivalent.

See the [configuration reference](configuration.md) for optional assumptions and scope. New features must not bypass other transformers' rollback, identity, or exception checks.

## Validation

```bash
./gradlew clean test installDist distZip
```

Prioritize actual samples; counterexamples with unknown values, out-of-bounds access, escape, and exceptions; DEX write/read round trips; and a second run with no edits. Refactoring should compare output DEX files and key reports under identical configurations. Readability alone does not establish success.

Decompiled Java helps inspect residual obfuscation but may omit parentheses that affect floating-point rounding. Verify behavior against DEX execution order.

Frozen regression DEX files and descriptions belong in `src/test/resources`. Local experimental APKs, analysis scripts, device logs, and temporary output belong in ignored `tmp/`, outside source commits and distributions.
