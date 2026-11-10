# Development instructions

These instructions apply to AI agents developing Android Deobfuscator, including
adding deobfuscation rules, fixing transformations, and extending the engine.

## Project constraints

- Keep the project name **Android Deobfuscator** and the CLI executable name
  `deobfuscator`.
- Keep the product CLI-only unless the user explicitly requests otherwise.
- Keep CLI messages, help, errors, transformer metadata, and this file in English.
- Use Java 17 source compatibility, the existing single Gradle module, and the
  checked-in Gradle Wrapper. Follow the surrounding code style.
- Read the relevant implementation and [English extension guide](docs/extending.md)
  before changing architecture. Consult the [English configuration reference](docs/configuration.md)
  when changing options or defaults.
- Preserve existing transformer IDs, CLI aliases, and configuration compatibility
  unless the requested change requires otherwise.

## Code organization

Production packages are under `src/main/java/me/naptila/deobfuscator`.

- Put feature implementations in `transformers/np`, `transformers/strings`, or
  `transformers/cleanup`, according to their purpose.
- Keep reusable control-flow, data-flow, register, and instruction-editing logic
  in `dex`. Keep format-independent scheduling in `core`.
- Use `transform` for provider discovery and scheduling, `config` for typed
  configuration, and `app` for processing workflows.
- Keep concrete deobfuscation algorithms out of `cli`, `io`, and `report`.
- Reuse existing analysis and editing helpers before adding parallel machinery.
  Keep feature-specific helpers with their owning feature.

## Adding or changing a deobfuscation rule

1. Reproduce the behavior with a known input and explicit configuration. Inspect
   the actual instructions and report before changing the rule.
2. Identify a general instruction or data-flow pattern. Do not hardcode a sample's
   random class names, method names, offsets, or dispatcher keys.
3. Implement method transformations as `DexPass` classes. Keep features
   independently selectable and give new features stable, descriptive IDs.
4. Declare a `public static final class Provider` in the transformer file and
   register it in
   `src/main/resources/META-INF/services/me.naptila.deobfuscator.transform.TransformerProvider`.
   Create fresh transformer instances for each run.
5. Validate options through `TransformerOptions.requireOnly`, `bool`, and
   `strings`. Perform signature and other domain-specific checks in the provider.
6. Declare automatic cleanup through `TransformerProvider.cleanup(options)`.
   Reuse cleanup deduplication and explicit-configuration precedence. Put
   cross-method cleanup in the appropriate `DexFinalizer` phase.
7. Add a regression for the new behavior and relevant counterexamples. Update
   configuration examples and documentation when the public interface changes.
   Change the default pipeline only when the task calls for it.

## Transformation requirements

- Prove rewrite conditions from instruction semantics and data flow. Preserve
  unproven paths and provide useful diagnostics when a recognized case is skipped.
- Preserve business effects, class initialization, synchronization, and exception
  behavior. A known return value alone does not justify removing a call.
- Check register liveness on normal and exceptional successors. Handle both words
  of wide values and respect instruction register encoding limits.
- Preserve operation order, branch targets, try ranges, and ordered exception
  handlers. Use `Edits`, `ExceptionEdits`, and existing branch-relaxation helpers.
- Preserve integer overflow and floating-point semantics unless an explicit
  feature contract permits a behavior change.
- Treat `DexContext` and `MethodContext.originalGraph()` as original-input facts.
  Rebuild current-code graphs and data-flow analyses after mutation. Do not reuse
  stale instruction indexes.
- Preserve method transactions and rollback. Use committed
  `TransformationEvidence` and final references for definition removal; do not
  infer deletion eligibility from simplified code alone.
- Preserve APK resources and original class-to-DEX ownership when rewriting APKs.

## Verification

Tests use JUnit 4. Run the relevant test class while developing, for example:

```bash
./gradlew test --tests me.naptila.deobfuscator.DispatcherArithmeticTest
```

- For transformation changes, test both successful rewrites and cases that must
  remain unchanged. Cover relevant unknown values, side effects, exception paths,
  and register edge cases.
- Check DEX write/read round trips and idempotence where relevant. Use actual
  bytecode behavior to assess correctness; decompiled appearance is supporting
  evidence only.
- Run `./gradlew test` before handing off bytecode or engine changes.
- For CLI, dependency, or packaging changes, also run
  `./gradlew installDist distZip` and exercise the installed launcher at
  `build/install/deobfuscator/bin/deobfuscator`.
- When a change needs Android runtime verification, run suitable fixtures on ART
  and compare original and transformed behavior.
- For documentation-only edits, review the content and run `git diff --check`.

## Workspace and handoff

- Preserve original samples and unrelated working-tree changes.
- Keep local analysis scripts, APKs, generated DEX files, reports, and device logs
  in ignored `tmp/`. Keep local `samples/` inputs, build products, and caches out of
  source commits and distributions.
- Put deliberately selected regression fixtures in `src/test/resources/` and
  document their origin, configuration, and expected behavior.
- Inspect the diff and stage only files belonging to the requested change.
- At handoff, explain the behavior changed, the checks actually performed, and
  any unresolved development issues.
