# Configuration

English | [简体中文](configuration.zh-CN.md)

Start with [config.example.yml](../config.example.yml). Each transformer accepts only its declared options. Unknown keys and incorrect types are rejected.

## General configuration

| Key | Meaning |
| --- | --- |
| `input` | APK or standalone DEX |
| `output` | New output file path; APK output is unsigned |
| `report` | Optional JSON report path |
| `dryRun` | Transform in memory without writing an APK/DEX; a report can still be written; default false |
| `maxRounds` | Maximum iteration rounds per method; default 20 |
| `transformers` | Ordered transformer list; omitted uses the default pipeline, an empty list disables all rules |

```yaml
input: input.apk
output: output.cleaned.apk
report: report.json
maxRounds: 20
transformers:
  - np.strings
  - np.opaque-predicates
  - np.dispatcher
```

Top-level file paths are relative to the YAML directory. CLI arguments override corresponding top-level values; `--transformers` replaces the transformer list and its per-transformer options. `classpath` is a transformer option resolved against the process working directory, so absolute paths are recommended. Output files, reports, and exported configurations do not overwrite existing files.

## NP options

Boolean options default to false, except `inlineProtected`, which defaults to true. Lists default to empty. Selecting an NP feature automatically adds shared cleanup once; method hiding also adds its own definition cleanup. Control-flow flattening, junk-code obfuscation, and opaque predicates remain independent features.

| Transformer | Option | Meaning |
| --- | --- | --- |
| `np.method-hiding` | `classpath` | Paths to Android/JAR member metadata; only class metadata is parsed |
| | `inlineProtected` | Restore verified proxies inside try blocks while preserving business exceptions from the original target operations |
| | `assumeClosedWorld` | Allow finalization to remove recorded public proxy definitions with no external entry points |
| | `keepMethods` | Exact DEX method signatures that definition cleanup must retain |
| `np.reflection` | `classpath` | Paths to Android/JAR member metadata |
| | `assumeStandardRuntime` | Restore recognized NP reflection-cache semantics; must be explicitly enabled for reflection restoration |
| | `assumeClosedWorld` | Inspect private string fields and verified accessors, removing cache wrappers when proven eligible |
| `np.strings` | `assumeClosedWorld` | Verify private short tables behind public guarded getters |
| | `assumeImmutableTables` | Exact field signatures of short tables confirmed immutable at runtime |
| | `removeProtectedStringCalls` | Allow cleanup to remove verified decryptor calls and related reads inside try blocks when their results are unused |
| `np.instructions` | `restoreFloatingPoint` | Algebraically restore expanded float/double addition and subtraction |

`np.numbers`, `np.opaque-predicates`, `np.dispatcher`, and `np.flower` accept no options.

`np.dispatcher` supports integer, object, and 64-bit register moves in switch default backedges and loop headers. It accepts bounded constant/copy loops only when the selector is proven unchanged across the loop. The selector register may be temporarily reused if restored from an unchanged backup. Recovered paths preserve live header assignments. Overwritten backups, unknown states, and default loops containing business operations or throwing instructions remain unchanged.

`np.flower` supports comparison chains that copy state into the other operand of a two-address XOR before jumping back. Integer, object, and 64-bit moves may appear between comparisons. Integer moves can copy the comparison state to other registers and back; tracking stops for an alias once overwritten. Recognition and path recovery each follow at most 128 instructions. Assignments along the path are preserved, and jumps are replaced only when the comparison is known. Unknown states, looping default paths, and paths whose exception handlers cannot be preserved remain unchanged.

Redundant and round-trip moves can be removed across jumps. Equality proofs recurse up to 64 steps, and removal requires both registers to be equal on every incoming edge. Register overwrites, relevant casts, exception entries, and unproven loops block removal. Both register words are checked for 64-bit values; explicit alias bindings after constructor initialization are retained.

In methods with direct NP evidence, an integer or object move can be delayed to a conditional successor when its destination is live only on that branch. This restores short-circuit conditions interrupted by early assignments. The rule runs after other shared cleanup stabilizes so it does not disrupt shared-region expansion. It checks at most 64 instructions along a single-entry path; the source must remain unchanged and the destination must not be observed or overwritten. Exception handlers, constructor initialization, joins, loops, monitors, and visible debug locals block motion. Ordinary calls and their effects stay in place, with labels, line numbers, and exception ranges attached to their original instructions. Wide moves are excluded. Each invocation moves at most 64 copies; methods exceeding 4096 instructions are skipped.

`np.instructions` also normalizes constructor object aliases. When registers in the same basic block are proven to come from one `new-instance`, and the constructor type matches, live aliases are rebound after successful construction. This avoids uninitialized SSA references when a decompiler merges constructor expressions. Other branch entries skip these bindings, and constructor exceptions retain their original handlers.

Repeated copies of the same `this` across constructor branches can be combined into one entry assignment when the incoming receiver is never overwritten, the alias has no other definitions, and the alias cannot be observed before assignment. This avoids SSA merges of uninitialized receivers. Both normal and exceptional liveness checks must pass.

Bitwise expansions starting with `not-int` can use integer masks proven across basic blocks to recover XOR from `(~x & k) | (x & ~k)`. Unknown masks and observed intermediate values block the corresponding replacement. Exception handlers inherit only constants left unchanged by the throwing instruction.

Integer offsets and paired negations can be recovered across single-entry goto edges, such as `(x - 8) + y + 8` and `-(-x - y)`. Register constants and intermediate moves are supported. Tracking is bounded to 64 instructions and preserves 32-bit overflow semantics. Reads and calls stay in place. Joins, loops, observed or live intermediate values, and rewritten values visible to exception handlers block the corresponding replacement.

Pure int/long arithmetic windows are also followed across single-entry gotos to recover split constant masks and identities such as `(~x) & x`, with limits of 12 pure instructions and 64 steps. Expressions are proven in execution order and edits are located by instruction identity, including cases where later operations appear earlier in the DEX layout. Branch labels, debug information, and exception metadata are updated with original instruction locations. Multiple entries, unknown operations, calls, throwing instructions, or observed intermediate values end the window.

Proven constant-string getters remain eligible for string restoration and shared cleanup even when defined in NP helper classes, allowing processing of decryptor calls exposed by proxy expansion. This exception applies only to getters proven constant by the model. Core hash helpers, integer guards, and decryptors accepting runtime parameters retain their existing helper protections. Call removal still requires decryption, access, initialization, and exception-path checks.

Shared cleanup removes verified hash-helper calls with known string arguments and unused results. Necessary first calls are retained for helper classes with static initializers. Once a static call or static field access on the same path has successfully initialized the class, redundant hashes can be removed, including calls inside try blocks. Joins require initialization on every incoming path; handlers inherit the state before the throwing instruction. `const-class` does not initialize a class. Calls with live results, unknown arguments, or unverified access remain. Reports distinguish removed calls from calls retained for initialization.

Shared cleanup can also remove unused, verified NP integer-field reads inside try blocks once the owning class is successfully initialized on every incoming path, preventing redundant reads from interrupting comparison-chain recovery. First reads, paths following failed initialization, conditional initialization, illegal access, volatile fields, and mutable fields do not become removable under this proof. The original first access still performs initialization effects. Reports use `redundant initialized NP field reads removed`; no separate cleanup module or protected-string cleanup option is needed.

If the owning class is proven to have no business initialization effects (no initializer, an empty initializer, or only construction of its own private final short table), unused stable integer reads can be removed inside try blocks even on first access. Reports use `unused harmless NP field reads removed`. Business initialization, illegal access, volatile or mutable fields, and live results remain protected. Shared boolean-constant blocks can be copied per entry within identical exception protection. Copies contain only integer constants and jumps; business calls and throwing instructions remain in place, avoiding JADX duplicate-region fallback after proxy expansion.

When a DEX contains a verified NP helper family, shared cleanup also normalizes jumps, shared short-circuit branches, and switch default edges in business methods without direct helper references, including default edges routed through gotos. NP optimization can affect only these layouts. These rules use control-flow proofs without authorizing removal of business calls or field reads. Shared regions count only reachable predecessors, excluding unreachable alignment NOPs as extra entries so copying and unreachable-code cleanup do not repeat indefinitely. Inputs without NP helper families keep the existing processing scope.

After state-machine expansion, a conditional left at the end of a method can be moved back to its original jump site if it has one direct entry and identical exception protection. Both branches and their register values are preserved. Shared conditions and exception entries stay in place; business calls are not duplicated.

Shared null-assignment prefixes that repeatedly test the same unchanged register can be expanded by incoming conditions. At most 24 assignments and tests are copied; business operations stay in place. Shared-region processing is limited to methods without try blocks and at most 1024 instructions.

Methods with direct NP evidence can split shared terminal paths, copying at most 256 instructions. All paths must return or throw, and no conditional may follow an internal join. Each execution path still performs each original business operation once. Copying does not cross try blocks, loops, or monitors, and the resulting method remains limited to 1024 instructions.

Shared array-initialization prefixes can be split by conditional incoming edges, supporting `new-array`, `filled-new-array`, and range encoding. The prefix may contain one array allocation, constants, copies, and jumps. Result instructions must remain paired with their creation instructions. Business calls, internal conditions, and loops are excluded. Only methods without try blocks or debug entries and at most 1024 instructions qualify. Allocation counts on each path remain unchanged.

Once other shared cleanup stabilizes, shared terminal paths with local constants can be specialized. Tracking is limited to 128 instructions; every subsequent condition must be determined by local constants, and at least one known condition must be eliminated. Calls, allocations, and other business operations are preserved individually; unknown calls invalidate constant facts for their results. Unknown conditions, loops, try blocks, monitors, payloads, or debug entries retain the original path. Code is not expanded merely to duplicate an ordinary call tail.

After copy motion stabilizes, 32-bit integer constants can also be delayed to the only conditional successor that needs them. Supported opcodes are `const/4`, `const/16`, `const`, and `const/high16`, preserving their original encoding. At most 64 instructions are checked along a single-entry path; the destination must not be read or overwritten early. Exception handlers, constructor initialization, joins, loops, monitors, and visible debug locals block motion. Throwing string/type constants and wide constants are excluded. Reports separately record `integer constants delayed to live conditional edges`.

Once other shared cleanup stabilizes, blocks in methods with direct NP evidence can be reordered in reverse postorder. Later iterations process optimization windows exposed by the layout. Normal and handler entries are traversed separately. Labels rebuild jumps and exception ranges, with checks on each original instruction's handler types, order, and corresponding entry points. Methods with debug entries or switch/array payloads retain their layout, as do methods exceeding 4096 instructions or 512 basic blocks. Convergence remains bounded by `maxRounds`. Class, field, and method declarations and DEX ownership are preserved.

Legacy explicit cleanup rules remain supported. `np.cleanup` accepts `assumeClosedWorld`, `assumeImmutableTables`, and `removeProtectedStringCalls`; `np.method-hiding.cleanup` accepts `assumeClosedWorld` and `keepMethods`. `dex.constant-switch` and `dex.unreachable` accept no options. Existing execution order and explicit cleanup options take precedence, and the same cleanup steps are not added again.

### Method hiding and reflection

```yaml
- id: np.method-hiding
  options:
    classpath: [/path/to/android.jar]
    inlineProtected: true
- id: np.reflection
  options:
    classpath: [/path/to/android.jar]
    assumeStandardRuntime: true
```

Proxy recognition verifies guards and the remaining body, restoring the member operations, literals, or argument forwarding that actually execute. Proxies remain when access, initialization, synchronization, or exception conditions are unknown. When `inlineProtected` skips a proxy guard, the guard's VM/linkage failure behavior is not guaranteed to remain identical.

Method hiding also recognizes NP proxy families by class structure: a public class directly extends `Object`, implements no interfaces, has one public static integer field and an optional private final short table, and has public static ordinary methods. Hash, integer-guard, and short-array decryptor semantics are verified, and a String-to-String helper must be present. Guards may read a field from another proxy class; class and method names do not participate in recognition. Existing semantic proofs handle helpers with additional initialization or control-flow obfuscation.

Short forwarders in these classes need no separate guard and can restore ordered operations such as table retrieval, field reads, and decryptor calls. Each method still needs a complete execution-path proof. Existing restrictions on unknown branches, recursion, synchronization, and protected calls remain. Matching the class does not establish purity of anti-string-decryption helpers or authorize removing business operations. Core hash, guard, and array-decryption calls remain owned by their respective features. Reports record class features and method proofs as `np.class-proxy.trace.v1`, reusing the same proxy cleanup.

When guards are wrapped by multiple proxy layers, the rule verifies their normal integer return values one layer at a time and uses them to select outer proxy paths. Wrapper calls remain to preserve initialization and exceptions. Known int operations are folded with 32-bit semantics; unknown operands and division by zero are not folded. Proxies with more arguments and casts can also be recognized, subject to DEX register and instruction encoding limits. Guard wrappers containing unknown business effects, cyclic dependencies, or unstable fields provide no constant facts.

Method-hiding restoration searches the first 256 registers for a contiguous free workspace, checking live values on normal paths and in exception handlers. Member-call arguments that cannot be encoded directly can be moved into consecutive registers for a range invocation. Instance-field operations may borrow free low registers; wide values occupy adjacent pairs. Insufficient space retains the proxy call and reports encoding or register limits.

`NP proxy calls retained (...)` distinguishes missing body proofs, explicitly disabled expansion inside try blocks, static initialization, member metadata/access, and encoding limits. Configure an `android.jar` matching the target platform for proxies involving Android members. Access checks still apply once metadata is available. `inlineProtected` defaults to true: verified proxies are not retained solely because the call is inside a try block. Expansion preserves original exception protection and checks register liveness in handlers. Set it to false to disable expansion inside try blocks. Counts are recorded per method per round; the same call may appear repeatedly, so summing them does not give the final residual count.

For verified NP proxy classes with an empty initializer, or one that only constructs and publishes the class's own private final short table, method hiding reuses the string rules' proof of no business effects to allow first-call expansion. Reports record `proxyInitialization=verified`; VM behavior such as table allocation failure may differ. Initializers with additional writes, business calls, exception handling, or unproven operations retain the first call. Later proxies can be restored after a successful static call or field access on the same path. Path proofs are shared with hash cleanup: joins require initialization on every incoming path, and failed-initialization exception paths do not acquire that fact.

Reflection runtime assumptions include successful target lookup, no additional business effects in the helper layer, and private caches not modified through JNI, reflection, or instrumentation. Unknown IDs, unknown receiver types, or escaping argument arrays retain checked fallback adapters. Business exceptions propagate through the original handlers.

String contents are initially exposed through `np$resolved$string` cache accessors. They can become literals when only string contents are observed. Returns, storage in fields or arrays, identity comparisons, and unknown consumers retain caching. `TextView.setText` may retain the object, so display usage alone does not justify removing the wrapper.

NP static integer guard fields without encoded initial values participate in constant proofs with DEX's default zero, subject to the same reachable-write checks as explicitly initialized fields. Initializers that change the field, unknown writes, and volatile fields still block the proof.

### Complete inputs and short tables

`assumeClosedWorld` declares that the input contains the complete application code needed for analysis, with no hidden observers of relevant entry points through external DEX files, dynamic loading, JNI, reflection, or framework configuration. Each feature reads this declaration independently. `np.strings` also passes it to its automatically scheduled shared cleanup, and `np.method-hiding` uses it for definition cleanup. Explicit cleanup rules in legacy configurations use their own options. Having multiple DEX files in an APK does not itself establish this condition.

`np.strings` first restores plaintext. Automatically scheduled cleanup then removes unused calls, and DEX finalization collects unreferenced, verified short tables. Business reads, writes, return escapes, metadata references, and unknown consumers block the corresponding proofs. Selecting only `np.strings` still runs this cleanup. Referenced or insufficiently proven tables remain.

`assumeClosedWorld: true` does not automatically make all short tables constant. JNI, reflection, or dynamic loading can still block static verification of public getters. A `private static final short[]` prevents field reassignment but does not make array elements immutable. `unproven NP string calls` means the decryptor is recognized but its array or slice arguments remain unproven. If those strings also compute control-flow state, their unresolved hash/switch dispatch remains as well.

String tables remain usable after verified `short[]` casts, and alias checks continue tracking writes through cast aliases. After a verified initializer publishes a static table, the original local array retains the same table identity, allowing reuse for decryption in `<clinit>`. Numeric-field verification also covers subsequently recognized NP helpers, still rejecting writes of different values and volatile fields. For public no-argument string getters, the rule can infer constant returns along verified paths and propagate them to callers, iterating up to eight rounds for nested getters. Original getter calls remain responsible for first initialization, business effects, and exceptions; this return-value proof does not authorize call removal.

Public static string proxies with parameters can propagate known tables and slice arguments, including `Object`-to-`short[]` casts and verified guards. Evaluation is bounded to eight call levels and 4096 steps. Unknown arguments, unstable guards, incompatible casts, and recursion cycles keep the result unknown. The original proxy still executes, and table mutability requirements are unchanged.

If a sample exposes an encrypted table that is confirmed unchanged at runtime, configure:

```yaml
- id: np.strings
  options:
    assumeImmutableTables:
      - 'Lexample/Strings;->table:[S'
```

This is an explicit assumption for exact fields; detected array writes still cause rejection. It does not relax array collection or public-proxy removal conditions.

### Floating-point recovery and protected calls

```yaml
- id: np.instructions
  options:
    restoreFloatingPoint: true
- id: np.strings
  options:
    removeProtectedStringCalls: true
```

Floating-point recovery algebraically simplifies negation through subtraction from zero, nested addition/subtraction, and constant cancellation within one basic block, preserving necessary conversions and field writes. It may match ordinary code and change rounding, signed zero, NaN, infinity, and addition association. For example, the fixture `testDoublePoint(0.1, 0.2)` changes from `0.8200000000000006` to `0.82`. Keep the default false when current floating-point behavior must remain intact. The removed experimental option `floatingPointClasses` is no longer accepted.

`removeProtectedStringCalls` removes only verified decryptor calls with valid arguments and unused results, plus related reads. Business calls and handlers remain. Allocation failures, linkage failures, and similar VM exception behavior are not guaranteed to remain identical. Reports record actual rewrites triggered by these options.

NP decryption records successfully decoded, proven-removable calls in the current method transaction for direct cleanup use. Records bind to instruction identity and move with instructions; old offsets are not used to match new calls. Rebuilding instructions or replacing calls invalidates records, which are verified again next round. `assumeImmutableTables` is also passed to cleanup so decryption and collection use consistent table facts. After call removal, unused array/string casts, table reads, and argument assignments are collected. `removeProtectedStringCalls` also handles decryptor calls exposed by method-hiding expansion. Helpers may have an empty `return-void` initializer. If `<clinit>` only constructs and publishes the class's own private final short table, its allocation behavior may be disregarded. Initializers with business calls, other superclasses, or externally published tables do not qualify.

### Proxy definition cleanup

```yaml
- id: np.method-hiding
  options:
    assumeClosedWorld: true
    keepMethods:
      - 'Lexample/Helper;->keep(I)I'
```

Cleanup consumes only restoration evidence committed in the current run, checking original fingerprints, final references, entry points, and dynamic-access risks. Public proxies are retained by default. Definition removal is skipped after method rollback or non-convergence. Running cleanup alone on an earlier output does not rediscover candidates, and does not remove helper classes or fields.

## General string models

```yaml
- id: strings.decrypt
  options:
    xorMethods:
      - 'Lexample/Crypto;->decode(Ljava/lang/String;I)Ljava/lang/String;'
    stringFogXorMethods:
      - 'Lexample/Fog;->decrypt(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;'
    # Remove decoded repeated calls only after confirming no per-call business effects.
    removeDecryptedCalls: false
```

`xorMethods` requires UTF-16 char XOR. `stringFogXorMethods` requires Base64 ciphertext and key, repeating byte XOR, and UTF-8 output. The configurator must verify these exact signatures; they cannot be applied to other algorithms. General models preserve original calls and replace only known return values. NP-specific rules separately verify helper bodies.

`removeDecryptedCalls: true` declares that configured decryptors have no per-call business effects. It allows removal of calls with valid arguments and restored or unused results, potentially changing allocation, linkage, and VM failure behavior. The default is false. Cleanup covers exact signatures in `xorMethods` / `stringFogXorMethods` and verified forwarding wrappers. Unknown arguments, invalid ciphertext, missing members, synchronized methods, inaccessible members, and unproven business effects block removal.

Decryption records call sites, leaf decryptors, and proxy dependencies for cleanup in the same run, without searching again near plaintext. Even the first valid call can be removed when initialization of the decryptor and its dependencies is proven free of business effects. Verification follows static methods, constructors, and instance methods with known targets, up to 64 methods and 8192 instructions, without executing target code. Initializers may contain only empty operations, private final primitive constant tables, and stateless objects created through empty constructors without finalizers. Superclasses and interfaces are checked too. Platform dependencies are limited to explicitly supported string, Base64, UTF-8, and array-copy operations. Business initialization, unknown library methods, and virtual calls with unknown targets block this first-call removal proof.

When initialization cannot be fully proven, the first valid, normally completed leaf-decryptor call on each path remains. A verified proxy's normal return can establish that its leaf decryptor completed. Calls with unknown arguments may return null early even on normal completion, so they do not establish successful decryption. Joins require a verified successful call to the same exact signature on every incoming path; handlers inherit facts from before the throwing instruction. Proxies additionally check effects, casts, field reads, and class initialization along the original path, retaining business calls. Call removal also collects unused argument assignments while keeping needed plaintext and business exception handling. Reports record `decrypted calls removed`, `proven decryptor proxy calls removed`, `decrypted calls removed with proven harmless dependency initialization`, and retention reasons.

`String` casts introduced by method-hiding expansion preserve proven string constants, allowing NP plaintext to feed subsequent StringFog decryption. Remaining decryptor calls do not necessarily mean unresolved results: a following `const-string` is the substituted known return value.

When hidden proxies remain because of try protection or first initialization, `strings.decrypt` can infer returns through static string-forwarding chains, including `Object` parameter casts and nested proxies with verified NP integer guards. Only public static methods reaching a configured decryptor signature are followed. Limits are 512 instructions per method, eight call levels, and 4096 steps per evaluation. Unknown conditions or decryptor arguments, recursion cycles, internal exception handlers, wide parameters, and synchronized methods prevent return substitution. Original proxy calls remain by default; cleanup removes only calls that separately pass effect and initialization checks.

A JADX decryptor statement with no result receiver may be an unused-result call retained for these behaviors. Rules replace only received return values; they do not insert unused plaintext that would be removed immediately.

When ciphertext or keys differ at a join but each incoming path can be decoded independently, plaintext is written on the corresponding paths, preserving argument correlations and original decryptor calls. At most eight incoming edges and 32 shared-prefix instructions are checked. Unknown inputs, different exception protection, inseparable control flow, or insufficient encodable scratch registers cause a skip. Reports record `branch string results restored (calls retained)`.

Exception paths inherit only local constants left unchanged by the throwing instruction. Ciphertext or keys reassigned inside catch blocks can be restored through the same per-entry proof while preserving the actual exceptional path selection.

In the default configuration, `strings.decrypt` has no algorithm signatures and does not rewrite strings. APKs combining NP and StringFog must satisfy NP table proofs and configure verified `stringFogXorMethods`. Enabling one layer alone does not remove the other encryption layer.

## Reports and scope

`methods` records per-method steps, skip reasons, rollback, and convergence. `dexSteps` / `dexEdits` record finalization changes. `methodEvidence` contains proxy candidates, committed replacements, and remove/retain decisions. An unchanged method may be unobfuscated or may lack sufficient proof for rewriting.

All root-level `classes*.dex` files in an APK are analyzed together and written back with original class ownership. Resource, Manifest, asset, and native-library contents are preserved. The ZIP is rebuilt and invalidated signatures are removed. Duplicate classes, mixed DEX versions, and output-limit violations are rejected. AAB, APKS, and split-APK sets are not merged.
