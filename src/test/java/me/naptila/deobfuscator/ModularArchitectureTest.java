package me.naptila.deobfuscator;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.cli.Main;
import me.naptila.deobfuscator.config.*;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.config.YamlConfiguration;
import me.naptila.deobfuscator.core.PassResult;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.transform.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.report.JsonReport;
import me.naptila.deobfuscator.transform.TransformerProvider;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.MethodImplementationBuilder;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.value.ImmutableIntEncodedValue;
import org.jf.dexlib2.writer.pool.DexPool;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class ModularArchitectureTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();

    @Test public void featuresOwnCleanupAndRetainLegacyExecutionAndReports() throws Exception {
        var registry = TransformerRegistry.discover();
        var legacy = List.of("np.method-hiding", "np.numbers", "np.instructions", "np.strings", "strings.decrypt",
                "np.opaque-predicates", "np.dispatcher", "np.flower", "dex.constant-switch", "dex.unreachable",
                "np.cleanup", "np.method-hiding.cleanup").stream().map(TransformerSpec::new).toList();
        var features = RunConfiguration.defaults().transformers();
        assertEquals(8, features.size());
        assertTrue(features.contains(new TransformerSpec("np.dispatcher")));
        assertTrue(features.contains(new TransformerSpec("np.flower")));
        assertEquals(legacy, registry.scheduled(features));
        assertEquals(legacy, registry.scheduled(legacy));
        assertTrue(registry.scheduled(List.of()).isEmpty());
        var app = new Deobfuscator(registry);
        for (String sample : List.of("/np-combo/full-flower.dex", "/np-combo/full-planar.dex")) {
            var input = DexFiles.read(Path.of(getClass().getResource(sample).toURI()));
            var automatic = app.transform(input, features, 20);
            var explicit = app.transform(input, legacy, 20);
            String name = Path.of(sample).getFileName().toString();
            Path a = directory.getRoot().toPath().resolve("automatic-" + name);
            Path b = directory.getRoot().toPath().resolve("explicit-" + name);
            DexFiles.write(a, automatic.dex()); DexFiles.write(b, explicit.dex());
            assertArrayEquals(Files.readAllBytes(b), Files.readAllBytes(a));
            assertEquals(JsonReport.write(explicit, false), JsonReport.write(automatic, false));
        }
    }

    @Test public void cleanupIsSharedAndExplicitLegacyOptionsTakePrecedence() {
        var registry = TransformerRegistry.discover();
        var strings = new TransformerSpec("np.strings", new TransformerOptions(Map.of("removeProtectedStringCalls", true)));
        var automatic = registry.scheduled(List.of(new TransformerSpec("np.numbers"), strings));
        assertEquals(1, automatic.stream().filter(s -> s.id().equals("np.cleanup")).count());
        assertTrue(automatic.stream().filter(s -> s.id().equals("np.cleanup")).findFirst().orElseThrow().options().bool("removeProtectedStringCalls"));
        var explicit = new TransformerSpec("np.cleanup", new TransformerOptions(Map.of("removeProtectedStringCalls", false)));
        var scheduled = registry.scheduled(List.of(strings, explicit));
        assertEquals(explicit, scheduled.get(1));
        assertEquals(1, scheduled.stream().filter(s -> s.id().equals("np.cleanup")).count());
        assertThrows(IllegalArgumentException.class, () -> registry.create(List.of(new TransformerSpec("np.strings",
                new TransformerOptions(Map.of("removeProtectedStringCalls", "true"))))));
    }

    /** Loaded only through test resources, exercising the same SPI as an external plugin. */
    public static final class ExampleProvider implements TransformerProvider {
        public String id() { return "test.constant"; }
        public String description() { return "Test configurable transformer"; }
        public DexPass create(TransformerOptions options) {
            options.requireOnly("value", "failPrepare");
            int value = (Integer) options.values().getOrDefault("value", 42);
            boolean fail = (Boolean) options.values().getOrDefault("failPrepare", false);
            return new DexPass() {
                private boolean prepared;
                public String id() { return "test.constant"; }
                public void prepare(DexContext context) {
                    if (prepared) throw new IllegalStateException("Transformer instance reused across runs");
                    prepared = true;
                    if (fail) throw new IllegalStateException("Preparation failed");
                }
                public PassResult run(MethodContext context) {
                    if (!prepared) throw new IllegalStateException("Missing preparation");
                    Instruction first = context.code().getInstructions().get(0);
                    if (first.getOpcode() != Opcode.CONST) return PassResult.unchanged();
                    if (((NarrowLiteralInstruction) first).getNarrowLiteral() == value) return PassResult.unchanged();
                    context.code().replaceInstruction(0, new BuilderInstruction31i(Opcode.CONST, 0, value));
                    return PassResult.changed(1);
                }
            };
        }
    }
    public static final class NoopProvider implements TransformerProvider {
        public String id() { return "test.noop"; }
        public String description() { return "Test ordered no-op transformer"; }
        public DexPass create(TransformerOptions options) {
            options.requireOnly();
            return new DexPass() {
                public String id() { return "test.noop"; }
                public PassResult run(MethodContext context) { return PassResult.unchanged(); }
            };
        }
    }

    private Method constant(String name, int value) {
        MethodImplementationBuilder b = new MethodImplementationBuilder(1);
        Fixtures.integer(b, 0, value);
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        return Fixtures.method(name, List.of(), "I", b.getMethodImplementation());
    }
    private int cli(String... args) {
        PrintStream log = new PrintStream(new ByteArrayOutputStream());
        return Main.run(args, log, log);
    }
    private boolean hasPlaintext(Method method) {
        for (Instruction instruction : method.getImplementation().getInstructions())
            if (instruction.getOpcode() == Opcode.CONST_STRING_JUMBO) return true;
        return false;
    }

    @Test public void spiSupportsConfiguredProvidersFreshInstancesAndExecutionOrder() {
        TransformerRegistry registry = TransformerRegistry.discover();
        assertTrue(registry.providers().stream().anyMatch(p -> p.id().equals("test.constant")));
        assertTrue(registry.providers().stream().anyMatch(p -> p.id().equals("test.noop")));
        assertFalse(RunConfiguration.defaults().transformers().stream().anyMatch(s -> s.id().startsWith("test.")));
        Deobfuscator app = new Deobfuscator(registry);
        var specs = List.of(new TransformerSpec("test.constant", new TransformerOptions(Map.of("value", 123))),
                new TransformerSpec("test.noop"));
        for (int run = 0; run < 2; run++) {
            var result = app.transform(Fixtures.dex(constant("value", 1)), specs, 5);
            assertEquals(0, result.failedMethods());
            assertEquals(123, Fixtures.execute(Fixtures.first(result.dex()), 0));
            assertEquals(List.of("test.constant", "test.noop", "test.constant", "test.noop"),
                    result.methods().get(0).steps().stream().map(step -> step.pass()).toList());
        }
    }

    @Test public void registryRejectsUnknownDuplicateAndMistypedOptions() {
        var registry = TransformerRegistry.discover();
        assertThrows(IllegalArgumentException.class, () -> registry.create(List.of(new TransformerSpec("typo"))));
        assertThrows(IllegalArgumentException.class, () -> registry.create(List.of(new TransformerSpec("test.noop"), new TransformerSpec("test.noop"))));
        assertThrows(IllegalArgumentException.class, () -> new TransformerRegistry(List.of(new ExampleProvider(), new ExampleProvider())));
        assertThrows(IllegalArgumentException.class, () -> registry.create(List.of(new TransformerSpec("strings.decrypt",
                new TransformerOptions(Map.of("xorMethod", List.of(Fixtures.DECODE)))))));
        assertThrows(IllegalArgumentException.class, () -> registry.create(List.of(new TransformerSpec("strings.decrypt",
                new TransformerOptions(Map.of("xorMethods", Fixtures.DECODE))))));
        assertThrows(IllegalArgumentException.class, () -> registry.create(List.of(new TransformerSpec("np.cleanup",
                new TransformerOptions(Map.of("removeProtectedStringCalls", "true"))))));
    }

    @Test public void dexSnapshotIncludesCrossClassFieldsAndRemainsOriginalOnRollback() {
        Method original = constant("first", 7), second = constant("second", 8);
        Field field = new ImmutableField("Lsample/Helper;", "key", "I", AccessFlags.STATIC.getValue(),
                new ImmutableIntEncodedValue(73), Set.of(), Set.of());
        ClassDef helper = new ImmutableClassDef("Lsample/Helper;", 1, "Ljava/lang/Object;", List.of(), null,
                Set.of(), List.of(field), List.of());
        DexFile input = new ImmutableDexFile(Opcodes.forApi(28), List.of(Fixtures.dex(original, second).getClasses().iterator().next(), helper));
        int[] prepared = {0};
        DexPass pass = new DexPass() {
            private DexContext snapshot;
            public String id() { return "test.snapshot"; }
            public void prepare(DexContext context) {
                prepared[0]++;
                snapshot = context;
                assertEquals(2, context.classes().size());
                assertTrue(context.findField("Lsample/Helper;->key:I").isPresent());
                assertThrows(UnsupportedOperationException.class, () -> context.classes().clear());
            }
            public PassResult run(MethodContext context) {
                assertSame(snapshot, context.dex());
                assertEquals(7, Fixtures.execute(snapshot.findMethod(Signatures.of(original)).orElseThrow(), 0));
                if (context.original().getName().equals("first")) {
                    context.code().replaceInstruction(0, new BuilderInstruction31i(Opcode.CONST, 0, 99));
                    throw new IllegalStateException("Rollback this method");
                }
                assertEquals(8, Fixtures.execute(context.finish(), 0));
                return PassResult.unchanged();
            }
        };
        var result = new DexEngine(List.of(pass), 5).transform(input);
        assertEquals(1, prepared[0]);
        assertEquals(1, result.failedMethods());
        assertEquals(2, result.methods().size());
        assertEquals(7, Fixtures.execute(new DexContext(result.dex()).findMethod(Signatures.of(original)).orElseThrow(), 0));
    }

    @Test public void originalGraphRemainsIndependentOfTransactionEditsAndRegisterGrowth() {
        Method method = constant("original", 7);
        var context = new MethodContext(method);
        CodeGraph original = context.originalGraph();
        assertSame(original, context.originalGraph());
        context.code().replaceInstruction(0, new BuilderInstruction31i(Opcode.CONST, 0, 99));
        assertEquals(99, Fixtures.execute(context.finish(), 0));
        assertEquals(7, ((org.jf.dexlib2.iface.instruction.NarrowLiteralInstruction) original.at(0)).getNarrowLiteral());
        context.appendScratchRegisters(2);
        var replacement = new org.jf.dexlib2.builder.MutableMethodImplementation(context.finish().getImplementation());
        replacement.replaceInstruction(0, new BuilderInstruction31i(Opcode.CONST, 0, 123));
        context.replaceCode(replacement);
        assertSame(original, context.originalGraph());
        assertEquals(1, original.registers());
        assertEquals(3, context.graph().registers());
        assertEquals(123, Fixtures.execute(context.finish(), 0));
        assertEquals(Signatures.of(method), context.name());
    }

    @Test public void yamlDrivesStringDecoderAndResolvesPathsRelativeToConfig() throws Exception {
        Path root = directory.newFolder("nested").toPath();
        DexPool.writeTo(root.resolve("input.dex").toString(), Fixtures.dex(Fixtures.encryptedString(false)));
        Path config = root.resolve("config.yml");
        Files.writeString(config, """
                input: input.dex
                output: output.dex
                report: report.json
                maxRounds: 5
                transformers:
                  - id: strings.decrypt
                    options:
                      xorMethods:
                        - '%s'
                  - dex.unreachable
                """.formatted(Fixtures.DECODE));
        assertEquals(0, cli("--config", config.toString()));
        Method restored = Fixtures.first(DexFileFactory.loadDexFile(root.resolve("output.dex").toFile(), null));
        assertEquals("中文🙂 secret", Fixtures.execute(restored, 0));
        assertTrue(hasPlaintext(restored));
        assertTrue(Files.readString(root.resolve("report.json")).contains("\"changedMethods\": 1"));
    }

    @Test public void cliOverridesYamlAndLegacyXorFlagStillWorks() throws Exception {
        Path root = directory.getRoot().toPath();
        Path input = root.resolve("input.dex"), output = root.resolve("output.dex"), config = root.resolve("config.yml");
        DexPool.writeTo(input.toString(), Fixtures.dex(Fixtures.encryptedString(false)));
        Files.writeString(config, "input: missing.dex\noutput: unused.dex\ntransformers: [test.noop]\n");
        assertEquals(0, cli("--config", config.toString(), "--input", input.toString(), "--output", output.toString(),
                "--passes", "strings.decrypt", "--xor-method", Fixtures.DECODE));
        Method restored = Fixtures.first(DexFileFactory.loadDexFile(output.toFile(), null));
        assertTrue(hasPlaintext(restored));
        assertFalse(Files.exists(root.resolve("unused.dex")));
        assertEquals(1, cli("--input", input.toString(), "--dry-run", "--transformers", "dex.unreachable", "--xor-method", Fixtures.DECODE));
    }

    @Test public void malformedYamlFailsInsteadOfSilentlyIgnoringConfiguration() throws Exception {
        Path config = directory.getRoot().toPath().resolve("bad.yml");
        for (String text : List.of("maxRound: 2", "maxRounds: 2\nmaxRounds: 3", "maxRounds: 1.5", "maxRounds: 0",
                "dryRun: perhaps", "transformers: strings.decrypt", "transformers: [null]", "transformers: [{id: test.noop, typo: true}]",
                "transformers: [{id: strings.decrypt, options: null}]", "input: !!java.net.URL ['https://example.com']")) {
            Files.writeString(config, text);
            assertThrows(text, RuntimeException.class, () -> YamlConfiguration.read(config));
        }
    }

    @Test public void preparationFailureWritesNeitherDexNorReport() throws Exception {
        Path root = directory.getRoot().toPath(), config = root.resolve("config.yml");
        DexPool.writeTo(root.resolve("input.dex").toString(), Fixtures.dex(constant("value", 1)));
        Files.writeString(config, """
                input: input.dex
                output: output.dex
                report: report.json
                transformers:
                  - id: test.constant
                    options: {failPrepare: true}
                """);
        assertEquals(1, cli("--config", config.toString()));
        assertFalse(Files.exists(root.resolve("output.dex")));
        assertFalse(Files.exists(root.resolve("report.json")));
    }

    @Test public void finalizersRunOnceAfterAllMethodsInConfigurationOrder() {
        List<String> events = new ArrayList<>();
        class FinalPass implements DexPass, DexFinalizer {
            private final String name;
            FinalPass(String name) { this.name = name; }
            public String id() { return name; }
            public PassResult run(MethodContext method) { events.add(name + ":" + method.original().getName()); return PassResult.unchanged(); }
            public DexFinalizer.Result finish(DexContext original, DexFile rewritten) {
                assertEquals(2, new DexContext(rewritten).methods().size());
                events.add(name + ":finish"); return new DexFinalizer.Result(rewritten, PassResult.unchanged());
            }
        }
        var result = new DexEngine(List.of(new FinalPass("a"), new FinalPass("b")), 5)
                .transform(Fixtures.dex(constant("first", 7), constant("second", 8)));
        assertEquals(List.of("a:first", "b:first", "a:second", "b:second", "a:finish", "b:finish"), events);
        assertEquals(List.of("a", "b"), result.dexSteps().stream().map(DexEngine.DexStep::pass).toList());
    }

    @Test public void incompleteMethodsSkipFinalizationAndFinalizerErrorsAbort() {
        class FinalPass implements DexPass, DexFinalizer {
            final boolean failMethod; boolean finished;
            FinalPass(boolean failMethod) { this.failMethod = failMethod; }
            public String id() { return "test.finalizer"; }
            public PassResult run(MethodContext method) {
                if (failMethod) throw new IllegalStateException("method failed");
                return PassResult.unchanged();
            }
            public DexFinalizer.Result finish(DexContext original, DexFile rewritten) {
                finished = true; throw new IllegalStateException("finalizer failed");
            }
        }
        DexFile input = Fixtures.dex(constant("first", 7));
        var rollback = new FinalPass(true); var result = new DexEngine(List.of(rollback), 5).transform(input);
        assertEquals(1, result.failedMethods()); assertFalse(rollback.finished);
        assertTrue(result.dexSteps().get(0).result().notes().get(0).contains("incomplete method transactions"));
        var failure = new FinalPass(false);
        var error = assertThrows(IllegalStateException.class, () -> new DexEngine(List.of(failure), 5).transform(input));
        assertTrue(error.getMessage().contains("Finalization failed in test.finalizer")); assertTrue(failure.finished);
    }
}
