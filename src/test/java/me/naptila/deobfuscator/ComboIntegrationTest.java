package me.naptila.deobfuscator;

import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class ComboIntegrationTest {
    private static final List<String> NAMES = List.of("string-instruction", "string-flower", "string-planar", "full-flower", "full-planar");
    private static final Map<String, DexFile> inputs = new LinkedHashMap<>();
    private static final Map<String, DexEngine.Result> results = new LinkedHashMap<>();
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    @BeforeClass public static void prepare() throws Exception {
        for (String name : NAMES) {
            DexFile input = DexFiles.read(Path.of(Objects.requireNonNull(ComboIntegrationTest.class.getResource("/np-combo/" + name + ".dex")).toURI()));
            inputs.put(name, input); results.put(name, transform(input));
        }
    }
    private static DexEngine.Result transform(DexFile input) {
        var result = new Deobfuscator(TransformerRegistry.discover()).transform(input, RunConfiguration.defaults().transformers(), 20);
        assertEquals(result.methods().stream().filter(DexEngine.MethodReport::rolledBack).toList().toString(), 0, result.failedMethods());
        assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged)); return result;
    }
    private static long switches(DexFile dex) {
        return new DexContext(dex).methods().values().stream().filter(m -> m.getImplementation() != null)
                .mapToLong(m -> { long n = 0; for (Instruction i : m.getImplementation().getInstructions()) if (CodeGraph.isSwitch(i.getOpcode())) n++; return n; }).sum();
    }
    @Test public void allAddedDispatchersDisappearAndAll485StringsAreRestored() {
        for (String name : NAMES) {
            assertEquals(name, 8, switches(results.get(name).dex()));
            assertEquals(name, 485, results.get(name).methods().stream().flatMap(m -> m.steps().stream())
                    .filter(s -> s.pass().equals("np.strings")).mapToLong(s -> s.result().edits()).sum());
        }
    }
    @Test public void unusedStringTablesAndTheirPureInitializersAreRemoved() {
        for (String name : NAMES) {
            DexContext before = new DexContext(inputs.get(name)), after = new DexContext(results.get(name).dex());
            Set<String> removed = new HashSet<>(before.fields().keySet()); removed.removeAll(after.fields().keySet());
            assertEquals(name, 16, removed.size());
            for (String field : removed) {
                assertEquals("[S", before.fields().get(field).getType());
                String owner = before.fields().get(field).getDefiningClass();
                assertFalse(after.findMethod(owner + "-><clinit>()V").isPresent());
                assertTrue(FieldReferences.collect(after, Set.of()).stream().noneMatch(ref -> FieldReferences.mayResolveTo(after, ref, before.fields().get(field))));
            }
            assertEquals(name, 32, results.get(name).dexEdits());
            assertTrue(after.findField("Ldev/deobfuscator/fixture/MainActivity$4;->short:[S").isPresent());
            assertTrue(after.findField("Ldev/deobfuscator/fixture/cases/ExceptionCases;->short:[S").isPresent());
        }
    }
    @Test public void remainingDecoderCallsAreProtectedAndBusinessLookalikesSurvive() throws Exception {
        DexFile original = DexFiles.read(Path.of(Objects.requireNonNull(getClass().getResource("/np-v2/original.dex")).toURI()));
        Set<String> business = new DexContext(original).classes().keySet();
        for (String name : NAMES) {
            int decoders = 0, lookalikes = 0, retainedReads = 0;
            for (Method method : new DexContext(results.get(name).dex()).methods().values()) {
                if (method.getImplementation() == null) continue;
                CodeGraph graph = new CodeGraph(method.getImplementation());
                for (int i = 0; i < graph.size(); i++) {
                    if (business.contains(method.getDefiningClass()) && graph.at(i).getOpcode() == org.jf.dexlib2.Opcode.SGET
                            && graph.at(i) instanceof ReferenceInstruction read && read.getReference() instanceof FieldReference field
                            && !business.contains(field.getDefiningClass())) {
                        retainedReads++; assertFalse(name + " " + Signatures.of(method), graph.protection(i).isEmpty());
                    }
                    if (graph.at(i) instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference call
                            && call.getParameterTypes().equals(List.of("[S", "I", "I", "I")) && call.getReturnType().equals("Ljava/lang/String;")) {
                        if (business.contains(call.getDefiningClass())) { lookalikes++; continue; }
                        decoders++; assertFalse(name + " " + Signatures.of(method), graph.protection(i).isEmpty());
                    }
                }
            }
            assertEquals(name, 4, decoders); assertEquals(name, 3, lookalikes);
            // Harmless initialization does not require retaining unused reads in try.
            assertEquals(name, 0, retainedReads);
        }
    }
    @Test public void encodedOutputsReloadAndASecondRunChangesNothing() throws Exception {
        for (String name : NAMES) {
            Path file = directory.getRoot().toPath().resolve(name + ".dex"); DexFiles.write(file, results.get(name).dex());
            var again = transform(DexFiles.read(file));
            assertEquals(name + ": " + again.methods().stream().filter(m -> m.edits() != 0).toList(), 0, again.changedMethods());
            assertEquals(name, 0, again.dexEdits());
        }
    }
    @Test public void optInClearsAllNpStringScaffoldingAndKeepsBusinessCatchCoverage() throws Exception {
        DexFile original = DexFiles.read(Path.of(Objects.requireNonNull(getClass().getResource("/np-v2/original.dex")).toURI()));
        Set<String> business = new DexContext(original).classes().keySet();
        var specs = RunConfiguration.defaults().transformers().stream().map(s -> s.id().equals("np.strings")
                ? new TransformerSpec(s.id(), new TransformerOptions(Map.of("removeProtectedStringCalls", true))) : s).toList();
        for (String name : NAMES) {
            var app = new Deobfuscator(TransformerRegistry.discover());
            var result = app.transform(inputs.get(name), specs, 20);
            assertEquals(0, result.failedMethods()); assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged));
            assertEquals(name, 36, result.dexEdits());
            DexContext output = new DexContext(result.dex()), conservative = new DexContext(results.get(name).dex());
            int remaining = 0;
            for (Method method : output.methods().values()) if (method.getImplementation() != null)
                for (Instruction i : method.getImplementation().getInstructions())
                    if (i instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference call
                            && call.getParameterTypes().equals(List.of("[S", "I", "I", "I")) && call.getReturnType().equals("Ljava/lang/String;")) {
                        remaining++; assertTrue("Only business lookalikes remain", business.contains(call.getDefiningClass()));
                    }
            assertEquals(name, 3, remaining);
            Set<String> helpers = new HashSet<>(output.classes().keySet()); helpers.removeAll(business);
            for (String signature : List.of("Ldev/deobfuscator/fixture/MainActivity$4;->run()V",
                    "Ldev/deobfuscator/fixture/cases/ExceptionCases;->finallyTrace(I)Ljava/lang/String;"))
                assertEquals(name + signature, businessCoverage(conservative.findMethod(signature).orElseThrow(), helpers),
                        businessCoverage(output.findMethod(signature).orElseThrow(), helpers));
            long protectedCalls = result.methods().stream().flatMap(m -> m.steps().stream()).flatMap(s -> s.result().notes().stream())
                    .filter(n -> n.startsWith("protected NP string calls removed: ")).mapToLong(n -> Long.parseLong(n.substring(n.lastIndexOf(' ') + 1))).sum();
            assertEquals(name, 4, protectedCalls);
            Path path = directory.getRoot().toPath().resolve("opt-in-" + name + ".dex"); DexFiles.write(path, result.dex());
            var again = app.transform(DexFiles.read(path), specs, 20);
            assertEquals(name, 0, again.changedMethods()); assertEquals(name, 0, again.dexEdits());
        }
    }
    private static Map<String, List<List<String>>> businessCoverage(Method method, Set<String> helpers) {
        CodeGraph graph = new CodeGraph(method.getImplementation()); Map<String, List<List<String>>> result = new TreeMap<>();
        for (int i = 0; i < graph.size(); i++)
            if (graph.at(i) instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference call
                    && !helpers.contains(call.getDefiningClass()))
                result.computeIfAbsent(Signatures.of(call), ignored -> new ArrayList<>()).add(graph.protection(i).stream().map(CodeGraph.Handler::type).toList());
        return result;
    }
    @Test public void foldedIntegerResultsAgreeWithOriginalObfuscatedCode() {
        String owner = "Ldev/deobfuscator/fixture/cases/ArithmeticEdges;->";
        int[] edges = {0, 1, -1, Integer.MIN_VALUE, Integer.MAX_VALUE, 0x55555555, 0xaaaaaaaa};
        for (String name : NAMES) {
            var before = new NpNumericInterpreter(inputs.get(name)); var after = new NpNumericInterpreter(results.get(name).dex());
            for (int a : edges) for (int b : edges) for (String op : List.of("add", "sub", "and", "or", "xor")) {
                String signature = owner + op + "(II)I";
                assertEquals(name + signature, before.run(signature, a, b), after.run(signature, a, b));
            }
            long[] wideEdges = {Long.MIN_VALUE, Long.MAX_VALUE, -1, 0, 1, 0x5555555555555555L};
            for (long a : wideEdges) for (long b : wideEdges) for (String op : List.of("add", "sub", "and", "or", "xor")) {
                long expected = switch(op) { case "add" -> a + b; case "sub" -> a - b; case "and" -> a & b; case "or" -> a | b; default -> a ^ b; };
                String signature = owner + op + "Long(JJ)J";
                assertEquals(name + signature, expected, before.run(signature, a, b));
                assertEquals(name + signature, expected, after.run(signature, a, b));
            }
        }
    }
}
