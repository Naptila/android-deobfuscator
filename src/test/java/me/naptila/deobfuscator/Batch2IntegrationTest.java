package me.naptila.deobfuscator;

import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import me.naptila.deobfuscator.transformers.np.analysis.NpAnalysis;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.instruction.ImmutableInstruction;
import org.jf.dexlib2.immutable.reference.ImmutableMethodReference;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class Batch2IntegrationTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private static final Map<String, DexFile> inputs = new HashMap<>();
    private static final Map<String, DexEngine.Result> results = new HashMap<>();
    @BeforeClass public static void prepare() throws Exception {
        for (String name : List.of("original", "opt", "instruction", "flower", "string", "string-antidecrypt")) {
            DexFile input = DexFiles.read(Path.of(Objects.requireNonNull(Batch2IntegrationTest.class.getResource("/np-v2/" + name + ".dex")).toURI()));
            inputs.put(name, input); results.put(name, transform(input));
        }
    }
    private static DexEngine.Result transform(DexFile input, String... ids) {
        var specs = ids.length == 0 ? RunConfiguration.defaults().transformers() : Arrays.stream(ids).map(TransformerSpec::new).toList();
        var result = new Deobfuscator(TransformerRegistry.discover()).transform(input, specs, 20);
        assertEquals(result.methods().stream().filter(DexEngine.MethodReport::rolledBack).toList().toString(), 0, result.failedMethods());
        assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged)); return result;
    }
    private long edits(String sample, String pass) {
        return results.get(sample).methods().stream().flatMap(m -> m.steps().stream()).filter(s -> s.pass().equals(pass)).mapToLong(s -> s.result().edits()).sum();
    }
    private long switches(DexFile dex) {
        long count = 0;
        for (ClassDef c : dex.getClasses()) for (Method m : c.getMethods()) if (m.getImplementation() != null)
            for (Instruction i : m.getImplementation().getInstructions()) if (CodeGraph.isSwitch(i.getOpcode())) count++;
        return count;
    }
    @Test public void removesAll276FlowerDispatchersButKeepsEightBusinessSwitches() {
        assertEquals(8, switches(inputs.get("opt"))); assertEquals(284, switches(inputs.get("flower")));
        assertEquals(8, switches(results.get("flower").dex())); assertTrue(edits("flower", "np.flower") > 0);
        assertEquals(0, results.get("original").changedMethods());
        // This source method intentionally uses value -= -delta; the same exact
        // two-instruction identity now simplifies it in NP inputs as well.
        assertEquals(List.of("Ldev/deobfuscator/fixture/cases/ObjectCases$Counter;->add(I)I"),
                results.get("opt").methods().stream().filter(m -> m.steps().stream().anyMatch(s -> s.pass().equals("np.instructions") && s.result().edits() > 0))
                        .map(DexEngine.MethodReport::method).toList());
    }
    @Test public void allRealStringsAreDecodedInBothStringSamples() {
        assertEquals(485, edits("string", "np.strings")); assertEquals(485, edits("string-antidecrypt", "np.strings"));
        assertEquals(60, edits("string-antidecrypt", "np.opaque-predicates"));
    }
    @Test public void decodedCallsAreRemovedExceptFourProtectedSites() {
        Set<String> originalClasses = new DexContext(inputs.get("original")).classes().keySet();
        for (String name : List.of("string", "string-antidecrypt")) {
            int remaining = 0;
            for (Method method : new DexContext(results.get(name).dex()).methods().values()) {
                if (method.getImplementation() == null) continue;
                CodeGraph graph = new CodeGraph(method.getImplementation());
                for (int i = 0; i < graph.size(); i++)
                    if (graph.at(i) instanceof ReferenceInstruction r && r.getReference() instanceof MethodReference call
                            && !originalClasses.contains(call.getDefiningClass())
                            && call.getParameterTypes().equals(List.of("[S", "I", "I", "I"))
                            && call.getReturnType().equals("Ljava/lang/String;")) {
                        remaining++;
                        assertFalse(Signatures.of(method), graph.protection(i).isEmpty());
                    }
            }
            assertEquals(name, 4, remaining);
            long removed = results.get(name).methods().stream().flatMap(m -> m.steps().stream())
                    .flatMap(s -> s.result().notes().stream())
                    .filter(n -> n.startsWith("unused proven NP string calls removed: "))
                    .mapToLong(n -> Long.parseLong(n.substring(n.lastIndexOf(' ') + 1))).sum();
            assertEquals(name, 481, removed);
        }
    }
    @Test public void singletonStringTableRejectsInvalidIndexAndOverlappingRegisters() {
        DexFile input = inputs.get("string-antidecrypt");
        int tables = NpAnalysis.of(new DexContext(input)).shortArrays();
        String owner = "Ldev/deobfuscator/fixture/cases/ObjectCases;";
        for (boolean badIndex : List.of(true, false)) {
            List<ClassDef> classes = new ArrayList<>();
            for (ClassDef cls : input.getClasses()) {
                if (!cls.getType().equals(owner)) { classes.add(cls); continue; }
                List<Method> methods = new ArrayList<>();
                for (Method method : cls.getMethods()) {
                    if (!method.getName().equals("<clinit>")) { methods.add(method); continue; }
                    MethodContext context = new MethodContext(method);
                    if (badIndex) context.code().replaceInstruction(2, new BuilderInstruction11n(Opcode.CONST_4, 1, 1));
                    else {
                        context.code().replaceInstruction(3, new BuilderInstruction21s(Opcode.CONST_16, 1, 0xb33));
                        context.code().replaceInstruction(4, new BuilderInstruction23x(Opcode.APUT_SHORT, 1, 0, 1));
                    }
                    methods.add(context.finish());
                }
                classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(),
                        cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
            }
            DexFile mutated = new ImmutableDexFile(input.getOpcodes(), classes);
            assertEquals(tables - 1, NpAnalysis.of(new DexContext(mutated)).shortArrays());
            long restored = transform(mutated).methods().stream().flatMap(m -> m.steps().stream())
                    .filter(s -> s.pass().equals("np.strings")).mapToLong(s -> s.result().edits()).sum();
            assertEquals(484, restored);
        }
    }
    @Test public void integerExpansionsMatchIndependentJavaFormulasIncludingOverflow() {
        var original = new NpNumericInterpreter(inputs.get("instruction"));
        var output = new NpNumericInterpreter(results.get("instruction").dex());
        assertTrue(edits("instruction", "np.instructions") >= 12);
        String owner = "Ldev/deobfuscator/fixture/cases/ArithmeticEdges;->";
        Random random = new Random(0x4e505f5632L);
        long[] edges = {Long.MIN_VALUE, Long.MAX_VALUE, Integer.MIN_VALUE, Integer.MAX_VALUE, -1, 0, 1, 2, 0x5555555555555555L};
        for (int n = 0; n < 256; n++) {
            long a = n < edges.length * edges.length ? edges[n / edges.length] : random.nextLong();
            long b = n < edges.length * edges.length ? edges[n % edges.length] : random.nextLong();
            for (String op : List.of("add", "sub", "and", "or", "xor")) {
                int x = (int)a, y = (int)b;
                int expectedInt = switch(op) { case "add" -> x + y; case "sub" -> x - y; case "and" -> x & y; case "or" -> x | y; default -> x ^ y; };
                long expectedLong = switch(op) { case "add" -> a + b; case "sub" -> a - b; case "and" -> a & b; case "or" -> a | b; default -> a ^ b; };
                for (NpNumericInterpreter interpreter : List.of(original, output)) {
                    assertEquals(expectedInt, interpreter.run(owner + op + "(II)I", x, y));
                    assertEquals(expectedLong, interpreter.run(owner + op + "Long(JJ)J", a, b));
                }
            }
            for (NpNumericInterpreter interpreter : List.of(original, output)) {
                assertEquals((a * 3) ^ 0x1020304050607080L, interpreter.run(
                        "Ldev/deobfuscator/fixture/cases/ArithmeticCases;->wide(J)J", a));
                assertEquals((int)a + 1, interpreter.run(owner + "increment(I)I", (int)a));
                assertEquals((int)a - 1, interpreter.run(owner + "decrement(I)I", (int)a));
            }
        }
    }
    @Test public void preservesDoubleInstructionsExactly() {
        String signature = "Ldev/deobfuscator/fixture/cases/ArithmeticCases;->floating(D)D";
        Method before = new DexContext(inputs.get("instruction")).findMethod(signature).orElseThrow();
        Method after = new DexContext(results.get("instruction").dex()).findMethod(signature).orElseThrow();
        List<ImmutableInstruction> a = new ArrayList<>(), b = new ArrayList<>();
        before.getImplementation().getInstructions().forEach(i -> a.add(ImmutableInstruction.of(i)));
        after.getImplementation().getInstructions().forEach(i -> b.add(ImmutableInstruction.of(i)));
        // dexlib instructions use identity equality: compare opcodes and encoded wide constants explicitly.
        assertEquals(a.size(), b.size());
        for (int i = 0; i < a.size(); i++) {
            assertEquals(a.get(i).getOpcode(), b.get(i).getOpcode());
            if (a.get(i) instanceof WideLiteralInstruction v) assertEquals(v.getWideLiteral(), ((WideLiteralInstruction)b.get(i)).getWideLiteral());
            if (a.get(i) instanceof OneRegisterInstruction v) assertEquals(v.getRegisterA(), ((OneRegisterInstruction)b.get(i)).getRegisterA());
            if (a.get(i) instanceof TwoRegisterInstruction v) assertEquals(v.getRegisterB(), ((TwoRegisterInstruction)b.get(i)).getRegisterB());
        }
    }
    @Test public void everyOutputReloadsAndIsIdempotent() throws Exception {
        for (String name : List.of("instruction", "flower", "string", "string-antidecrypt")) {
            Path output = directory.getRoot().toPath().resolve(name + ".dex"); DexFiles.write(output, results.get(name).dex());
            assertEquals(name, 0, transform(DexFiles.read(output)).changedMethods());
        }
    }
    private DexFile with(Method method) {
        List<ClassDef> classes = new ArrayList<>(inputs.get("opt").getClasses());
        classes.add(Fixtures.dex(method).getClasses().iterator().next());
        return new ImmutableDexFile(inputs.get("opt").getOpcodes(), classes);
    }
    @Test public void instructionRecoveryKeepsLiveIntermediateOutputs() {
        var b = new MethodImplementationBuilder(4);
        b.addInstruction(new BuilderInstruction23x(Opcode.XOR_INT, 0, 2, 3));
        b.addInstruction(new BuilderInstruction23x(Opcode.AND_INT, 1, 2, 3));
        b.addInstruction(new BuilderInstruction12x(Opcode.OR_INT_2ADDR, 0, 1));
        b.addInstruction(new BuilderInstruction12x(Opcode.ADD_INT_2ADDR, 0, 1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        Method method = Fixtures.method("live", List.of(new ImmutableMethodParameter("I", Set.of(), "x"), new ImmutableMethodParameter("I", Set.of(), "y")), "I", b.getMethodImplementation());
        DexFile input = with(method); var result = transform(input, "np.instructions");
        assertTrue(result.methods().stream().filter(m -> m.method().equals(Signatures.of(method)))
                .flatMap(m -> m.steps().stream()).allMatch(s -> s.result().edits() == 0));
        var interpreter = new NpNumericInterpreter(result.dex());
        for (int x : new int[]{0, -1, Integer.MIN_VALUE, 7}) for (int y : new int[]{1, -3, Integer.MAX_VALUE})
            assertEquals((x | y) + (x & y), interpreter.run(Signatures.of(method), x, y));
    }
    @Test public void instructionRecoveryDoesNotCrossAnInteriorBranchTarget() {
        var b = new MethodImplementationBuilder(2); Fixtures.integer(b, 0, 5);
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 1, b.getLabel("middle")));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 1, 11));
        b.addLabel("middle"); b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, 1));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, -11)); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        Method method = Fixtures.method("branch", List.of(new ImmutableMethodParameter("I", Set.of(), "x")), "I", b.getMethodImplementation());
        assertTrue(transform(with(method), "np.instructions").methods().stream()
                .filter(m -> m.method().equals(Signatures.of(method))).flatMap(m -> m.steps().stream())
                .allMatch(s -> s.result().edits() == 0));
    }
    @Test public void exceptionConstantsMergeOnlyUnchangedLocalsAndKillDestination() {
        var b = new MethodImplementationBuilder(6); Fixtures.integer(b, 0, 42); Fixtures.integer(b, 4, 73); Fixtures.integer(b, 5, 9);
        b.addLabel("start"); b.addInstruction(new BuilderInstruction23x(Opcode.DIV_INT, 0, 0, 5));
        Fixtures.integer(b, 4, 74);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Lsample/Unknown;", "call", List.of(), "V")));
        b.addLabel("end"); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        b.addLabel("catch"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 2)); b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        b.addCatch(b.getLabel("start"), b.getLabel("end"), b.getLabel("catch"));
        CodeGraph graph = new CodeGraph(b.getMethodImplementation());
        ConstantAnalysis facts = new ConstantAnalysis(graph, ConstantEvaluator::step, false, true);
        int target = graph.index(b.getMethodImplementation().getTryBlocks().get(0).getExceptionHandlers().get(0).getHandlerCodeAddress());
        assertEquals(9, facts.before(target).get(5)); assertNull(facts.before(target).get(4)); assertNull(facts.before(target).get(0));
    }
}
