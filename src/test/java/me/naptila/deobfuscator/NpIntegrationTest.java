package me.naptila.deobfuscator;

import java.nio.file.*;
import java.util.*;
import java.util.function.UnaryOperator;
import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import me.naptila.deobfuscator.transformers.np.analysis.NpAnalysis;
import me.naptila.deobfuscator.transformers.np.numbers.NumberTransformer;
import me.naptila.deobfuscator.transformers.np.strings.StringTransformer;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class NpIntegrationTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private static final String STRING_CLASS = "Ldev/deobfuscator/fixture/cases/StringCases;";
    private static final String LITERAL = STRING_CLASS + "->encryptedLiteral()Ljava/lang/String;";
    private DexFile sample(String name) throws Exception {
        return DexFileFactory.loadDexFile(Path.of(Objects.requireNonNull(getClass().getResource("/np/" + name + ".dex")).toURI()).toFile(), null);
    }
    private DexEngine.Result transform(DexFile input, String... ids) {
        var specs = ids.length == 0 ? RunConfiguration.defaults().transformers() : Arrays.stream(ids).map(TransformerSpec::new).toList();
        var result = new Deobfuscator(TransformerRegistry.discover()).transform(input, specs, 20);
        assertEquals(result.methods().stream().filter(DexEngine.MethodReport::rolledBack).toList().toString(), 0, result.failedMethods());
        assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged));
        return result;
    }
    private long edits(DexEngine.Result result, String id) {
        return result.methods().stream().flatMap(m -> m.steps().stream()).filter(s -> s.pass().equals(id)).mapToLong(s -> s.result().edits()).sum();
    }
    private Map<String, Integer> literals(Method method) {
        Map<String, Integer> result = new HashMap<>();
        for (Instruction i : method.getImplementation().getInstructions())
            if (i instanceof ReferenceInstruction r && r.getReference() instanceof StringReference s) result.merge(s.getString(), 1, Integer::sum);
        return result;
    }
    private int opcodes(Method method, Opcode opcode) {
        int count = 0;
        for (Instruction i : method.getImplementation().getInstructions()) if (i.getOpcode() == opcode) count++;
        return count;
    }
    private DexFile map(DexFile input, UnaryOperator<Method> mapper, Method extra) {
        List<ClassDef> classes = new ArrayList<>();
        for (ClassDef cls : input.getClasses()) {
            List<Method> methods = new ArrayList<>();
            for (Method method : cls.getMethods()) methods.add(mapper.apply(method));
            if (extra != null && extra.getDefiningClass().equals(cls.getType())) methods.add(extra);
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(),
                    cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        return new ImmutableDexFile(input.getOpcodes(), classes);
    }
    private Method extra(String owner, String name, String ret, MethodImplementation code) {
        return new ImmutableMethod(owner, name, List.of(), ret, AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(), Set.of(), Set.of(), code);
    }

    @Test public void recognizesSampleFactsAndOnlySimplifiesTheExactNegationIdentityInOpt() throws Exception {
        for (String name : List.of("opt", "number", "planar", "strings")) {
            NpAnalysis analysis = NpAnalysis.of(new DexContext(sample(name)));
            assertEquals(name, 5, analysis.hashHelpers());
            assertEquals(name, 5, analysis.stringHelpers());
            assertEquals(name, 5, analysis.stableIntegerFields());
            assertEquals(name, 0, analysis.rejectedIntegerFields());
            assertEquals(name, name.equals("strings") ? 8 : 0, analysis.shortArrays());
        }
        assertEquals(List.of("Ldev/deobfuscator/fixture/cases/ObjectCases$Counter;->add(I)I"),
                transform(sample("opt")).methods().stream()
                        .filter(m -> m.steps().stream().anyMatch(s -> s.pass().equals("np.instructions") && s.result().edits() > 0))
                        .map(DexEngine.MethodReport::method).toList());
        assertEquals(0, transform(sample("original")).changedMethods());
    }
    @Test public void restoresAll61NumericExpressionsAndRetainsFieldReads() throws Exception {
        DexFile input = sample("number");
        var result = new DexEngine(List.of(new NumberTransformer()), 20).transform(input);
        assertEquals(61, edits(result, "np.numbers"));
        assertEquals(19, result.changedMethods());
        DexContext before = new DexContext(input), after = new DexContext(result.dex());
        for (var entry : before.methods().entrySet())
            assertEquals(entry.getKey(), opcodes(entry.getValue(), Opcode.SGET), opcodes(after.findMethod(entry.getKey()).orElseThrow(), Opcode.SGET));
        assertEquals(0, new DexEngine(List.of(new NumberTransformer()), 20).transform(result.dex()).changedMethods());
    }
    @Test public void restoresAll224StringsIncludingUnicodeAndPreservesInvokes() throws Exception {
        DexFile input = sample("strings");
        var result = new DexEngine(List.of(new StringTransformer()), 20).transform(input);
        assertEquals(224, edits(result, "np.strings"));
        assertEquals(16, result.changedMethods());
        DexContext original = new DexContext(sample("original")), after = new DexContext(result.dex()), before = new DexContext(input);
        for (var report : result.methods()) if (report.edits() > 0) {
            Method method = after.findMethod(report.method()).orElseThrow();
            assertEquals(report.method(), literals(original.findMethod(report.method()).orElseThrow()), literals(method));
            assertEquals(report.method(), opcodes(before.findMethod(report.method()).orElseThrow(), Opcode.INVOKE_STATIC_RANGE), opcodes(method, Opcode.INVOKE_STATIC_RANGE));
        }
        assertEquals(0, new DexEngine(List.of(new StringTransformer()), 20).transform(result.dex()).changedMethods());
    }
    @Test public void planarOutputReloadsAndRestoresExceptionDispatchers() throws Exception {
        var result = transform(sample("planar"));
        assertTrue(edits(result, "np.dispatcher") > 0);
        DexContext input = new DexContext(sample("planar")), output = new DexContext(result.dex());
        String flow = "Ldev/deobfuscator/fixture/cases/FlowCases;->";
        for (String name : List.of("sign(I)I", "nested(II)I", "loop(I)I"))
            assertEquals(name, 0, opcodes(output.findMethod(flow + name).orElseThrow(), Opcode.SPARSE_SWITCH));
        for (String signature : List.of(
                "Ldev/deobfuscator/fixture/cases/ExceptionCases;->safeDivide(I)I",
                "Ldev/deobfuscator/fixture/cases/ExceptionCases;->finallyTrace(I)Ljava/lang/String;",
                "Ldev/deobfuscator/fixture/harness/FixtureSuite;->runAll()Ldev/deobfuscator/fixture/harness/FixtureSuite$Report;",
                "Ldev/deobfuscator/fixture/harness/BaselineMain;->main([Ljava/lang/String;)V")) {
            Method restored = output.findMethod(signature).orElseThrow();
            assertEquals(signature, 0, opcodes(restored, Opcode.SPARSE_SWITCH));
            assertFalse(signature, restored.getImplementation().getTryBlocks().isEmpty());
        }
        Path path = directory.getRoot().toPath().resolve("output.dex");
        DexFiles.write(path, result.dex());
        assertEquals(0, transform(DexFiles.read(path)).changedMethods());
    }

    @Test public void planarEvaluateHasNoProxyScaffoldingAndKeepsBusinessSwitches() throws Exception {
        DexFile input = sample("planar");
        var result = transform(input);
        assertTrue(edits(result, "np.cleanup") > 0);
        DexContext original = new DexContext(sample("original")), cleaned = new DexContext(result.dex());
        Set<String> helpers = new HashSet<>(new DexContext(input).classes().keySet());
        helpers.removeAll(original.classes().keySet());
        String sig = "Ldev/deobfuscator/fixture/harness/FixtureSuite;->evaluate(Ldev/deobfuscator/fixture/harness/FixtureSuite$Vector;)Ljava/lang/String;";
        Method method = cleaned.findMethod(sig).orElseThrow();
        for (Instruction i : method.getImplementation().getInstructions()) if (i instanceof ReferenceInstruction r) {
            if (r.getReference() instanceof MethodReference m) assertFalse(Signatures.of(m), helpers.contains(m.getDefiningClass()));
            if (r.getReference() instanceof FieldReference f) assertFalse(Signatures.of(f), helpers.contains(f.getDefiningClass()));
        }
        assertEquals(1, opcodes(method, Opcode.SPARSE_SWITCH));
        assertEquals(1, opcodes(method, Opcode.PACKED_SWITCH));
        assertTrue("Business calls must survive", opcodes(method, Opcode.INVOKE_STATIC) >= 15);
    }

    private MethodReference hashHelper(DexFile input) {
        return new DexContext(input).methods().values().stream()
                .filter(m -> m.getParameterTypes().equals(List.of("Ljava/lang/Object;")) && m.getReturnType().equals("I"))
                .findFirst().orElseThrow();
    }

    @Test public void cleanupRetainsNullHashAndUnknownCallsAndThrowingDivision() throws Exception {
        DexFile input = sample("opt");
        MethodReference hash = hashHelper(input);
        MethodImplementationBuilder b = new MethodImplementationBuilder(3);
        Fixtures.string(b, 0, "pure");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, hash));
        Fixtures.integer(b, 0, 0);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, hash));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Ljava/lang/System;", "nanoTime", List.of(), "J")));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_WIDE, 1));
        Fixtures.integer(b, 1, 4);
        b.addInstruction(new BuilderInstruction23x(Opcode.DIV_INT, 2, 1, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 1));
        Method added = extra(STRING_CLASS, "cleanupEffects", "I", b.getMethodImplementation());
        var result = transform(map(input, UnaryOperator.identity(), added), "np.cleanup");
        Method output = new DexContext(result.dex()).findMethod(Signatures.of(added)).orElseThrow();
        assertEquals(2, opcodes(output, Opcode.INVOKE_STATIC)); // null hash and nanoTime retained
        assertEquals(0, opcodes(output, Opcode.MOVE_RESULT_WIDE)); // unused result, not the call
        assertEquals(1, opcodes(output, Opcode.DIV_INT));
        assertEquals(0, opcodes(output, Opcode.CONST_STRING));
    }

    @Test public void cleanupKeepsLiveHashResultsAndWideValues() throws Exception {
        DexFile input = sample("opt");
        MethodReference hash = hashHelper(input);
        MethodImplementationBuilder b = new MethodImplementationBuilder(5);
        Fixtures.string(b, 0, "live");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, hash));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addInstruction(new BuilderInstruction12x(Opcode.INT_TO_LONG, 1, 0));
        b.addInstruction(new BuilderInstruction51l(Opcode.CONST_WIDE, 3, Long.MIN_VALUE + 7));
        b.addInstruction(new BuilderInstruction12x(Opcode.XOR_LONG_2ADDR, 1, 3));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_WIDE, 1));
        Method added = extra(STRING_CLASS, "cleanupWide", "J", b.getMethodImplementation());
        var result = transform(map(input, UnaryOperator.identity(), added), "np.cleanup");
        Method output = new DexContext(result.dex()).findMethod(Signatures.of(added)).orElseThrow();
        assertEquals(1, opcodes(output, Opcode.INVOKE_STATIC));
        assertEquals(1, opcodes(output, Opcode.CONST_WIDE));
        assertEquals(1, opcodes(output, Opcode.XOR_LONG_2ADDR));
    }

    @Test public void cleanupDoesNotBypassHelperBusinessInitialization() throws Exception {
        DexFile input = sample("opt");
        MethodReference hash = hashHelper(input);
        MethodImplementationBuilder init = new MethodImplementationBuilder(0);
        init.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Lprobe/Effects;", "initialize", List.of(), "V")));
        init.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        input = map(input, UnaryOperator.identity(), extra(hash.getDefiningClass(), "<clinit>", "V", init.getMethodImplementation()));
        MethodImplementationBuilder b = new MethodImplementationBuilder(1);
        Fixtures.string(b, 0, "initialization must remain");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, hash));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        Method added = extra(STRING_CLASS, "cleanupInit", "V", b.getMethodImplementation());
        var result = transform(map(input, UnaryOperator.identity(), added), "np.cleanup");
        Method output = new DexContext(result.dex()).findMethod(Signatures.of(added)).orElseThrow();
        assertEquals(1, opcodes(output, Opcode.INVOKE_STATIC));
        assertEquals(1, opcodes(output, Opcode.CONST_STRING));
    }

    // The external probe records/throws from <clinit> during optional ART verification.
    private static final ImmutableFieldReference HASH_VALUE = new ImmutableFieldReference(Fixtures.NP_HASH.getDefiningClass(), "value", "I");
    private static final ImmutableMethodReference HASH_TOUCH = new ImmutableMethodReference(Fixtures.NP_HASH.getDefiningClass(), "touch", List.of(), "V");
    private static void hashCall(MethodImplementationBuilder b, boolean range) {
        b.addInstruction(range ? new BuilderInstruction3rc(Opcode.INVOKE_STATIC_RANGE, 0, 1, Fixtures.NP_HASH)
                : new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0, Fixtures.NP_HASH));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 1));
    }
    private static void hashLiteral(MethodImplementationBuilder b, boolean range) {
        Fixtures.string(b, 0, "ۣۢ۠"); hashCall(b, range);
    }
    private static void hashTouch(MethodImplementationBuilder b) {
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, HASH_TOUCH));
    }
    private static DexFile initializedHashFixture(String scenario, boolean range) {
        var b = new MethodImplementationBuilder(6);
        if (Set.of("anchorCall", "anchorLoop", "anchorProtected", "initializedHandler", "unknown", "live").contains(scenario)) hashTouch(b);
        if (scenario.equals("anchorRead")) b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 2, HASH_VALUE));
        if (scenario.equals("constClass")) b.addInstruction(new BuilderInstruction21c(Opcode.CONST_CLASS, 2,
                new ImmutableTypeReference(Fixtures.NP_HASH.getDefiningClass())));
        if (scenario.startsWith("branch")) {
            b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 4, b.getLabel("other")));
            hashTouch(b); Fixtures.go(b, "join");
            b.addLabel("other"); if (scenario.equals("branchBoth")) hashTouch(b);
            b.addLabel("join");
        }
        b.addLabel("start");
        if (scenario.equals("initializedHandler")) b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 4, 0, 0, 0, 0,
                new ImmutableMethodReference("LHashInitProbe;", "raise", List.of("I"), "V")));
        if (scenario.equals("unknown")) {
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 0, 5)); hashCall(b, range);
        } else {
            hashLiteral(b, range);
            if (!Set.of("loop", "anchorLoop", "initializedHandler", "live").contains(scenario)) hashLiteral(b, range);
            if (scenario.equals("repeated")) hashLiteral(b, range);
        }
        if (scenario.equals("loop") || scenario.equals("anchorLoop")) {
            b.addInstruction(new BuilderInstruction21t(Opcode.IF_LEZ, 4, b.getLabel("end")));
            b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 4, 4, -1)); Fixtures.go(b, "start");
        }
        b.addLabel("end");
        if (!scenario.equals("live")) Fixtures.integer(b, 1, 7);
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 1));
        if (Set.of("protected", "anchorProtected", "failedInit", "initializedHandler").contains(scenario)) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 2));
            if (scenario.equals("failedInit") || scenario.equals("initializedHandler")) hashLiteral(b, range);
            Fixtures.integer(b, 1, -9); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 1));
            b.addCatch(b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        }
        Method caller = Fixtures.method("hashCleanup", List.of(new ImmutableMethodParameter("I", Set.of(), null),
                new ImmutableMethodParameter("Ljava/lang/Object;", Set.of(), null)), "I", b.getMethodImplementation());
        var classes = new ArrayList<ClassDef>();
        for (ClassDef cls : Fixtures.npDex(caller).getClasses()) {
            if (!cls.getType().equals(Fixtures.NP_HASH.getDefiningClass())) { classes.add(cls); continue; }
            var init = new MethodImplementationBuilder(1);
            init.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                    new ImmutableMethodReference("LHashInitProbe;", "initialize", List.of(), "I")));
            init.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
            init.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, HASH_VALUE));
            init.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            var touch = new MethodImplementationBuilder(0); touch.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            var methods = new ArrayList<Method>(); cls.getMethods().forEach(methods::add);
            methods.add(new ImmutableMethod(cls.getType(), "<clinit>", List.of(), "V", AccessFlags.STATIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                    Set.of(), Set.of(), init.getMethodImplementation()));
            methods.add(new ImmutableMethod(cls.getType(), "touch", List.of(), "V", AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(),
                    Set.of(), Set.of(), touch.getMethodImplementation()));
            var field = new ImmutableField(cls.getType(), "value", "I", AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(), null, Set.of(), Set.of());
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(),
                    cls.getAnnotations(), List.of(field), methods));
        }
        return new ImmutableDexFile(Opcodes.forApi(28), classes);
    }
    private Method cleanedHash(String scenario, boolean range, int expectedCalls) throws Exception {
        var result = transform(initializedHashFixture(scenario, range), "np.cleanup");
        Path file = directory.getRoot().toPath().resolve(scenario + range + ".dex"); DexFiles.write(file, result.dex());
        DexFile reread = DexFiles.read(file);
        Method method = new DexContext(reread).findMethod("Lsample/Test;->hashCleanup(ILjava/lang/Object;)I").orElseThrow();
        int calls = 0;
        for (Instruction i : method.getImplementation().getInstructions()) if (i instanceof ReferenceInstruction r
                && r.getReference() instanceof MethodReference m && Signatures.of(m).equals(Signatures.of(Fixtures.NP_HASH))) calls++;
        assertEquals(scenario + " range=" + range, expectedCalls, calls);
        assertEquals(scenario, 0, transform(reread, "np.cleanup").changedMethods());
        return method;
    }
    @Test public void cleanupRemovesRepeatedHashesButKeepsTheFirstInitializer() throws Exception {
        for (boolean range : new boolean[]{false, true}) {
            Method method = cleanedHash("repeated", range, 1);
            assertEquals(1, opcodes(method, Opcode.CONST_STRING));
            assertEquals(0, opcodes(method, Opcode.MOVE_RESULT));
        }
    }
    @Test public void cleanupUsesEarlierStaticCallsAndFieldReadsAsInitializationProof() throws Exception {
        for (boolean range : new boolean[]{false, true}) for (String scenario : List.of("anchorCall", "anchorRead")) {
            Method method = cleanedHash(scenario, range, 0);
            assertEquals(0, opcodes(method, Opcode.CONST_STRING));
            assertEquals(scenario.equals("anchorRead") ? 1 : 0, opcodes(method, Opcode.SGET));
        }
    }
    @Test public void cleanupRequiresInitializationOnEveryIncomingBranch() throws Exception {
        for (boolean range : new boolean[]{false, true}) {
            cleanedHash("branchOne", range, 1); cleanedHash("branchBoth", range, 0);
        }
    }
    @Test public void cleanupDoesNotAssumeInitializationFromALoopBackEdge() throws Exception {
        for (boolean range : new boolean[]{false, true}) {
            cleanedHash("loop", range, 1); cleanedHash("anchorLoop", range, 0);
        }
    }
    @Test public void cleanupPreservesFailedInitializationAndSeparatesHandlerPaths() throws Exception {
        for (boolean range : new boolean[]{false, true}) {
            cleanedHash("protected", range, 1); cleanedHash("anchorProtected", range, 0);
            cleanedHash("failedInit", range, 2); cleanedHash("initializedHandler", range, 0);
        }
    }
    @Test public void cleanupRetainsLiveAndUnknownHashesAfterInitialization() throws Exception {
        for (boolean range : new boolean[]{false, true}) {
            cleanedHash("live", range, 1); cleanedHash("unknown", range, 1);
        }
    }
    @Test public void cleanupDoesNotTreatConstClassAsInitialization() throws Exception {
        for (boolean range : new boolean[]{false, true}) cleanedHash("constClass", range, 1);
    }
    private DexFile protectedFieldFixture(String scenario) throws Exception {
        DexFile input = sample("number");
        var original = new DexContext(input); var model = NpAnalysis.of(original).model();
        Field field = original.fields().get(model.fields().keySet().iterator().next());
        String owner = field.getDefiningClass(); var classes = new ArrayList<ClassDef>();
        for (ClassDef cls : input.getClasses()) {
            if (!cls.getType().equals(owner)) { classes.add(cls); continue; }
            var fields = new ArrayList<Field>();
            for (Field f : cls.getFields()) fields.add(f == field || Signatures.of(f).equals(Signatures.of(field))
                    ? new ImmutableField(f.getDefiningClass(), f.getName(), f.getType(), f.getAccessFlags()
                            | (scenario.equals("volatile") ? AccessFlags.VOLATILE.getValue() : 0), f.getInitialValue(), f.getAnnotations(), f.getHiddenApiRestrictions()) : f);
            var methods = new ArrayList<Method>(); cls.getMethods().forEach(methods::add);
            boolean privateTable = scenario.startsWith("private-table");
            var init = new MethodImplementationBuilder(privateTable ? 3 : 0);
            if (privateTable) {
                var table = new ImmutableFieldReference(owner, "privateTable", "[S");
                fields.add(new ImmutableField(owner, table.getName(), "[S", AccessFlags.PRIVATE.getValue()
                        | AccessFlags.STATIC.getValue() | AccessFlags.FINAL.getValue(), null, Set.of(), Set.of()));
                Fixtures.integer(init, 0, 1);
                init.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 0, 0, new ImmutableTypeReference("[S")));
                Fixtures.integer(init, 1, 0); Fixtures.integer(init, 2, 7);
                init.addInstruction(new BuilderInstruction23x(Opcode.APUT_SHORT, 2, 0, 1));
                init.addInstruction(new BuilderInstruction21c(Opcode.SPUT_OBJECT, 0, table));
            } else if (!scenario.equals("empty-init") && !scenario.equals("no-init")) {
                init.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                        new ImmutableMethodReference("LRootFlowFixtureProbe;", "initialize", List.of(), "V")));
            }
            init.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            assertTrue(methods.stream().noneMatch(m -> m.getName().equals("<clinit>")));
            if (!scenario.equals("no-init")) methods.add(extra(owner, "<clinit>", "V", init.getMethodImplementation()));
            if (scenario.equals("mutation")) {
                var write = new MethodImplementationBuilder(1);
                Fixtures.integer(write, 0, ((org.jf.dexlib2.iface.value.IntEncodedValue)field.getInitialValue()).getValue() + 1);
                write.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, field)); write.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
                methods.add(extra(owner, "mutateProtectedField", "V", write.getMethodImplementation()));
            }
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), fields, methods));
        }
        var b = new MethodImplementationBuilder(2);
        if (scenario.equals("conditional")) b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 1, b.getLabel("second")));
        if (scenario.equals("const-class")) b.addInstruction(new BuilderInstruction21c(Opcode.CONST_CLASS, 0, new ImmutableTypeReference(owner)));
        else {
            b.addLabel("first"); b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, field)); b.addLabel("firstEnd");
        }
        Fixtures.go(b, "second");
        if (scenario.equals("failed-init")) {
            b.addLabel("firstHandler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0)); Fixtures.go(b, "second");
        }
        b.addLabel("second"); b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, field)); b.addLabel("secondEnd");
        if (!scenario.endsWith("live")) Fixtures.integer(b, 0, 7);
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("secondHandler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
        Fixtures.integer(b, 0, -7); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        if (scenario.equals("failed-init")) b.addCatch("Ljava/lang/Throwable;", b.getLabel("first"), b.getLabel("firstEnd"), b.getLabel("firstHandler"));
        b.addCatch("Ljava/lang/Throwable;", b.getLabel("second"), b.getLabel("secondEnd"), b.getLabel("secondHandler"));
        Method caller = new ImmutableMethod(STRING_CLASS, "protectedReads", List.of(new ImmutableMethodParameter("I", Set.of(), "flag")), "I",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
        return map(new ImmutableDexFile(input.getOpcodes(), classes), UnaryOperator.identity(), caller);
    }

    @Test public void protectedRepeatedReadsRequireSuccessfulInitializationOnEveryPath() throws Exception {
        for (String scenario : List.of("straight", "conditional", "failed-init", "const-class", "volatile", "mutation", "live")) {
            DexFile input = protectedFieldFixture(scenario);
            var result = transform(input, "np.cleanup"); String signature = STRING_CLASS + "->protectedReads(I)I";
            Method caller = new DexContext(result.dex()).methods().get(signature);
            assertEquals(scenario, scenario.equals("straight") || scenario.equals("const-class") ? 1 : 2, opcodes(caller, Opcode.SGET));
            assertTrue("First initialization call and its business effect remain", opcodes(caller, Opcode.SGET) > 0);
            Path file = directory.getRoot().toPath().resolve("protected-read-" + scenario + ".dex"); DexFiles.write(file, result.dex());
            assertEquals(scenario, 0, transform(DexFiles.read(file), "np.cleanup").changedMethods());
        }
    }
    @Test public void protectedFirstReadsAcceptHarmlessInitializationAndRetainLiveResults() throws Exception {
        for (String scenario : List.of("no-init", "empty-init", "private-table", "private-table-live")) {
            var input = protectedFieldFixture(scenario); var result = transform(input, "np.cleanup");
            String signature = STRING_CLASS + "->protectedReads(I)I";
            Method caller = new DexContext(result.dex()).findMethod(signature).orElseThrow();
            assertEquals(scenario, scenario.endsWith("live") ? 1 : 0, opcodes(caller, Opcode.SGET));
            assertEquals(new NpNumericInterpreter(input).run(signature, 0), new NpNumericInterpreter(result.dex()).run(signature, 0));
            Path path = directory.getRoot().toPath().resolve("harmless-field-" + scenario + ".dex"); DexFiles.write(path, result.dex());
            assertEquals(0, transform(DexFiles.read(path), "np.cleanup").changedMethods());
        }
    }
    @Test public void reachableFieldMutationInvalidatesAssumptionAndLeavesUnknownXor() throws Exception {
        DexFile input = sample("number");
        Method mix = new DexContext(input).findMethod("Ldev/deobfuscator/fixture/cases/ArithmeticCases;->mix(I)I").orElseThrow();
        FieldReference field = null;
        for (Instruction i : mix.getImplementation().getInstructions()) if (i.getOpcode() == Opcode.SGET) {
            field = (FieldReference)((ReferenceInstruction)i).getReference(); break;
        }
        assertNotNull(field);
        MethodImplementationBuilder b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction31i(Opcode.CONST, 0, 12345));
        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, field));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        DexFile mutated = map(input, UnaryOperator.identity(), extra(mix.getDefiningClass(), "mutateProxy", "V", b.getMethodImplementation()));
        NpAnalysis analysis = NpAnalysis.of(new DexContext(mutated));
        assertEquals(4, analysis.stableIntegerFields());
        assertEquals(1, analysis.rejectedIntegerFields());
        var result = transform(mutated, "np.numbers");
        Method restored = new DexContext(result.dex()).findMethod(Signatures.of(mix)).orElseThrow();
        assertEquals(2, opcodes(restored, Opcode.XOR_INT_LIT16));
    }
    @Test public void rejectsEscapingAndModifiedShortArrays() throws Exception {
        DexFile input = sample("strings");
        for (boolean escape : new boolean[]{true, false}) {
            MethodImplementationBuilder b = new MethodImplementationBuilder(3);
            b.addInstruction(new BuilderInstruction21c(Opcode.SGET_OBJECT, 0, new ImmutableFieldReference(STRING_CLASS, "short", "[S")));
            if (escape) b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
            else {
                b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 1, 0));
                b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 0));
                b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 2, 1));
                b.addInstruction(new BuilderInstruction23x(Opcode.APUT_SHORT, 2, 1, 0));
                b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            }
            DexFile unsafe = map(input, UnaryOperator.identity(), extra(STRING_CLASS, "unsafeTable", escape ? "[S" : "V", b.getMethodImplementation()));
            assertEquals(7, NpAnalysis.of(new DexContext(unsafe)).shortArrays());
            var result = transform(unsafe, "np.strings");
            assertEquals(215, edits(result, "np.strings"));
            assertEquals(0, opcodes(new DexContext(result.dex()).findMethod(LITERAL).orElseThrow(), Opcode.CONST_STRING_JUMBO));
        }
    }
    @Test public void sameDecoderDescriptorWithDifferentBodyIsNotTrusted() throws Exception {
        DexFile input = sample("strings");
        Method method = new DexContext(input).findMethod(LITERAL).orElseThrow();
        String decoder = null;
        for (Instruction i : method.getImplementation().getInstructions()) if (i.getOpcode() == Opcode.INVOKE_STATIC_RANGE) {
            decoder = Signatures.of((MethodReference)((ReferenceInstruction)i).getReference()); break;
        }
        assertNotNull(decoder);
        String target = decoder;
        DexFile different = map(input, m -> {
            if (!Signatures.of(m).equals(target)) return m;
            MethodContext context = new MethodContext(m);
            context.code().replaceInstruction(5, new BuilderInstruction12x(Opcode.ADD_INT_2ADDR, 2, 6));
            return context.finish();
        }, null);
        var result = transform(different, "np.strings");
        assertEquals(0, opcodes(new DexContext(result.dex()).findMethod(LITERAL).orElseThrow(), Opcode.CONST_STRING_JUMBO));
    }
    @Test public void unknownOrOutOfBoundsStringSliceKeepsOriginalResult() throws Exception {
        DexFile input = sample("strings");
        for (boolean unknown : new boolean[]{false, true}) {
            DexFile changed = map(input, method -> {
                if (!Signatures.of(method).equals(LITERAL)) return method;
                MethodContext context = new MethodContext(method); CodeGraph graph = context.graph();
                int startRegister = -1;
                for (int i = 0; i < graph.size(); i++) if (graph.at(i).getOpcode() == Opcode.INVOKE_STATIC_RANGE) {
                    startRegister = ConstantEvaluator.arguments(graph.at(i))[1]; break;
                }
                assertTrue(startRegister >= 0);
                for (int i = 0; i < graph.size(); i++) if (graph.at(i).getOpcode() == Opcode.CONST
                        && ((OneRegisterInstruction)graph.at(i)).getRegisterA() == startRegister) {
                    context.code().replaceInstruction(i, unknown
                            ? new BuilderInstruction21c(Opcode.SGET, startRegister, new ImmutableFieldReference("Ldev/deobfuscator/fixture/cases/ObjectCases;", "calls", "I"))
                            : new BuilderInstruction31i(Opcode.CONST, startRegister, Integer.MAX_VALUE));
                    return context.finish();
                }
                throw new AssertionError("Missing offset constant");
            }, null);
            var result = transform(changed, "np.strings");
            assertEquals(223, edits(result, "np.strings"));
            assertEquals(0, opcodes(new DexContext(result.dex()).findMethod(LITERAL).orElseThrow(), Opcode.CONST_STRING_JUMBO));
        }
    }
    @Test public void npStringsComposeWithExistingConfiguredDecoder() throws Exception {
        var specs = List.of(new TransformerSpec("np.strings"), new TransformerSpec("strings.decrypt",
                new TransformerOptions(Map.of("xorMethods", List.of("Ldev/deobfuscator/fixture/cases/XorStrings;->decode(Ljava/lang/String;I)Ljava/lang/String;")))));
        var result = new Deobfuscator(TransformerRegistry.discover()).transform(sample("strings"), specs, 20);
        assertEquals(0, result.failedMethods());
        assertEquals(224, edits(result, "np.strings"));
        assertEquals(2, edits(result, "strings.decrypt"));
        DexContext output = new DexContext(result.dex());
        assertTrue(literals(output.findMethod(LITERAL).orElseThrow()).containsKey("Hello"));
        assertTrue(literals(output.findMethod(STRING_CLASS + "->encryptedUnicode()Ljava/lang/String;").orElseThrow()).containsKey("中文🙂"));
    }
    @Test public void fieldInvariantRechecksDependentProofsAfterRejection() throws Exception {
        DexFile input = sample("number");
        String owner = "Ldev/deobfuscator/fixture/cases/ArithmeticCases;";
        List<Field> fields = new DexContext(input).fields().values().stream()
                .filter(f -> !f.getDefiningClass().contains("R$") && f.getInitialValue() instanceof org.jf.dexlib2.iface.value.IntEncodedValue).toList();
        Field a = fields.get(0), b = fields.get(1);
        int av = ((org.jf.dexlib2.iface.value.IntEncodedValue)a.getInitialValue()).getValue();
        int bv = ((org.jf.dexlib2.iface.value.IntEncodedValue)b.getInitialValue()).getValue();
        MethodImplementationBuilder mutate = new MethodImplementationBuilder(1);
        mutate.addInstruction(new BuilderInstruction31i(Opcode.CONST, 0, av + 1));
        mutate.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, a));
        mutate.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        input = map(input, UnaryOperator.identity(), extra(owner, "writeA", "V", mutate.getMethodImplementation()));
        MethodImplementationBuilder dependent = new MethodImplementationBuilder(2);
        dependent.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, a));
        dependent.addInstruction(new BuilderInstruction31i(Opcode.CONST, 1, av));
        dependent.addInstruction(new BuilderInstruction22t(Opcode.IF_EQ, 0, 1, dependent.getLabel("end")));
        dependent.addInstruction(new BuilderInstruction31i(Opcode.CONST, 0, bv + 1));
        dependent.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, b));
        dependent.addLabel("end"); dependent.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        input = map(input, UnaryOperator.identity(), extra(owner, "writeB", "V", dependent.getMethodImplementation()));
        assertEquals(2, NpAnalysis.of(new DexContext(input)).rejectedIntegerFields());
    }
    @Test public void normalizedHelperOwnersContributeCheckedNumericFields() throws Exception {
        DexFile input = sample("strings");
        var original = new DexContext(input);
        String decoder = NpAnalysis.of(original).model().helpers().decoders().iterator().next();
        String owner = decoder.substring(0, decoder.indexOf("->"));
        var stable = new ImmutableField(owner, "sliceLength", "I", AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(),
                new org.jf.dexlib2.immutable.value.ImmutableIntEncodedValue(7), Set.of(), Set.of());
        var mutable = new ImmutableField(owner, "mutableLength", "I", stable.getAccessFlags(),
                stable.getInitialValue(), Set.of(), Set.of());
        var volatileField = new ImmutableField(owner, "volatileLength", "I", stable.getAccessFlags() | AccessFlags.VOLATILE.getValue(),
                stable.getInitialValue(), Set.of(), Set.of());
        var initialize = new MethodImplementationBuilder(1);
        initialize.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Lprobe/Effects;", "initialize", List.of(), "V")));
        initialize.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        var mutate = new MethodImplementationBuilder(1);
        mutate.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 8));
        mutate.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, mutable));
        mutate.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        var classes = new ArrayList<ClassDef>();
        for (ClassDef cls : input.getClasses()) {
            if (!cls.getType().equals(owner)) { classes.add(cls); continue; }
            var fields = new ArrayList<Field>(); cls.getFields().forEach(fields::add);
            fields.addAll(List.of(stable, mutable, volatileField));
            var methods = new ArrayList<Method>(); cls.getMethods().forEach(methods::add);
            assertTrue(methods.stream().noneMatch(m -> m.getName().equals("<clinit>")));
            methods.add(new ImmutableMethod(owner, "<clinit>", List.of(), "V", AccessFlags.STATIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                    Set.of(), Set.of(), initialize.getMethodImplementation()));
            methods.add(extra(owner, "mutateLength", "V", mutate.getMethodImplementation()));
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(),
                    cls.getSourceFile(), cls.getAnnotations(), fields, methods));
        }
        var b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET, 0, stable));
        b.addInstruction(new BuilderInstruction22b(Opcode.ADD_INT_LIT8, 0, 0, -2));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        Method caller = extra(STRING_CLASS, "knownSliceLength", "I", b.getMethodImplementation());
        input = map(new ImmutableDexFile(input.getOpcodes(), classes), UnaryOperator.identity(), caller);
        var model = NpAnalysis.of(new DexContext(input)).model();
        assertFalse("This owner is discovered only by helper normalization", model.helpers().owners().contains(owner));
        assertEquals(Integer.valueOf(7), model.fields().get(Signatures.of(stable)));
        assertFalse(model.fields().containsKey(Signatures.of(mutable)));
        assertFalse(model.fields().containsKey(Signatures.of(volatileField)));
        var output = new DexContext(transform(input, "np.numbers").dex()).findMethod(Signatures.of(caller)).orElseThrow();
        assertTrue(opcodes(output, Opcode.SGET) > 0);
        assertEquals(0, opcodes(output, Opcode.ADD_INT_LIT8));
        var graph = new CodeGraph(output.getImplementation());
        assertEquals(Integer.valueOf(5), new ConstantAnalysis(graph).before(graph.size() - 1).get(0));
    }
    @Test public void arithmeticUsesJavaOverflowDivisionRemainderAndLeavesDivideByZero() {
        Constants state = new Constants();
        state.put(1, Integer.MIN_VALUE); state.put(2, -1);
        assertTrue(ConstantEvaluator.step(new BuilderInstruction23x(Opcode.DIV_INT, 0, 1, 2), state));
        assertEquals(Integer.MIN_VALUE, state.get(0));
        state.put(1, -517); state.put(2, 444);
        ConstantEvaluator.step(new BuilderInstruction23x(Opcode.DIV_INT, 0, 1, 2), state);
        assertEquals(-1, state.get(0));
        ConstantEvaluator.step(new BuilderInstruction23x(Opcode.REM_INT, 0, 1, 2), state);
        assertEquals(-73, state.get(0));
        state.put(2, 0);
        assertFalse(ConstantEvaluator.step(new BuilderInstruction23x(Opcode.DIV_INT, 0, 1, 2), state));
        assertNull(state.get(0));
    }
    @Test public void rewrittenControlFlowMatchesIndependentSourceOracles() throws Exception {
        Set<Integer> values = new LinkedHashSet<>(List.of(Integer.MIN_VALUE, Integer.MAX_VALUE, -1000, -7, -1, 0, 1, 2, 3, 4, 7, 8, 10, 11, 12, 20, 99, 100000));
        Random random = new Random(20260922);
        for (int i = 0; i < 100; i++) values.add(random.nextInt());
        for (String name : List.of("original", "number", "planar")) {
            DexFile input = sample(name), output = transform(input).dex();
            Path file = directory.getRoot().toPath().resolve(name + ".dex");
            DexFiles.write(file, output);
            NpNumericInterpreter interpreter = new NpNumericInterpreter(DexFiles.read(file));
            String flow = "Ldev/deobfuscator/fixture/cases/FlowCases;->", math = "Ldev/deobfuscator/fixture/cases/ArithmeticCases;->";
            for (int value : values) {
                assertEquals(Integer.signum(value), interpreter.run(flow + "sign(I)I", value));
                int loop = 0; for (int i : new int[]{1,3,5,7}) if (i < value) loop += i;
                assertEquals(loop, interpreter.run(flow + "loop(I)I", value));
                assertEquals(Map.of(0,11,1,22,2,33,3,44).getOrDefault(value,-9), interpreter.run(flow + "denseSwitch(I)I", value));
                assertEquals(Map.of(-1000,17,7,31,100000,99).getOrDefault(value,-1), interpreter.run(flow + "sparseSwitch(I)I", value));
                assertEquals(((value + 17 - 9) ^ 0x13579bdf) ^ 0x2468ace0, interpreter.run(math + "mix(I)I", value));
                assertEquals(((long)value * 3) ^ 0x1020304050607080L, interpreter.run(math + "wide(J)J", (long)value));
                for (int right : new int[]{Integer.MIN_VALUE, -3, 0, 4, 12, Integer.MAX_VALUE}) {
                    int expected = value > 10 ? right < 0 ? value - right : value + right : value == right ? 42 : value ^ right;
                    assertEquals(expected, interpreter.run(flow + "nested(II)I", value, right));
                }
            }
            for (double value : new double[]{-4, 0, 4}) assertEquals(value * 1.5 - 2.0, interpreter.run(math + "floating(D)D", value));
        }
    }
}
