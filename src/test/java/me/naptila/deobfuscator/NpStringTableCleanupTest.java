package me.naptila.deobfuscator;

import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.config.RunConfiguration;
import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import me.naptila.deobfuscator.transformers.np.NpCleanup;
import me.naptila.deobfuscator.transformers.np.analysis.NpAnalysis;
import me.naptila.deobfuscator.transformers.np.strings.StringTransformer;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.reference.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.jf.dexlib2.immutable.value.*;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import static org.junit.Assert.*;

public class NpStringTableCleanupTest {
    @Rule public TemporaryFolder directory = new TemporaryFolder();
    private static final String OWNER = "Lprobe/Subject;", CHILD = "Lprobe/Child;";
    private static final ImmutableFieldReference TABLE = new ImmutableFieldReference(OWNER, "arbitrary_name", "[S");
    private List<ClassDef> helpers;
    private MethodReference decoder;
    @Before public void loadHelpers() throws Exception {
        DexFile input = DexFiles.read(Path.of(getClass().getResource("/np-v2/string.dex").toURI()));
        helpers = new ArrayList<>();
        for (ClassDef cls : input.getClasses()) {
            boolean helper = false;
            for (Method method : cls.getMethods())
                if (method.getParameterTypes().equals(List.of("[S", "I", "I", "I"))
                        && !cls.getType().contains("StringEdges")) { decoder = method; helper = true; }
            if (helper) helpers.add(cls);
        }
        assertNotNull(decoder);
    }
    private Method method(String name, String ret, MethodImplementationBuilder b) {
        return new ImmutableMethod(OWNER, name, List.of(), ret,
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(), Set.of(), Set.of(), b.getMethodImplementation());
    }
    @Test public void restoresConstantStringGetterInsideHelperWithoutRewritingCoreDecoder() throws Exception {
        String owner = decoder.getDefiningClass();
        DexFile base = fixture(true, false, false, false, "");
        var baseContext = new DexContext(base);
        var facts = NpAnalysis.of(baseContext).model();
        var guard = facts.helpers().guards().entrySet().stream().filter(e -> e.getKey().startsWith(owner + "->")).findFirst().orElseThrow();
        Method guardMethod = baseContext.findMethod(guard.getKey()).orElseThrow();
        int guardValue = facts.fields().get(guard.getValue().field()) ^ guard.getValue().key();
        var target = new ImmutableMethodReference(owner, "constantTextTarget", List.of(), "Ljava/lang/String;");
        var additions = new ArrayList<Method>();
        for (boolean wrapper : List.of(false, true)) {
            var b = new MethodImplementationBuilder(1);
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, guardMethod));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
            b.addInstruction(new BuilderInstruction21t(guardValue == 0 ? Opcode.IF_NEZ : Opcode.IF_EQZ, 0, b.getLabel("fallback")));
            if (wrapper) {
                b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, target));
                b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
            } else Fixtures.string(b, 0, "A");
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
            b.addLabel("fallback"); Fixtures.string(b, 0, "unselected");
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
            additions.add(new ImmutableMethod(owner, wrapper ? "constantText" : target.getName(), List.of(), "Ljava/lang/String;",
                    AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(), Set.of(), Set.of(), b.getMethodImplementation()));
        }
        var classes = new ArrayList<ClassDef>();
        for (ClassDef cls : base.getClasses()) {
            if (!cls.getType().equals(owner)) { classes.add(cls); continue; }
            var methods = new ArrayList<Method>(); cls.getMethods().forEach(methods::add); methods.addAll(additions);
            classes.add(new ImmutableClassDef(owner, cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(),
                    cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        DexFile input = new ImmutableDexFile(Opcodes.forApi(28), classes); var before = new DexContext(input);
        var model = NpAnalysis.of(before).model();
        String signature = owner + "->constantText()Ljava/lang/String;";
        assertTrue(model.helpers().owners().contains(owner)); assertEquals("A", model.stringGetters().get(signature));
        var result = transform(input); var after = new DexContext(result.dex()); Method restored = after.findMethod(signature).orElseThrow();
        for (var instruction : restored.getImplementation().getInstructions())
            if (instruction instanceof org.jf.dexlib2.iface.instruction.ReferenceInstruction ref
                    && ref.getReference() instanceof MethodReference call) assertNotEquals(Signatures.of(target), Signatures.of(call));
        assertEquals("A", new NpNumericInterpreter(input).run(signature));
        assertEquals("A", new NpNumericInterpreter(result.dex()).run(signature));
        assertEquals(MethodFingerprint.of(before, before.findMethod(Signatures.of(decoder)).orElseThrow()),
                MethodFingerprint.of(after, after.findMethod(Signatures.of(decoder)).orElseThrow()));
        Path file = directory.getRoot().toPath().resolve("helper-getter.dex"); DexFiles.write(file, result.dex());
        var second = transform(DexFiles.read(file)); assertEquals(0, second.changedMethods()); assertEquals(0, second.dexEdits());
    }
    private Method initializer(boolean singleton, boolean mixed) {
        var b = new MethodImplementationBuilder(3);
        Fixtures.integer(b, 0, singleton ? 1 : 2);
        b.addInstruction(new BuilderInstruction22c(Opcode.NEW_ARRAY, 0, 0, new ImmutableTypeReference("[S")));
        if (singleton) {
            Fixtures.integer(b, 1, 0); Fixtures.integer(b, 2, 'A' ^ 73);
            b.addInstruction(new BuilderInstruction23x(Opcode.APUT_SHORT, 2, 0, 1));
        } else b.addInstruction(new BuilderInstruction31t(Opcode.FILL_ARRAY_DATA, 0, b.getLabel("data")));
        b.addInstruction(new BuilderInstruction21c(Opcode.SPUT_OBJECT, 0, TABLE));
        if (mixed) b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Lprobe/Effects;", "run", List.of(), "V")));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        if (!singleton) { b.addLabel("data"); b.addInstruction(new BuilderArrayPayload(2, List.of('A' ^ 73, 'B' ^ 73))); }
        return method("<clinit>", "V", b);
    }
    private Method decode(boolean protectedCall, boolean unknownSlice) {
        var b = new MethodImplementationBuilder(6);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET_OBJECT, 0, TABLE));
        // The origin tracker must follow aliases, rather than the array register's spelling.
        b.addInstruction(new BuilderInstruction22x(Opcode.MOVE_OBJECT_FROM16, 4, 0));
        if (unknownSlice) {
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                    new ImmutableMethodReference("Lprobe/Effects;", "offset", List.of(), "I")));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 1));
        } else Fixtures.integer(b, 1, 0);
        Fixtures.integer(b, 2, 1); Fixtures.integer(b, 3, 73);
        b.addLabel("start"); b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 4, 4, 1, 2, 3, 0, decoder));
        b.addLabel("end"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        if (protectedCall) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 0));
            b.addInstruction(new BuilderInstruction11x(Opcode.THROW, 0));
            b.addCatch(b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        }
        return method("decode", "Ljava/lang/String;", b);
    }
    private DexFile fixture(boolean singleton, boolean mixed, boolean protectedCall, boolean unknown, String reference) {
        List<Method> methods = new ArrayList<>(List.of(initializer(singleton, mixed), decode(protectedCall, unknown)));
        List<Annotation> annotations = new ArrayList<>(); List<ClassDef> classes = new ArrayList<>(helpers);
        FieldReference field = reference.equals("inherited") ? new ImmutableFieldReference(CHILD, TABLE.getName(), "[S") : TABLE;
        var handle = new ImmutableMethodHandleReference(MethodHandleType.STATIC_GET, field);
        if (reference.equals("annotation") || reference.equals("inherited")) {
            var nested = new ImmutableAnnotationEncodedValue("Lprobe/Nested;", Set.of(new ImmutableAnnotationElement("value", new ImmutableFieldEncodedValue(ImmutableFieldReference.of(field)))));
            annotations.add(new ImmutableAnnotation(AnnotationVisibility.RUNTIME, "Lprobe/Uses;",
                    Set.of(new ImmutableAnnotationElement("nested", new ImmutableArrayEncodedValue(List.of(nested))))));
        } else if (!reference.isEmpty()) {
            var b = new MethodImplementationBuilder(1);
            if (reference.equals("read")) {
                b.addInstruction(new BuilderInstruction21c(Opcode.SGET_OBJECT, 0, TABLE));
                b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
                methods.add(method("businessReader", "[S", b));
            } else {
                if (reference.equals("handle")) b.addInstruction(new BuilderInstruction21c(Opcode.CONST_METHOD_HANDLE, 0, handle));
                else {
                    var bootstrap = new ImmutableMethodHandleReference(MethodHandleType.INVOKE_STATIC,
                            new ImmutableMethodReference("Lprobe/Bootstrap;", "bootstrap", List.of(), "V"));
                    var callsite = new ImmutableCallSiteReference("site", bootstrap, "call", new ImmutableMethodProtoReference(List.of(), "V"),
                            List.of(new ImmutableMethodHandleEncodedValue(handle)));
                    b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_CUSTOM, 0, 0, 0, 0, 0, 0, callsite));
                }
                b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID)); methods.add(method("metadata", "V", b));
            }
        }
        Field table = new ImmutableField(OWNER, TABLE.getName(), "[S", AccessFlags.PRIVATE.getValue() | AccessFlags.STATIC.getValue() | AccessFlags.FINAL.getValue(), null, Set.of(), Set.of());
        classes.add(new ImmutableClassDef(OWNER, AccessFlags.PUBLIC.getValue(), "Ljava/lang/Object;", List.of(), null, annotations, List.of(table), methods));
        if (reference.equals("inherited")) classes.add(new ImmutableClassDef(CHILD, AccessFlags.PUBLIC.getValue(), OWNER, List.of(), null, Set.of(), List.of(), List.of()));
        return new ImmutableDexFile(Opcodes.forApi(28), classes);
    }
    private DexEngine.Result transform(DexFile dex, String... ids) {
        var specs = ids.length == 0 ? RunConfiguration.defaults().transformers() : Arrays.stream(ids).map(TransformerSpec::new).toList();
        var result = new Deobfuscator(TransformerRegistry.discover()).transform(dex, specs, 20);
        assertEquals(0, result.failedMethods()); assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged)); return result;
    }
    private void retained(DexEngine.Result result) {
        DexContext dex = new DexContext(result.dex());
        assertTrue(dex.findField(Signatures.of(TABLE)).isPresent()); assertTrue(dex.findMethod(OWNER + "-><clinit>()V").isPresent());
        assertEquals(0, result.dexEdits());
    }
    @Test public void removesPayloadAndSingletonTablesAfterFollowingDecoderArguments() throws Exception {
        for (boolean singleton : List.of(false, true)) {
            var result = transform(fixture(singleton, false, false, false, "")); var dex = new DexContext(result.dex());
            assertFalse(dex.findField(Signatures.of(TABLE)).isPresent()); assertFalse(dex.findMethod(OWNER + "-><clinit>()V").isPresent());
            assertEquals(2, result.dexEdits());
            Path file = directory.getRoot().toPath().resolve("output-" + singleton + ".dex"); DexFiles.write(file, result.dex());
            var second = transform(DexFiles.read(file)); assertEquals(0, second.changedMethods()); assertEquals(0, second.dexEdits());
        }
    }
    @Test public void protectedUnknownOrBusinessUsesKeepTheirTables() {
        retained(transform(fixture(false, false, true, false, "")));
        retained(transform(fixture(false, false, false, true, "")));
        retained(transform(fixture(false, false, false, false, "read")));
    }
    @Test public void metadataMethodHandlesAndCallsitesPreventDanglingFields() throws Exception {
        for (String reference : List.of("annotation", "handle", "callsite", "inherited")) {
            var result = transform(fixture(false, false, false, false, reference)); retained(result);
            // dexlib2 2.5.2 ClassPool cannot encode CONST_METHOD_HANDLE (reference type 6).
            // Exercise that instruction's reference proof in memory; the other forms round-trip.
            if (reference.equals("handle")) continue;
            Path file = directory.getRoot().toPath().resolve(reference + ".dex"); DexFiles.write(file, result.dex());
            assertTrue(new DexContext(DexFiles.read(file)).findField(Signatures.of(TABLE)).isPresent());
        }
    }
    @Test public void mixedInitializersKeepBusinessEffectsAndStringFeatureOwnsCleanup() throws Exception {
        var result = transform(fixture(false, true, false, false, ""));
        var dex = new DexContext(result.dex());
        assertFalse(dex.findField(Signatures.of(TABLE)).isPresent());
        Method init = dex.findMethod(OWNER + "-><clinit>()V").orElseThrow();
        List<Opcode> ops = new ArrayList<>(); init.getImplementation().getInstructions().forEach(i -> ops.add(i.getOpcode()));
        assertTrue(ops.contains(Opcode.INVOKE_STATIC));
        assertFalse(ops.contains(Opcode.NEW_ARRAY));
        Path file = directory.getRoot().toPath().resolve("mixed.dex"); DexFiles.write(file, result.dex());
        assertEquals(0, transform(DexFiles.read(file)).dexEdits());
        var automatic = transform(fixture(false, false, false, false, ""), "np.strings");
        assertFalse(new DexContext(automatic.dex()).findField(Signatures.of(TABLE)).isPresent());
        var bare = new DexEngine(List.of(new StringTransformer()), 20)
                .transform(fixture(false, false, false, false, ""));
        retained(bare);
        retained(transform(fixture(false, false, false, false, ""), "np.cleanup"));
    }
    @Test public void unusedBusinessTableWithoutAnyDecoderCallIsNotSelected() {
        DexFile input = fixture(false, false, false, false, ""); List<ClassDef> classes = new ArrayList<>();
        for (ClassDef cls : input.getClasses()) {
            if (!cls.getType().equals(OWNER)) { classes.add(cls); continue; }
            classes.add(new ImmutableClassDef(OWNER, cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), null,
                    cls.getAnnotations(), cls.getFields(), List.of(initializer(false, false))));
        }
        retained(transform(new ImmutableDexFile(input.getOpcodes(), classes)));
    }

    @Test public void assumedTableProofIsRecordedByCallIdentityAndConsumedAfterRelocation() {
        DexFile input = fixture(false, false, false, false, "read");
        DexContext dex = new DexContext(input);
        var strings = new StringTransformer(false, Set.of(Signatures.of(TABLE)));
        strings.prepare(dex);
        Method caller = dex.methods().get(OWNER + "->decode()Ljava/lang/String;");
        var context = new MethodContext(dex, caller);
        assertEquals(1, strings.run(context).edits());
        var call = context.code().getInstructions().stream().filter(i -> i.getOpcode() == Opcode.INVOKE_STATIC).findFirst().orElseThrow();
        assertTrue(context.decodedStringCall(call));
        context.code().addInstruction(0, new BuilderInstruction10x(Opcode.NOP));
        var cleanup = new NpCleanup();
        cleanup.prepare(dex); // Deliberately has no immutable-table assumption.
        assertTrue(cleanup.run(context).edits() > 0);
        assertFalse(context.code().getInstructions().stream().anyMatch(i -> i.getOpcode() == Opcode.INVOKE_STATIC));

        context = new MethodContext(dex, caller); strings.run(context);
        int index = callIndex(context);
        // Replacing a call invalidates its proof even at the exact same offset.
        var old = context.code().getInstructions().get(index);
        context.code().replaceInstruction(index, Edits.copy(old, context.code().getRegisterCount()));
        assertFalse(context.decodedStringCall(context.code().getInstructions().get(index)));
        cleanup.run(context);
        assertTrue(context.code().getInstructions().stream().anyMatch(i -> i.getOpcode() == Opcode.INVOKE_STATIC));
    }

    private int callIndex(MethodContext context) {
        for (int i = 0; i < context.code().getInstructions().size(); i++)
            if (context.code().getInstructions().get(i).getOpcode() == Opcode.INVOKE_STATIC) return i;
        throw new AssertionError("missing decoder call");
    }

    @Test public void immutableTableOptionsReachCleanupAndDeadCastsAreCollected() {
        var options = new TransformerOptions(Map.of("assumeImmutableTables", List.of(Signatures.of(TABLE))));
        var specs = List.of(new TransformerSpec("np.strings", options));
        var scheduled = TransformerRegistry.discover().scheduled(specs);
        assertEquals(List.of(Signatures.of(TABLE)), scheduled.stream().filter(s -> s.id().equals("np.cleanup"))
                .findFirst().orElseThrow().options().strings("assumeImmutableTables"));
        DexFile input = fixture(false, false, false, false, "read");
        var classes = new ArrayList<ClassDef>();
        for (ClassDef cls : input.getClasses()) {
            var methods = new ArrayList<Method>();
            for (Method method : cls.getMethods()) {
                if (method.getName().equals("decode")) {
                    var context = new MethodContext(method);
                    context.code().addInstruction(2, new BuilderInstruction21c(Opcode.CHECK_CAST, 4, new ImmutableTypeReference("[S")));
                    int end = context.code().getInstructions().size() - 1;
                    context.code().addInstruction(end, new BuilderInstruction21c(Opcode.CONST_STRING, 5, new ImmutableStringReference("unused encrypted argument")));
                    context.code().addInstruction(end + 1, new BuilderInstruction21c(Opcode.CHECK_CAST, 5, new ImmutableTypeReference("Ljava/lang/String;")));
                    method = context.finish();
                }
                methods.add(method);
            }
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(),
                    cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        var result = new Deobfuscator(TransformerRegistry.discover()).transform(new ImmutableDexFile(input.getOpcodes(), classes), specs, 20);
        assertEquals(0, result.failedMethods());
        var caller = new DexContext(result.dex()).methods().get(OWNER + "->decode()Ljava/lang/String;");
        for (var i : caller.getImplementation().getInstructions())
            assertFalse(i.getOpcode().name, Set.of(Opcode.INVOKE_STATIC, Opcode.SGET_OBJECT, Opcode.CHECK_CAST).contains(i.getOpcode()));
        assertEquals(2, new CodeGraph(caller.getImplementation()).size()); // Plaintext and return; no dead encrypted arguments.
        assertTrue(new DexContext(result.dex()).findField(Signatures.of(TABLE)).isPresent()); // The business reader still needs it.
    }

    @Test public void protectedDecoderExposedByMethodHidingUsesTheRecordedProof() throws Exception {
        DexFile input = proxyFixture("protected");
        var classes = new ArrayList<ClassDef>();
        for (ClassDef cls : input.getClasses()) {
            var methods = new ArrayList<Method>();
            for (Method method : cls.getMethods())
                if (!cls.getType().equals("Lprobe/Strings;") || !method.getName().equals("<clinit>")) methods.add(method);
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(),
                    cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        var specs = List.of(new TransformerSpec("np.method-hiding", new TransformerOptions(Map.of("inlineProtected", true))),
                new TransformerSpec("np.strings", new TransformerOptions(Map.of("assumeImmutableTables", List.of(Signatures.of(TABLE)), "removeProtectedStringCalls", true))));
        var result = new Deobfuscator(TransformerRegistry.discover()).transform(new ImmutableDexFile(input.getOpcodes(), classes), specs, 20);
        assertEquals(0, result.failedMethods());
        Method caller = new DexContext(result.dex()).methods().get(OWNER + "->proxyCall()Ljava/lang/String;");
        for (var instruction : caller.getImplementation().getInstructions())
            assertFalse(instruction.getOpcode().name, instruction.getOpcode().name.startsWith("invoke-static"));
        assertTrue(result.methods().stream().flatMap(m -> m.steps().stream()).flatMap(s -> s.result().notes().stream())
                .anyMatch(note -> note.startsWith("protected NP string calls removed: ")));
    }
    private DexFile proxyFixture(String mode) throws Exception {
        DexFile guardDex = DexFiles.read(Path.of(getClass().getResource("/np-batch3/hide-methods.dex").toURI()));
        Method guard = new DexContext(guardDex).methods().values().stream().filter(m -> {
            if (m.getImplementation() == null || !m.getParameterTypes().isEmpty() || !m.getReturnType().equals("I")) return false;
            var g = new CodeGraph(m.getImplementation());
            return g.size() == 4 && g.at(0).getOpcode() == Opcode.CONST && g.at(1).getOpcode() == Opcode.SGET
                    && g.at(2).getOpcode() == Opcode.XOR_INT_2ADDR;
        }).findFirst().orElseThrow();
        String proxyOwner = "Lprobe/Strings;";
        List<String> types = List.of("Ljava/lang/Object;", "I", "I", "I");
        var proxy = new ImmutableMethodReference(proxyOwner, "decode", types, "Ljava/lang/String;");
        var outer = new ImmutableMethodReference(proxyOwner, "outer", types, "Ljava/lang/String;");
        var b = new MethodImplementationBuilder(5);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, guard));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("fallback")));
        b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 1, new ImmutableTypeReference(mode.equals("wrong-cast") ? "Ljava/lang/String;" : "[S")));
        if (mode.equals("wrong-cast")) b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 1, new ImmutableTypeReference("[S")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 4, 1, 2, 3, 4, 0, mode.equals("cycle") ? proxy : decoder));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        b.addLabel("fallback"); Fixtures.integer(b, 0, 0); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        int flags = AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue();
        List<Method> proxies = new ArrayList<>();
        proxies.add(new ImmutableMethod(proxyOwner, "decode", types.stream().map(t -> new ImmutableMethodParameter(t, Set.of(), null)).toList(),
                "Ljava/lang/String;", flags, Set.of(), Set.of(), b.getMethodImplementation()));
        b = new MethodImplementationBuilder(5);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, guard));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("fallback")));
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 4, 1, 2, 3, 4, 0, proxy));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        b.addLabel("fallback"); Fixtures.integer(b, 0, 0); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        proxies.add(new ImmutableMethod(proxyOwner, "outer", types.stream().map(t -> new ImmutableMethodParameter(t, Set.of(), null)).toList(),
                "Ljava/lang/String;", flags, Set.of(), Set.of(), b.getMethodImplementation()));
        b = new MethodImplementationBuilder(0);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Lprobe/Effects;", "initialize", List.of(), "V")));
        b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        proxies.add(new ImmutableMethod(proxyOwner, "<clinit>", List.of(), "V", AccessFlags.STATIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                Set.of(), Set.of(), b.getMethodImplementation()));
        b = new MethodImplementationBuilder(5);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET_OBJECT, 0, TABLE));
        if (mode.equals("unknown")) {
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                    new ImmutableMethodReference("Lprobe/Effects;", "offset", List.of(), "I")));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 1));
        } else Fixtures.integer(b, 1, 0);
        Fixtures.integer(b, 2, 1); Fixtures.integer(b, 3, 73);
        b.addLabel("start"); b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 4, 0, 1, 2, 3, 0, mode.equals("chain") ? outer : proxy));
        b.addLabel("end"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 4));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 4));
        if (mode.equals("protected")) {
            b.addLabel("handler"); b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_EXCEPTION, 4));
            b.addInstruction(new BuilderInstruction11x(Opcode.THROW, 4));
            b.addCatch(b.getLabel("start"), b.getLabel("end"), b.getLabel("handler"));
        }
        List<Method> callers = new ArrayList<>(List.of(initializer(false, false), method("proxyCall", "Ljava/lang/String;", b)));
        if (mode.equals("mutated")) {
            var graph = new CodeGraph(guard.getImplementation());
            b = new MethodImplementationBuilder(1);
            Fixtures.integer(b, 0, ((org.jf.dexlib2.iface.instruction.NarrowLiteralInstruction) graph.at(0)).getNarrowLiteral());
            b.addInstruction(new BuilderInstruction21c(Opcode.SPUT, 0, ((org.jf.dexlib2.iface.instruction.ReferenceInstruction) graph.at(1)).getReference()));
            b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID)); callers.add(method("mutate", "V", b));
        }
        List<ClassDef> classes = new ArrayList<>(guardDex.getClasses()); classes.addAll(helpers);
        classes.add(new ImmutableClassDef(proxyOwner, 1, "Ljava/lang/Object;", List.of(), null, Set.of(), List.of(), proxies));
        classes.add(new ImmutableClassDef(OWNER, 1, "Ljava/lang/Object;", List.of(), null, Set.of(),
                List.of(new ImmutableField(OWNER, TABLE.getName(), "[S", AccessFlags.PRIVATE.getValue() | AccessFlags.STATIC.getValue()
                        | AccessFlags.FINAL.getValue(), null, Set.of(), Set.of())), callers));
        return new ImmutableDexFile(guardDex.getOpcodes(), classes);
    }
    @Test public void restoresParameterizedTableProxyValuesWithoutRemovingCalls() throws Exception {
        for (String mode : List.of("plain", "chain", "protected", "unknown", "wrong-cast", "cycle", "mutated")) {
            var pass = new StringTransformer(false, Set.of(Signatures.of(TABLE)));
            var result = new DexEngine(List.of(pass), 20).transform(proxyFixture(mode));
            assertEquals(mode, 0, result.failedMethods());
            Method caller = new DexContext(result.dex()).findMethod(OWNER + "->proxyCall()Ljava/lang/String;").orElseThrow();
            boolean plain = false; int calls = 0;
            for (var i : caller.getImplementation().getInstructions()) {
                if (i instanceof org.jf.dexlib2.iface.instruction.ReferenceInstruction r && r.getReference() instanceof StringReference s)
                    plain |= s.getString().equals("A");
                if (i.getOpcode() == Opcode.INVOKE_STATIC) calls++;
            }
            assertEquals(mode, List.of("plain", "chain", "protected").contains(mode), plain);
            assertEquals(mode, mode.equals("unknown") ? 2 : 1, calls);
            Path file = directory.getRoot().toPath().resolve("proxy-" + mode + ".dex"); DexFiles.write(file, result.dex());
            assertEquals(mode, 0, new DexEngine(List.of(pass), 20).transform(DexFiles.read(file)).changedMethods());
        }
    }
}
