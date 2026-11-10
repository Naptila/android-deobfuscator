package me.naptila.deobfuscator.transformers.np.methodhiding;

import me.naptila.deobfuscator.config.TransformerOptions;
import me.naptila.deobfuscator.config.TransformerSpec;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.transformers.np.analysis.NpAnalysis;
import me.naptila.deobfuscator.transformers.np.analysis.NpHelpers;
import me.naptila.deobfuscator.transformers.np.analysis.NpModel;
import me.naptila.deobfuscator.transformers.np.analysis.NpArrays;
import me.naptila.deobfuscator.transformers.np.strings.StringTransformer;

import java.nio.file.*;
import java.util.*;
import me.naptila.deobfuscator.dex.*;
import me.naptila.deobfuscator.io.DexFiles;
import me.naptila.deobfuscator.app.Deobfuscator;
import me.naptila.deobfuscator.config.*;
import me.naptila.deobfuscator.transform.TransformerRegistry;
import org.jf.dexlib2.*;
import org.jf.dexlib2.builder.*;
import org.jf.dexlib2.builder.instruction.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.reference.*;
import org.jf.dexlib2.immutable.value.*;
import org.junit.*;
import static org.junit.Assert.*;

public class NpHiddenArrayTest {
    static final String OWNER = "Ldev/deobfuscator/fixture/cases/StringCases;";
    static final int FLAGS = AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue();
    DexFile source;
    Method getter;
    String field;
    @Before public void load() throws Exception {
        source = DexFiles.read(Path.of(getClass().getResource("/np-hide-combo/planar.dex").toURI()));
        DexContext dex = new DexContext(source);
        getter = dex.methods().values().stream().filter(m -> m.getDefiningClass().equals(OWNER) && m.getReturnType().equals("[S")).findFirst().orElseThrow();
        field = dex.fields().keySet().stream().filter(s -> s.startsWith(OWNER + "->") && s.endsWith(":[S")).findFirst().orElseThrow();
    }
    Method method(String name, String ret, int flags, MethodImplementationBuilder b) {
        return new ImmutableMethod(OWNER, name, List.of(), ret, flags, Set.of(), Set.of(), b == null ? null : b.getMethodImplementation());
    }
    DexFile add(Method extra) {
        List<ClassDef> classes = new ArrayList<>();
        for (var cls : source.getClasses()) {
            if (!cls.getType().equals(OWNER)) { classes.add(cls); continue; }
            List<Method> methods = new ArrayList<>(); cls.getMethods().forEach(methods::add); methods.add(extra);
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        return new ImmutableDexFile(source.getOpcodes(), classes);
    }
    @Test public void mixedGettersRequireExplicitCompleteInputAndProveAllTables() throws Exception {
        for (String mode : List.of("flower", "planar")) {
            DexContext dex = new DexContext(DexFiles.read(Path.of(getClass().getResource("/np-hide-combo/" + mode + ".dex").toURI())));
            assertEquals(0, NpAnalysis.of(dex).shortArrays());
            NpModel model = NpAnalysis.model(dex, true);
            assertEquals(mode, 18, model.arrayGetters().size());
            assertEquals(mode, 18, model.arrays().size());
        }
    }
    @Test public void returnedModifiedOrUnknownArrayUsesBlockTheTable() {
        for (String kind : List.of("escape", "write", "unknown")) {
            var b = new MethodImplementationBuilder(3);
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, getter));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
            if (kind.equals("write")) {
                b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 0));
                b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 2, 1));
                b.addInstruction(new BuilderInstruction23x(Opcode.APUT_SHORT, 2, 0, 1));
            } else if (kind.equals("unknown")) b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 0, 0, 0, 0, 0,
                    new ImmutableMethodReference("Lunknown/Consumer;", "use", List.of("[S"), "V")));
            b.addInstruction(kind.equals("escape") ? new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0) : new BuilderInstruction10x(Opcode.RETURN_VOID));
            assertFalse(kind, NpAnalysis.model(new DexContext(add(method("observer", kind.equals("escape") ? "[S" : "V", FLAGS, b))), true).arrays().containsKey(field));
        }
    }
    @Test public void nativeFieldReflectionAndHandlesBlockCrossMethodArrayProof() {
        for (String kind : List.of("native", "reflection", "handle")) {
            var b = new MethodImplementationBuilder(2);
            if (kind.equals("reflection")) b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 2, 0, 1, 0, 0, 0,
                    new ImmutableMethodReference("Ljava/lang/Class;", "getDeclaredField", List.of("Ljava/lang/String;"), "Ljava/lang/reflect/Field;")));
            if (kind.equals("handle")) b.addInstruction(new BuilderInstruction21c(Opcode.CONST_METHOD_HANDLE, 0,
                    new ImmutableMethodHandleReference(MethodHandleType.INVOKE_STATIC, getter)));
            b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            Method observer = method("observer", "V", FLAGS | (kind.equals("native") ? AccessFlags.NATIVE.getValue() : 0), kind.equals("native") ? null : b);
            assertFalse(kind, NpAnalysis.model(new DexContext(add(observer)), true).arrays().containsKey(field));
        }
    }
    @Test public void exactTableAssumptionAllowsEscapesButNotObservedWritesOrOtherTables() {
        var b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, getter));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        var dex = new DexContext(add(method("observer", "[S", FLAGS, b)));
        var base = NpAnalysis.of(dex).model();
        assertFalse(base.arrays().containsKey(field));
        var assumed = NpAnalysis.withAssumedTables(dex, base, Set.of(field));
        assertEquals(Set.of(field), assumed.arrays().keySet());
        assertFalse("The input-scoped default facts must remain unchanged", NpAnalysis.of(dex).model().arrays().containsKey(field));
        var mutation = new MethodImplementationBuilder(3);
        mutation.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, getter));
        mutation.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        mutation.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 0));
        mutation.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 2, 7));
        mutation.addInstruction(new BuilderInstruction23x(Opcode.APUT_SHORT, 2, 0, 1));
        mutation.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        var changed = new DexContext(add(method("mutate", "V", FLAGS, mutation)));
        assertFalse(NpAnalysis.withAssumedTables(changed, NpAnalysis.of(changed).model(), Set.of(field)).arrays().containsKey(field));
    }
    @Test public void metadataReferenceToGetterBlocksItsSummary() {
        List<ClassDef> classes = new ArrayList<>(source.getClasses());
        var annotation = new ImmutableAnnotation(AnnotationVisibility.RUNTIME, "Lprobe/Entry;", Set.of(new ImmutableAnnotationElement("method", new ImmutableMethodEncodedValue(ImmutableMethodReference.of(getter)))));
        classes.add(new ImmutableClassDef("Lprobe/Metadata;", 1, "Ljava/lang/Object;", List.of(), null, Set.of(annotation), List.of(), List.of()));
        assertFalse(NpAnalysis.model(new DexContext(new ImmutableDexFile(source.getOpcodes(), classes)), true).arrays().containsKey(field));
    }
    @Test public void knownTableCastsPreserveDecoderArgumentsAndKeepTheCast() {
        var original = new DexContext(source);
        var decoder = original.methods().get(NpAnalysis.of(original).model().helpers().decoders().iterator().next());
        for (String type : List.of("[S", "[B")) {
            var b = new MethodImplementationBuilder(5);
            b.addInstruction(new BuilderInstruction21c(Opcode.SGET_OBJECT, 0, original.fields().get(field)));
            b.addInstruction(new BuilderInstruction12x(Opcode.MOVE_OBJECT, 1, 0));
            b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 1, new ImmutableTypeReference(type)));
            b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 2, 0));
            b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 3, 1));
            b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 4, 0));
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 4, 1, 2, 3, 4, 0, decoder));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
            b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
            Method caller = method("castTable", "Ljava/lang/String;", FLAGS, b);
            var dex = new DexContext(add(caller));
            var pass = new StringTransformer(false, Set.of(field)); pass.prepare(dex);
            var context = new MethodContext(dex, caller);
            assertEquals(type, type.equals("[S") ? 1 : 0, pass.run(context).edits());
            var graph = context.graph();
            assertEquals(Opcode.CHECK_CAST, graph.at(2).getOpcode());
            if (type.equals("[S")) {
                var model = NpAnalysis.withAssumedTables(dex, NpAnalysis.of(dex).model(), Set.of(field));
                String expected = String.valueOf((char) (short) model.arrays().get(field).get(0));
                assertEquals(expected, ((org.jf.dexlib2.iface.reference.StringReference)
                        ((org.jf.dexlib2.iface.instruction.ReferenceInstruction) graph.at(7)).getReference()).getString());
            }
        }
    }
    @Test public void castsCannotHideObservedTableMutationFromAnAssumption() {
        for (String type : List.of("[S", "Ljava/lang/Object;")) {
            var b = new MethodImplementationBuilder(3);
            b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, getter));
            b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
            b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 0, new ImmutableTypeReference(type)));
            b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 0, new ImmutableTypeReference("[S")));
            b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 0));
            b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 2, 1));
            b.addInstruction(new BuilderInstruction23x(Opcode.APUT_SHORT, 2, 0, 1));
            b.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
            var dex = new DexContext(add(method("mutateAfterCast", "V", FLAGS, b)));
            assertFalse(type, NpAnalysis.withAssumedTables(dex, NpAnalysis.of(dex).model(), Set.of(field)).arrays().containsKey(field));
        }
    }
    @Test public void nestedStringGetterResultsPropagateWithoutRemovingCallsAndRespectTableWrites() {
        var original = new DexContext(source); var base = NpAnalysis.of(original).model();
        Method decoder = original.methods().get(base.helpers().decoders().iterator().next());
        Method guard = original.methods().get(base.helpers().guards().keySet().iterator().next());
        Method decoded = stringGetter("decodedGetter", decoder, guard, true);
        source = add(decoded);
        Method nested = stringGetter("nestedGetter", decoded, guard, false);
        source = add(nested);
        var b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, nested));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        Method caller = method("useString", "Ljava/lang/String;", FLAGS, b);
        source = add(caller);
        var dex = new DexContext(source);
        var model = NpAnalysis.withAssumedTables(dex, NpAnalysis.of(dex).model(), Set.of(field));
        String expected = String.valueOf((char) (short) model.arrays().get(field).get(0));
        assertEquals(expected, model.stringGetters().get(Signatures.of(decoded)));
        assertEquals(expected, model.stringGetters().get(Signatures.of(nested)));
        var pass = new StringTransformer(false, Set.of(field)); pass.prepare(dex);
        var context = new MethodContext(dex, caller);
        var result = pass.run(context);
        assertEquals(1, result.edits());
        assertTrue(result.notes().contains("NP string getter results restored (calls retained): 1"));
        assertEquals(Opcode.INVOKE_STATIC, context.graph().at(0).getOpcode());
        assertEquals(Opcode.CONST_STRING_JUMBO, context.graph().at(1).getOpcode());
        assertEquals(0, pass.run(context).edits());
        var mutate = new MethodImplementationBuilder(3);
        mutate.addInstruction(new BuilderInstruction21c(Opcode.SGET_OBJECT, 0, dex.fields().get(field)));
        mutate.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 0));
        mutate.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 2, 1));
        mutate.addInstruction(new BuilderInstruction23x(Opcode.APUT_SHORT, 2, 0, 1));
        mutate.addInstruction(new BuilderInstruction10x(Opcode.RETURN_VOID));
        var modified = new DexContext(add(method("mutateGetterTable", "V", FLAGS, mutate)));
        var changed = NpAnalysis.withAssumedTables(modified, NpAnalysis.of(modified).model(), Set.of(field));
        assertFalse(changed.stringGetters().containsKey(Signatures.of(decoded)));
        assertFalse(changed.stringGetters().containsKey(Signatures.of(nested)));
    }
    @Test public void publishedInitializerArrayRemainsKnownThroughItsLocalAlias() {
        var original = new DexContext(source);
        Method clinit = original.findMethod(OWNER + "-><clinit>()V").orElseThrow();
        var initializer = NpArrays.Initializer.find(new CodeGraph(clinit.getImplementation()));
        assertNotNull(initializer);
        int scratch = clinit.getImplementation().getRegisterCount();
        assertTrue(scratch + 4 <= 16);
        Method expanded = new ImmutableMethod(OWNER, "<clinit>", List.of(), "V", clinit.getAccessFlags(),
                clinit.getAnnotations(), clinit.getHiddenApiRestrictions(), new ImmutableMethodImplementation(scratch + 4,
                clinit.getImplementation().getInstructions(), clinit.getImplementation().getTryBlocks(), clinit.getImplementation().getDebugItems()));
        var edit = new MethodContext(original, expanded);
        Method decoder = original.methods().get(NpAnalysis.of(original).model().helpers().decoders().iterator().next());
        int position = initializer.store() + 1;
        for (var i : List.of(new BuilderInstruction11n(Opcode.CONST_4, scratch, 0),
                new BuilderInstruction11n(Opcode.CONST_4, scratch + 1, 1),
                new BuilderInstruction11n(Opcode.CONST_4, scratch + 2, 0),
                new BuilderInstruction21c(Opcode.CHECK_CAST, initializer.arrayRegister(), new ImmutableTypeReference("[S")),
                new BuilderInstruction35c(Opcode.INVOKE_STATIC, 4, initializer.arrayRegister(), scratch, scratch + 1, scratch + 2, 0, decoder),
                new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, scratch + 3))) edit.code().addInstruction(position++, i);
        var classes = new ArrayList<ClassDef>();
        for (ClassDef cls : source.getClasses()) {
            if (!cls.getType().equals(OWNER)) { classes.add(cls); continue; }
            var methods = new ArrayList<Method>();
            for (Method m : cls.getMethods()) methods.add(m.getName().equals("<clinit>") ? edit.finish() : m);
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(),
                    cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        var dex = new DexContext(new ImmutableDexFile(source.getOpcodes(), classes));
        var model = NpAnalysis.withAssumedTables(dex, NpAnalysis.of(dex).model(), Set.of(field));
        var context = new MethodContext(dex, dex.findMethod(OWNER + "-><clinit>()V").orElseThrow());
        var facts = model.analyze(context.graph());
        assertNull(facts.before(initializer.store()).get(initializer.arrayRegister()));
        assertEquals(new Constants.FieldValue(field), facts.before(initializer.store() + 1).get(initializer.arrayRegister()));
        var pass = new StringTransformer(false, Set.of(field)); pass.prepare(dex);
        assertTrue(pass.run(context).edits() > 0);
        assertEquals(Opcode.SPUT_OBJECT, context.graph().at(initializer.store()).getOpcode());
        assertEquals(Opcode.CONST_STRING_JUMBO, context.graph().at(position - 1).getOpcode());
    }
    private Method stringGetter(String name, Method target, Method guard, boolean decoder) {
        var b = new MethodImplementationBuilder(4);
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        b.addInstruction(new BuilderInstruction31t(Opcode.SPARSE_SWITCH, 0, b.getLabel("payload")));
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("body")));
        b.addLabel("body");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, guard));
        if (decoder) {
            b.addInstruction(new BuilderInstruction21c(Opcode.SGET_OBJECT, 0, new DexContext(source).fields().get(field)));
            b.addInstruction(new BuilderInstruction21c(Opcode.CHECK_CAST, 0, new ImmutableTypeReference("[S")));
            b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, 0));
            b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 2, 1));
            b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 3, 0));
        }
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, decoder ? 4 : 0, 0, 1, 2, 3, 0, target));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        b.addLabel("payload");
        b.addInstruction(new BuilderSparseSwitchPayload(List.of(new SwitchLabelElement(1, b.getLabel("body")))));
        return method(name, "Ljava/lang/String;", FLAGS, b);
    }
    @Test public void unresolvedSymbolicFieldOwnerDoesNotHideAnArrayEscape() {
        var original = new DexContext(source).fields().get(field);
        var b = new MethodImplementationBuilder(1);
        b.addInstruction(new BuilderInstruction21c(Opcode.SGET_OBJECT, 0, new ImmutableFieldReference("Lunknown/Subclass;", original.getName(), "[S")));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        assertFalse(NpAnalysis.model(new DexContext(add(method("observer", "[S", FLAGS, b))), true).arrays().containsKey(field));
    }
    Method traced(int divisor, boolean twoEffects, boolean loop) {
        var dex = new DexContext(source); var model = NpAnalysis.of(dex).model();
        Method guard = dex.methods().get(model.helpers().guards().keySet().iterator().next());
        var b = new MethodImplementationBuilder(2);
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        b.addInstruction(new BuilderInstruction31t(Opcode.SPARSE_SWITCH, 0, b.getLabel("payload")));
        b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("body")));
        b.addLabel("body");
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, guard));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 5));
        b.addInstruction(new BuilderInstruction22s(Opcode.DIV_INT_LIT16, 0, 0, divisor));
        if (twoEffects) for (int i = 0; i < 2; i++) b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0,
                new ImmutableMethodReference("Lprobe/Effects;", "run", List.of(), "V")));
        if (loop) b.addInstruction(new BuilderInstruction10t(Opcode.GOTO, b.getLabel("body")));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("literal")));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        b.addLabel("payload"); b.addInstruction(new BuilderSparseSwitchPayload(List.of(new SwitchLabelElement(1, b.getLabel("body")))));
        return method("traced", "Ljava/lang/String;", FLAGS, b);
    }
    @Test public void tracePreservesThrowingDivisionAndRejectsEffectsOrNontermination() {
        for (int divisor : List.of(0, 2)) {
            Method m = traced(divisor, false, false); DexContext dex = new DexContext(add(m));
            assertEquals(divisor != 0, new HiddenProxies(dex, NpAnalysis.of(dex).model()).templates.containsKey(Signatures.of(m)));
        }
        for (boolean loop : List.of(false, true)) {
            Method m = traced(2, !loop, loop); DexContext dex = new DexContext(add(m));
            assertFalse(new HiddenProxies(dex, NpAnalysis.of(dex).model()).templates.containsKey(Signatures.of(m)));
        }
    }
    @Test public void parameterDependentBranchesAreNotSelectedAsConstants() {
        DexContext base = new DexContext(source);
        Method guard = base.methods().get(NpAnalysis.of(base).model().helpers().guards().keySet().iterator().next());
        var b = new MethodImplementationBuilder(2);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, guard));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 1, b.getLabel("other")));
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("yes")));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        b.addLabel("other");
        b.addInstruction(new BuilderInstruction21c(Opcode.CONST_STRING, 0, new ImmutableStringReference("no")));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        Method m = new ImmutableMethod(OWNER, "dependent", List.of(new ImmutableMethodParameter("I", Set.of(), null)), "Ljava/lang/String;", FLAGS, Set.of(), Set.of(), b.getMethodImplementation());
        DexContext dex = new DexContext(add(m));
        assertFalse(new HiddenProxies(dex, NpAnalysis.of(dex).model()).templates.containsKey(Signatures.of(m)));
    }
    @Test public void parameterIdentityStillRestoresAfterAllLocalCopiesDisappear() {
        DexContext base = new DexContext(source);
        Method guard = base.methods().get(NpAnalysis.of(base).model().helpers().guards().keySet().iterator().next());
        var b = new MethodImplementationBuilder(2);
        b.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 0, 0, 0, 0, 0, 0, guard));
        b.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, 1));
        b.addInstruction(new BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("return")));
        b.addInstruction(new BuilderInstruction12x(Opcode.MOVE, 0, 1));
        b.addLabel("return"); b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        Method proxy = new ImmutableMethod(OWNER, "identity", List.of(new ImmutableMethodParameter("I", Set.of(), null)), "I", FLAGS, Set.of(), Set.of(), b.getMethodImplementation());
        DexContext dex = new DexContext(add(proxy));
        var caller = new MethodImplementationBuilder(2);
        caller.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 1, 1234));
        caller.addInstruction(new BuilderInstruction35c(Opcode.INVOKE_STATIC, 1, 1, 0, 0, 0, 0, proxy));
        caller.addInstruction(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
        caller.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        var context = new MethodContext(dex, method("callIdentity", "I", FLAGS, caller));
        var pass = new MethodHidingTransformer(); pass.prepare(dex); assertEquals(1, pass.run(context).edits());
        CodeGraph graph = context.graph(); var constants = new ConstantAnalysis(graph, ConstantEvaluator::step, false, true);
        int last = graph.size() - 1;
        assertEquals(1234, constants.before(last).get(NpHelpers.reg(graph.at(last))));
    }
    @Test public void combinedPipelineRemovesTablesAfterProxiesAndSurvivesDexRoundTrip() throws Exception {
        List<TransformerSpec> specs = new ArrayList<>();
        specs.add(new TransformerSpec("np.method-hiding", new TransformerOptions(Map.of("inlineProtected", true))));
        for (String id : List.of("np.numbers", "np.instructions", "np.strings", "strings.decrypt", "np.opaque-predicates", "np.dispatcher", "np.flower", "dex.constant-switch", "dex.unreachable", "np.cleanup", "np.method-hiding.cleanup")) {
            Map<String, Object> options = new HashMap<>();
            if (Set.of("np.strings", "np.cleanup", "np.method-hiding.cleanup").contains(id)) options.put("assumeClosedWorld", true);
            if (id.equals("np.cleanup")) options.put("removeProtectedStringCalls", true);
            specs.add(new TransformerSpec(id, new TransformerOptions(options)));
        }
        var app = new Deobfuscator(TransformerRegistry.discover());
        for (String mode : List.of("flower", "planar")) {
            DexFile input = DexFiles.read(Path.of(getClass().getResource("/np-hide-combo/" + mode + ".dex").toURI()));
            var result = app.transform(input, specs, 20);
            assertEquals(mode, 0, result.failedMethods());
            assertTrue(result.methods().stream().allMatch(DexEngine.MethodReport::converged));
            assertEquals(mode, 253, result.evidence().candidates().size());
            assertFalse(new DexContext(result.dex()).fields().values().stream().anyMatch(f -> f.getType().equals("[S")));
            var decoders = NpAnalysis.of(new DexContext(input)).model().helpers().decoders();
            assertFalse(new MethodReferences(new DexContext(result.dex())).uses().stream().anyMatch(u -> u.directCall() && decoders.contains(Signatures.of(u.method()))));
            var original = new DexContext(input); var output = new DexContext(result.dex());
            for (var use : new MethodReferences(output).uses()) {
                String sig = Signatures.of(use.method());
                if (original.methods().containsKey(sig)) assertTrue("Dangling input method: " + sig, output.methods().containsKey(sig));
            }
            Path temp = Files.createTempFile("np-hide-combo-", ".dex");
            try {
                Files.delete(temp); DexFiles.write(temp, result.dex());
                var again = app.transform(DexFiles.read(temp), specs, 20);
                assertEquals(mode, 0, again.failedMethods());
                assertEquals(mode + ": " + again.methods().stream().filter(m -> m.edits() != 0).toList(), 0, again.changedMethods());
                assertEquals(mode, 0, again.dexEdits());
            } finally { Files.deleteIfExists(temp); }
        }
    }
}
